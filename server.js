// server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

// CORS (local): libera tudo por enquanto
app.use(cors());
app.use(express.json());

// Postgres
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.DATABASE_URL?.includes("render.com") ||
    process.env.DATABASE_URL?.includes("onrender.com")
      ? { rejectUnauthorized: false }
      : false,
});

const EVENT_ID = Number(process.env.EVENT_ID || 1);

// Health check
app.get("/api/health", (req, res) => {
  res.json({ ok: true, service: "pdv-eventos-api", time: new Date().toISOString() });
});

// =====================
// AUTH helpers
// =====================
function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Token ausente" });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET); // { id, role, name }
    return next();
  } catch {
    return res.status(401).json({ message: "Token inválido" });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user?.role) return res.status(401).json({ message: "Não autenticado" });
    if (!roles.includes(req.user.role)) return res.status(403).json({ message: "Sem permissão" });
    return next();
  };
}

// =====================
// AUTH routes
// =====================
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ message: "Informe email e senha" });

  const q = await pool.query(
    `SELECT id, name, email, password_hash, role, active
     FROM users
     WHERE email = $1
     LIMIT 1`,
    [String(email).toLowerCase().trim()]
  );

  if (!q.rows.length) return res.status(401).json({ message: "Credenciais inválidas" });

  const user = q.rows[0];
  if (!user.active) return res.status(403).json({ message: "Usuário desativado" });

  const ok = await bcrypt.compare(String(password), user.password_hash);
  if (!ok) return res.status(401).json({ message: "Credenciais inválidas" });

  const token = jwt.sign(
    { id: user.id, role: user.role, name: user.name },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );

  return res.json({
    accessToken: token,
    user: { id: user.id, name: user.name, email: user.email, role: user.role },
  });
});

app.get("/api/me", auth, async (req, res) => {
  const q = await pool.query(
    `SELECT id, name, email, role, active, created_at
     FROM users
     WHERE id = $1
     LIMIT 1`,
    [req.user.id]
  );
  if (!q.rows.length) return res.status(404).json({ message: "Usuário não encontrado" });
  return res.json(q.rows[0]);
});

app.post("/api/users", auth, requireRole("ADMIN"), async (req, res) => {
  const { name, email, password, role } = req.body || {};
  if (!name || !email || !password || !role) {
    return res.status(400).json({ message: "name, email, password, role são obrigatórios" });
  }
  if (!["ADMIN", "SELLER"].includes(role)) {
    return res.status(400).json({ message: "role inválido (ADMIN/SELLER)" });
  }

  const password_hash = await bcrypt.hash(String(password), 10);

  try {
    const r = await pool.query(
      `INSERT INTO users (name, email, password_hash, role, active)
       VALUES ($1, $2, $3, $4, true)
       RETURNING id, name, email, role, active, created_at`,
      [String(name).trim(), String(email).toLowerCase().trim(), password_hash, role]
    );
    return res.status(201).json(r.rows[0]);
  } catch (e) {
    if (String(e?.message || "").includes("users_email_key")) {
      return res.status(409).json({ message: "Email já cadastrado" });
    }
    console.error(e);
    return res.status(500).json({ message: "Erro ao criar usuário" });
  }
});

// =====================
// Helper: cria o dia se não existir, ou reabre se existir fechado
// =====================
async function getOrCreateOpenDay(day_date) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const existing = await client.query(
      `
      SELECT id, is_open
      FROM event_days
      WHERE event_id = $1 AND day_date = $2
      LIMIT 1
      `,
      [EVENT_ID, day_date]
    );

    if (existing.rows.length) {
      const row = existing.rows[0];

      if (!row.is_open) {
        await client.query(
          `
          UPDATE event_days
          SET is_open = true, opened_at = now(), closed_at = NULL
          WHERE id = $1
          `,
          [row.id]
        );
      }

      await client.query("COMMIT");
      return row.id;
    }

    const created = await client.query(
      `
      INSERT INTO event_days (event_id, day_date, is_open)
      VALUES ($1, $2, true)
      RETURNING id
      `,
      [EVENT_ID, day_date]
    );

    await client.query("COMMIT");
    return created.rows[0].id;
  } catch (e) {
    await client.query("ROLLBACK");
    throw e;
  } finally {
    client.release();
  }
}

// =====================
// SUAS ROTAS ATUAIS
// =====================

// 1) Listar produtos
app.get("/api/products", async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT id, name, cost, price, active FROM products WHERE active = true ORDER BY id"
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 2) Abrir dia + lançar estoque inicial (OPENING apenas 1 vez)
app.post("/api/day/open", async (req, res) => {
  const { day_date, opening } = req.body;

  if (!day_date || !Array.isArray(opening) || opening.length === 0) {
    return res.status(400).json({ error: "day_date e opening são obrigatórios" });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const dayId = await getOrCreateOpenDay(day_date);

    const exists = await client.query(
      `
      SELECT 1 FROM inventory_movements
      WHERE event_day_id = $1 AND type = 'OPENING'
      LIMIT 1
      `,
      [dayId]
    );

    if (exists.rows.length) {
      await client.query("COMMIT");
      return res.json({ ok: true, event_day_id: dayId, already_open: true });
    }

    for (const item of opening) {
      const pid = Number(item.product_id);
      const qty = Number(item.qty);
      if (!pid || !qty || qty <= 0) continue;

      await client.query(
        `
        INSERT INTO inventory_movements (event_day_id, product_id, type, qty)
        VALUES ($1, $2, 'OPENING', $3)
        `,
        [dayId, pid, qty]
      );
    }

    await client.query("COMMIT");
    res.json({ ok: true, event_day_id: dayId, already_open: false });
  } catch (e) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

// 3) Estoque atual do dia
app.get("/api/day/:dayId/stock", async (req, res) => {
  const dayId = Number(req.params.dayId);
  try {
    const { rows } = await pool.query(
      `
      SELECT
        p.id,
        p.name,
        COALESCE(SUM(CASE WHEN im.type IN ('OPENING','RESTOCK') THEN im.qty ELSE 0 END),0)
        -
        COALESCE(SUM(CASE WHEN im.type = 'SALE' THEN im.qty ELSE 0 END),0)
        AS stock_now
      FROM products p
      LEFT JOIN inventory_movements im
        ON im.product_id = p.id AND im.event_day_id = $1
      WHERE p.active = true
      GROUP BY p.id, p.name
      ORDER BY p.id
      `,
      [dayId]
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 4) Vender (registra sale + baixa estoque)
app.post("/api/sale", async (req, res) => {
  const { event_day_id, product_id, qty, payment_method } = req.body;

  if (!event_day_id || !product_id || !qty || qty <= 0 || !payment_method) {
    return res.status(400).json({ error: "Dados inválidos" });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const day = await client.query("SELECT is_open FROM event_days WHERE id = $1", [event_day_id]);
    if (!day.rows.length || !day.rows[0].is_open) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Dia inválido ou fechado." });
    }

    const prod = await client.query(
      "SELECT price, cost FROM products WHERE id = $1 AND active = true",
      [product_id]
    );
    if (!prod.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Produto não encontrado." });
    }

    const unit_price = Number(prod.rows[0].price);
    const unit_cost = Number(prod.rows[0].cost);

    const stockQ = await client.query(
      `
      SELECT
        COALESCE(SUM(CASE WHEN type IN ('OPENING','RESTOCK') THEN qty ELSE 0 END),0)
        - COALESCE(SUM(CASE WHEN type = 'SALE' THEN qty ELSE 0 END),0) AS stock_now
      FROM inventory_movements
      WHERE event_day_id = $1 AND product_id = $2
      `,
      [event_day_id, product_id]
    );

    const stock_now = Number(stockQ.rows[0].stock_now);
    if (stock_now < qty) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: `Estoque insuficiente. Atual: ${stock_now}` });
    }

    await client.query(
      `
      INSERT INTO sales (event_day_id, product_id, qty, unit_price, unit_cost, payment_method)
      VALUES ($1, $2, $3, $4, $5, $6)
      `,
      [event_day_id, product_id, qty, unit_price, unit_cost, payment_method]
    );

    await client.query(
      `
      INSERT INTO inventory_movements (event_day_id, product_id, type, qty)
      VALUES ($1, $2, 'SALE', $3)
      `,
      [event_day_id, product_id, qty]
    );

    await client.query("COMMIT");
    res.json({ ok: true });
  } catch (e) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

// 5) Resumo do dia
app.get("/api/day/:dayId/summary", async (req, res) => {
  const dayId = Number(req.params.dayId);

  try {
    const base = await pool.query(
      `
      SELECT
        COALESCE(SUM(qty * unit_price),0) AS faturamento,
        COALESCE(SUM(qty * unit_cost),0) AS custo
      FROM sales
      WHERE event_day_id = $1
      `,
      [dayId]
    );

    const porPagamento = await pool.query(
      `
      SELECT payment_method, COALESCE(SUM(qty * unit_price),0) AS total
      FROM sales
      WHERE event_day_id = $1
      GROUP BY payment_method
      ORDER BY payment_method
      `,
      [dayId]
    );

    const cfg = await pool.query(
      `
      SELECT percent, vendor_count
      FROM event_commission_config
      WHERE event_id = $1
      LIMIT 1
      `,
      [EVENT_ID]
    );

    const faturamento = Number(base.rows[0].faturamento);
    const custo = Number(base.rows[0].custo);
    const lucroBruto = faturamento - custo;

    const percent = Number(cfg.rows[0]?.percent || 0);
    const vendors = Number(cfg.rows[0]?.vendor_count || 0);

    const comissao = vendors * 40 + faturamento * (percent / 100);
    const lucroLiquido = faturamento - custo - comissao;

    res.json({
      faturamento,
      custo,
      lucro_bruto: lucroBruto,
      comissao,
      lucro_liquido: lucroLiquido,
      por_pagamento: porPagamento.rows,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 6) Fechar dia
app.post("/api/day/:dayId/close", async (req, res) => {
  const dayId = Number(req.params.dayId);

  try {
    const r = await pool.query(
      `
      UPDATE event_days
      SET is_open = false, closed_at = now()
      WHERE id = $1 AND is_open = true
      RETURNING id
      `,
      [dayId]
    );

    if (!r.rows.length) {
      return res.status(400).json({ error: "Dia já está fechado ou inválido." });
    }

    res.json({ ok: true, day_id: dayId });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ✅ sempre por último
app.listen(process.env.PORT || 3001, "0.0.0.0", () => {
  console.log("🔥 PDV Eventos API rodando na porta", process.env.PORT || 3001);
});