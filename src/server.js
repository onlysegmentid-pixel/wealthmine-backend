
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const { z } = require("zod");

const app = express();
app.use(express.json());

const corsOrigin = process.env.CORS_ORIGIN || "*";
app.use(cors({ origin: corsOrigin, credentials: true }));

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

function signToken(user) {
  return jwt.sign({ sub: user.id, email: user.email, isAdmin: user.email === process.env.ADMIN_EMAIL }, process.env.JWT_SECRET, { expiresIn: "7d" });
}

function auth(req, res, next) {
  const hdr = req.headers.authorization || "";
  const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : "";
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }
}

function adminOnly(req, res, next) {
  if (!req.user?.isAdmin) return res.status(403).json({ error: "Forbidden" });
  return next();
}

async function getUserById(userId) {
  const { rows } = await pool.query("select id, email, username, balance, created_at from users where id=$1", [userId]);
  return rows[0] || null;
}

function toUserDto(row) {
  return {
    id: row.id,
    email: row.email,
    username: row.username,
    balance: Number(row.balance || 0),
    createdAt: row.created_at
  };
}

async function seedAdminIfNeeded() {
  const email = process.env.ADMIN_EMAIL;
  const password = process.env.ADMIN_PASSWORD;
  if (!email || !password) return;

  const { rows } = await pool.query("select id from users where email=$1", [email]);
  if (rows[0]) return;

  const hash = await bcrypt.hash(password, 10);
  await pool.query("insert into users(email, username, password_hash) values ($1,$2,$3)", [email, "Admin", hash]);
  console.log("Seeded admin:", email);
}

app.get("/api/health", (req, res) => res.json({ ok: true }));

app.post("/api/auth/register", async (req, res) => {
  const schema = z.object({
    username: z.string().min(2).max(60),
    email: z.string().email(),
    password: z.string().min(6).max(200)
  });
  const body = schema.parse(req.body);

  const hash = await bcrypt.hash(body.password, 10);
  try {
    const { rows } = await pool.query(
      "insert into users(email, username, password_hash) values ($1,$2,$3) returning id, email, username, balance, created_at",
      [body.email.toLowerCase(), body.username, hash]
    );
    const user = rows[0];
    const token = signToken(user);
    return res.json({ token, user: toUserDto(user) });
  } catch (e) {
    if (String(e).includes("unique")) return res.status(409).json({ error: "Email already registered" });
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const schema = z.object({ email: z.string().email(), password: z.string().min(1) });
  const body = schema.parse(req.body);

  const { rows } = await pool.query("select * from users where email=$1", [body.email.toLowerCase()]);
  const user = rows[0];
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const ok = await bcrypt.compare(body.password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  const token = signToken(user);
  return res.json({ token, user: toUserDto(user) });
});

app.get("/api/me", auth, async (req, res) => {
  const user = await getUserById(req.user.sub);
  if (!user) return res.status(401).json({ error: "Unauthorized" });
  return res.json({ user: toUserDto(user) });
});

function txId(prefix) {
  return `${prefix}-${Date.now()}-${Math.floor(Math.random()*10000)}`;
}

app.post("/api/deposits", auth, async (req, res) => {
  const schema = z.object({
    amount: z.number().positive(),
    method: z.string().default("manual"),
    txRef: z.string().min(1).max(120)
  });
  const body = schema.parse(req.body);

  const id = txId("DEP");
  await pool.query(
    "insert into transactions(id,user_id,kind,amount,status,meta) values ($1,$2,'deposit',$3,'pending',$4::jsonb)",
    [id, req.user.sub, body.amount, JSON.stringify({ method: body.method, txRef: body.txRef })]
  );
  return res.json({ id, status: "pending" });
});

app.get("/api/deposits", auth, async (req, res) => {
  const { rows } = await pool.query(
    "select id, amount, status, created_at from transactions where user_id=$1 and kind='deposit' order by created_at desc limit 200",
    [req.user.sub]
  );
  const sum = await pool.query(
    "select coalesce(sum(amount),0) as total from transactions where user_id=$1 and kind='deposit' and status='approved'",
    [req.user.sub]
  );
  return res.json({ items: rows, summary: { totalApprovedDeposits: Number(sum.rows[0].total) } });
});

app.post("/api/withdraws", auth, async (req, res) => {
  const schema = z.object({
    amount: z.number().positive(),
    address: z.string().min(6).max(200)
  });
  const body = schema.parse(req.body);

  const id = txId("WDR");
  await pool.query(
    "insert into transactions(id,user_id,kind,amount,status,meta) values ($1,$2,'withdraw',$3,'pending',$4::jsonb)",
    [id, req.user.sub, body.amount, JSON.stringify({ address: body.address })]
  );
  return res.json({ id, status: "pending" });
});

app.get("/api/withdraws", auth, async (req, res) => {
  const { rows } = await pool.query(
    "select id, amount, status, created_at from transactions where user_id=$1 and kind='withdraw' order by created_at desc limit 200",
    [req.user.sub]
  );
  const sum = await pool.query(
    "select coalesce(sum(amount),0) as total from transactions where user_id=$1 and kind='withdraw' and status='approved'",
    [req.user.sub]
  );
  return res.json({ items: rows, summary: { totalApprovedWithdraws: Number(sum.rows[0].total) } });
});

app.post("/api/purchase/machine", auth, async (req, res) => {
  const schema = z.object({ machine: z.any() });
  const body = schema.parse(req.body);
  const price = Number(body.machine?.price || 0);
  if (!price || price <= 0) return res.status(400).json({ error: "Invalid machine price" });

  const client = await pool.connect();
  try {
    await client.query("begin");
    const u = await client.query("select balance from users where id=$1 for update", [req.user.sub]);
    const bal = Number(u.rows[0]?.balance || 0);
    if (bal < price) throw new Error("INSUFFICIENT");

    await client.query("update users set balance=balance-$1 where id=$2", [price, req.user.sub]);
    await client.query(
      "insert into transactions(id,user_id,kind,amount,status,meta) values ($1,$2,'machine_purchase',$3,'approved',$4::jsonb)",
      [txId("BUY"), req.user.sub, price, JSON.stringify({ machine: body.machine })]
    );
    await client.query("commit");
    return res.json({ ok: true });
  } catch (e) {
    await client.query("rollback");
    if (String(e.message) === "INSUFFICIENT") return res.status(400).json({ error: "Insufficient balance" });
    return res.status(500).json({ error: "Server error" });
  } finally {
    client.release();
  }
});

app.post("/api/activate/plan", auth, async (req, res) => {
  const schema = z.object({ plan: z.any() });
  const body = schema.parse(req.body);
  const price = Number(body.plan?.price || 0);
  if (!price || price <= 0) return res.status(400).json({ error: "Invalid plan price" });

  const client = await pool.connect();
  try {
    await client.query("begin");
    const u = await client.query("select balance from users where id=$1 for update", [req.user.sub]);
    const bal = Number(u.rows[0]?.balance || 0);
    if (bal < price) throw new Error("INSUFFICIENT");

    await client.query("update users set balance=balance-$1 where id=$2", [price, req.user.sub]);
    await client.query(
      "insert into transactions(id,user_id,kind,amount,status,meta) values ($1,$2,'plan_activate',$3,'approved',$4::jsonb)",
      [txId("PLAN"), req.user.sub, price, JSON.stringify({ plan: body.plan })]
    );
    await client.query("commit");
    return res.json({ ok: true });
  } catch (e) {
    await client.query("rollback");
    if (String(e.message) === "INSUFFICIENT") return res.status(400).json({ error: "Insufficient balance" });
    return res.status(500).json({ error: "Server error" });
  } finally {
    client.release();
  }
});

app.get("/api/transactions", auth, async (req, res) => {
  const { rows } = await pool.query(
    "select id, kind, amount, status, created_at from transactions where user_id=$1 order by created_at desc limit 500",
    [req.user.sub]
  );
  return res.json({ items: rows });
});

// Admin: list pending deposits/withdraws
app.get("/api/admin/deposits", auth, adminOnly, async (req, res) => {
  const status = (req.query.status || "pending").toString();
  const { rows } = await pool.query(
    "select t.id,t.amount,t.status,t.created_at,u.email as user_email from transactions t join users u on u.id=t.user_id where t.kind='deposit' and t.status=$1 order by t.created_at asc limit 500",
    [status]
  );
  return res.json(rows);
});

app.post("/api/admin/deposits/:id", auth, adminOnly, async (req, res) => {
  const approve = !!req.body.approve;
  const id = req.params.id;

  const client = await pool.connect();
  try {
    await client.query("begin");
    const t = await client.query("select * from transactions where id=$1 for update", [id]);
    const tx = t.rows[0];
    if (!tx || tx.kind !== "deposit") throw new Error("NOTFOUND");
    if (tx.status !== "pending") throw new Error("NOTPENDING");

    const newStatus = approve ? "approved" : "rejected";
    await client.query("update transactions set status=$1, updated_at=now() where id=$2", [newStatus, id]);
    if (approve) {
      await client.query("update users set balance=balance+$1 where id=$2", [tx.amount, tx.user_id]);
    }
    await client.query("commit");
    return res.json({ ok: true });
  } catch (e) {
    await client.query("rollback");
    if (e.message === "NOTFOUND") return res.status(404).json({ error: "Not found" });
    if (e.message === "NOTPENDING") return res.status(400).json({ error: "Not pending" });
    return res.status(500).json({ error: "Server error" });
  } finally {
    client.release();
  }
});

app.get("/api/admin/withdraws", auth, adminOnly, async (req, res) => {
  const status = (req.query.status || "pending").toString();
  const { rows } = await pool.query(
    "select t.id,t.amount,t.status,t.created_at,u.email as user_email from transactions t join users u on u.id=t.user_id where t.kind='withdraw' and t.status=$1 order by t.created_at asc limit 500",
    [status]
  );
  return res.json(rows);
});

app.post("/api/admin/withdraws/:id", auth, adminOnly, async (req, res) => {
  const approve = !!req.body.approve;
  const id = req.params.id;

  const client = await pool.connect();
  try {
    await client.query("begin");
    const t = await client.query("select * from transactions where id=$1 for update", [id]);
    const tx = t.rows[0];
    if (!tx || tx.kind !== "withdraw") throw new Error("NOTFOUND");
    if (tx.status !== "pending") throw new Error("NOTPENDING");

    const u = await client.query("select balance from users where id=$1 for update", [tx.user_id]);
    const bal = Number(u.rows[0]?.balance || 0);
    if (approve && bal < Number(tx.amount)) throw new Error("INSUFFICIENT");

    const newStatus = approve ? "approved" : "rejected";
    await client.query("update transactions set status=$1, updated_at=now() where id=$2", [newStatus, id]);
    if (approve) {
      await client.query("update users set balance=balance-$1 where id=$2", [tx.amount, tx.user_id]);
    }
    await client.query("commit");
    return res.json({ ok: true });
  } catch (e) {
    await client.query("rollback");
    if (e.message === "NOTFOUND") return res.status(404).json({ error: "Not found" });
    if (e.message === "NOTPENDING") return res.status(400).json({ error: "Not pending" });
    if (e.message === "INSUFFICIENT") return res.status(400).json({ error: "Insufficient balance" });
    return res.status(500).json({ error: "Server error" });
  } finally {
    client.release();
  }
});

const port = Number(process.env.PORT || 8080);

seedAdminIfNeeded()
  .then(() => {
    app.listen(port, () => console.log("API listening on", port));
  })
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
