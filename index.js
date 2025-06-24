require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
app.use(express.json()); // Middleware to parse JSON body

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// --- Auth middleware ---
function auth(req, res, next) {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = payload.id;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// --- Routes ---

// 1) Register
app.post('/api/v1/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: 'All fields are required' });

  const hash = await bcrypt.hash(password, 10);
  try {
    await pool.query(
      `INSERT INTO users (name, email, password) VALUES ($1, $2, $3)`,
      [name, email, hash]
    );
    res.json({ message: 'User registered' });
  } catch (e) {
    res.status(400).json({ error: e.detail || e.message });
  }
});

// 2) Login
app.post('/api/v1/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email and password are required' });

  const { rows } = await pool.query(`SELECT * FROM users WHERE email=$1`, [email]);
  const user = rows[0];

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '12h' });
  res.json({ token });
});

// 3) Create Goal
app.post('/api/v1/goals', auth, async (req, res) => {
  const { title, target_amount, start_date, end_date } = req.body;
  if (!title || !target_amount)
    return res.status(400).json({ error: 'Title and target amount are required' });

  try {
    const { rows } = await pool.query(
      `INSERT INTO goals (title, target_amount, start_date, end_date, user_id)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [title, target_amount, start_date, end_date, req.userId]
    );
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'Failed to create goal' });
  }
});

// 4) Update Goal
app.put('/api/v1/goals/:id', auth, async (req, res) => {
  const { title, target_amount, start_date, end_date } = req.body;
  const { id } = req.params;

  if (!title || !target_amount)
    return res.status(400).json({ error: 'Title and target amount are required' });

  try {
    const { rows } = await pool.query(
      `UPDATE goals SET title=$1, target_amount=$2, start_date=$3, end_date=$4
       WHERE id=$5 AND user_id=$6 RETURNING *`,
      [title, target_amount, start_date, end_date, id, req.userId]
    );

    if (!rows[0]) return res.status(404).json({ error: 'Goal not found' });
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'Failed to update goal' });
  }
});

// 5) Delete Goal
app.delete('/api/v1/goals/:id', auth, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query(`DELETE FROM goals WHERE id=$1 AND user_id=$2`, [id, req.userId]);
    res.json({ message: 'Goal deleted' });
  } catch (e) {
    res.status(500).json({ error: 'Failed to delete goal' });
  }
});

// 6) List Goals
app.get('/api/v1/goals', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM goals WHERE user_id = $1 ORDER BY start_date DESC',
      [req.userId]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch goals' });
  }
});

// 7) Deposit to a Goal
app.post('/api/v1/goals/:id/deposits', auth, async (req, res) => {
  const { amount, date } = req.body;
  const goalId = req.params.id;

  if (!amount || !date)
    return res.status(400).json({ error: 'Amount and date are required' });

  const goalRes = await pool.query(
    `SELECT * FROM goals WHERE id=$1 AND user_id=$2`,
    [goalId, req.userId]
  );
  if (!goalRes.rows[0]) return res.status(404).json({ error: 'Goal not found' });

  await pool.query('BEGIN');
  try {
    const { rows: dep } = await pool.query(
      `INSERT INTO deposits (goal_id, amount, date)
       VALUES ($1, $2, $3) RETURNING *`,
      [goalId, amount, date]
    );

    // Optionally update current_amount
    // await pool.query(
    //   `UPDATE goals SET current_amount = current_amount + $1 WHERE id = $2`,
    //   [amount, goalId]
    // );

    await pool.query('COMMIT');
    res.json(dep[0]);
  } catch (e) {
    await pool.query('ROLLBACK');
    res.status(500).json({ error: e.message });
  }
});

// 8) List Deposits for a Goal
app.get('/api/v1/goals/:id/deposits', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM deposits WHERE goal_id=$1 ORDER BY date DESC`,
      [req.params.id]
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch deposits' });
  }
});

// 9) Summary
app.get('/api/v1/summary', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, title, target_amount, current_amount FROM goals WHERE user_id=$1`,
      [req.userId]
    );
    const totalSaved = rows.reduce((sum, g) => sum + parseFloat(g.current_amount || 0), 0);
    res.json({ totalSaved, goals: rows });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch summary' });
  }
});

// --- Start Server ---
app.listen(process.env.PORT, () =>
  console.log(`🚀 API running at http://localhost:${process.env.PORT}`)
);
