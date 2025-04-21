const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors');
const app = express();
const port = process.env.PORT || 3000;
app.use(bodyParser.json());
app.use(cors());
const db = new sqlite3.Database('./database.db', err => {
  if (err) console.error('DB error', err);
});
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    idNumber TEXT UNIQUE NOT NULL,
    address TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    memberId INTEGER NOT NULL,
    planType TEXT,
    coverLevel REAL,
    premium REAL,
    startDate TEXT,
    status TEXT,
    FOREIGN KEY(memberId) REFERENCES members(id)
  )`);
});
// Auth endpoints
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
  try {
    const hash = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (name,email,password) VALUES (?,?,?)', [name, email, hash], function(err) {
      if (err) {
        if (err.code === 'SQLITE_CONSTRAINT') return res.status(400).json({ error: 'Email in use' });
        return res.status(500).json({ error: 'DB error' });
      }
      res.json({ message: 'Registered' });
    });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'All fields required' });
  db.get('SELECT * FROM users WHERE email=?', [email], async (err, user) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Invalid credentials' });
    res.json({ message: 'Login successful' });
  });
});
// Members CRUD
app.get('/api/members', (req, res) => {
  db.all('SELECT * FROM members', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(rows);
  });
});
app.get('/api/members/:id', (req, res) => {
  db.get('SELECT * FROM members WHERE id=?', [req.params.id], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(row);
  });
});
app.post('/api/members', (req, res) => {
  const { name, idNumber, address } = req.body;
  db.run('INSERT INTO members (name,idNumber,address) VALUES (?,?,?)', [name, idNumber, address], function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ id: this.lastID });
  });
});
app.put('/api/members/:id', (req, res) => {
  const { name, idNumber, address } = req.body;
  db.run('UPDATE members SET name=?,idNumber=?,address=? WHERE id=?', [name, idNumber, address, req.params.id], err => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.sendStatus(200);
  });
});
app.delete('/api/members/:id', (req, res) => {
  db.run('DELETE FROM members WHERE id=?', [req.params.id], err => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.sendStatus(200);
  });
});
// Policies CRUD
app.get('/api/policies', (req, res) => {
  db.all('SELECT * FROM policies', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(rows);
  });
});
app.get('/api/policies/:id', (req, res) => {
  db.get('SELECT * FROM policies WHERE id=?', [req.params.id], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(row);
  });
});
app.post('/api/policies', (req, res) => {
  const { memberId, planType, coverLevel, premium, startDate, status } = req.body;
  db.run('INSERT INTO policies (memberId,planType,coverLevel,premium,startDate,status) VALUES (?,?,?,?,?,?)', 
    [memberId, planType, coverLevel, premium, startDate, status], function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ id: this.lastID });
  });
});
app.put('/api/policies/:id', (req, res) => {
  const { planType, coverLevel, premium, startDate, status } = req.body;
  db.run('UPDATE policies SET planType=?,coverLevel=?,premium=?,startDate=?,status=? WHERE id=?',
    [planType, coverLevel, premium, startDate, status, req.params.id], err => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.sendStatus(200);
  });
});
app.delete('/api/policies/:id', (req, res) => {
  db.run('DELETE FROM policies WHERE id=?', [req.params.id], err => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.sendStatus(200);
  });
});
app.listen(port, () => console.log(`Server running on port ${port}`));