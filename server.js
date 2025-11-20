const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  ssl: { rejectUnauthorized: false }
});

// Student Sign Up (auto-linked to guardian)
app.post('/auth/signup/student', async (req, res) => {
  try {
    const { firstName, lastName, username, email, password, parentCode } = req.body;
    
    // Check if parent code exists
    const guardian = await pool.query(
      'SELECT id FROM users WHERE parent_code = $1 AND role = $2',
      [parentCode, 'guardian']
    );
    
    if (guardian.rows.length === 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid parent code' 
      });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const guardianId = guardian.rows[0].id;
    
    const result = await pool.query(
      'INSERT INTO users (first_name, last_name, username, email, password, role, parent_code, guardian_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, username, email, role',
      [firstName, lastName, username, email, hashedPassword, 'student', parentCode, guardianId]
    );
    
    res.status(201).json({ 
      success: true, 
      message: 'Account created and linked to guardian!',
      user: result.rows[0] 
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Mentor Sign Up
app.post('/auth/signup/mentor', async (req, res) => {
  try {
    const { username, email, password, sponsorCode } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const result = await pool.query(
      'INSERT INTO users (username, email, password, role, sponsor_code) VALUES ($1, $2, $3, $4, $5) RETURNING id, username, email, role',
      [username, email, hashedPassword, 'mentor', sponsorCode]
    );
    
    res.status(201).json({ 
      success: true, 
      user: result.rows[0] 
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Guardian Sign Up (generates parent code)
app.post('/auth/signup/guardian', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Generate unique parent code
    const parentCode = 'P' + Date.now().toString().slice(-6);
    
    const result = await pool.query(
      'INSERT INTO users (username, email, password, role, parent_code) VALUES ($1, $2, $3, $4, $5) RETURNING id, username, email, role, parent_code',
      [username, email, hashedPassword, 'guardian', parentCode]
    );
    
    res.status(201).json({ 
      success: true, 
      message: `Your parent code is: ${parentCode}. Give this to your child for signup.`,
      user: result.rows[0],
      parentCode: parentCode
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Login (all roles)
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, error: 'Invalid email or password' });
    }
    
    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(401).json({ success: false, error: 'Invalid email or password' });
    }
    
    res.json({ 
      success: true, 
      user: { 
        id: user.id, 
        username: user.username,
        email: user.email, 
        role: user.role 
      } 
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/', (req, res) => {
  res.json({ message: 'HOPE Huddle Backend Running' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));