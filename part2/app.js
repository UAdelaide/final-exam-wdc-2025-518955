const express = require('express');
// session and password encryption, MySQL driver
const session = require('express-session');
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');
// end
const path = require('path');
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: false })); 
// session
app.use(session({
  secret: process.env.SESSION_SECRET || 'change_this_secret',
  resave: false,
  saveUninitialized: false
}));
// end

app.use(express.static(path.join(__dirname, '/public')));

// create database link
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME
});


// Routes
const walkRoutes = require('./routes/walkRoutes');
const userRoutes = require('./routes/userRoutes');

app.use('/api/walks', walkRoutes);
app.use('/api/users', userRoutes);

// Login processing
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    // request users
    const [rows] = await db.query(
      'SELECT user_id, username, password_hash, role FROM Users WHERE username = ?',
      [username]
    );
    if (rows.length === 0) {
      return res.redirect('/?error=The username or password is incorrect');
    }
    const user = rows[0];
    // vaildate users
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.redirect('/?error=The username or password is incorrect');
    }
    // save session
    req.session.user = { id: user.user_id, username: user.username, role: user.role };
    // jump
    if (user.role === 'owner') {
      return res.redirect('/owner-dashboard.html');
    } else {
      return res.redirect('/walker-dashboard.html');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('error');
  }
});

//Log out of the route
app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).send('Logout failed');
    }
    res.clearCookie('connect.sid'); 
    res.redirect('/');              // return
  });
});

// return all dogs
app.get('/api/dogs', async (req, res) => {
  if (!req.session.user) {
    return res.status(401).send('Unauthorized');
  }
  try {
    const [rows] = await db.query(
      'SELECT dog_id, name FROM Dogs WHERE owner_id = ?',
      [req.session.user.id]
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

module.exports = app;
