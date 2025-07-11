const express = require('express');
const bcrypt = require('bcrypt');
const db = require('../db');
const router = express.Router();
const nodemailer = require('nodemailer');
const SALT_ROUNDS = 10;

// Setup Nodemailer transporter with your noreply email
const transporter = nodemailer.createTransport({
  service: 'gmail', // or use SMTP config for your domain
  auth: {
    user: 'noreply@flurryvale.duckdns.org',
    pass: 'your_email_password_here' // or use env vars
  }
});

// Register route
router.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username & password required' });
  try {
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email || null, hash], function (err) {
      if (err) {
        if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'Username or email taken' });
        return res.status(500).json({ error: 'DB error' });
      }
      res.json({ success: true, message: 'Registered!' });
    });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

// Login route
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username & password required' });
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(400).json({ error: 'User not found' });
    const match = await bcrypt.compare(password, row.password);
    if (!match) return res.status(400).json({ error: 'Wrong password' });
    res.json({ success: true, message: 'Logged in!' });
  });
});

// Request password reset (generate code + email it)
router.post('/pwdreset/request', (req, res) => {
  const { usernameOrEmail } = req.body;
  if (!usernameOrEmail) return res.status(400).json({ error: 'Username or email required' });

  db.get('SELECT * FROM users WHERE username = ? OR email = ?', [usernameOrEmail, usernameOrEmail], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(400).json({ error: 'User not found' });

    const resetCode = Math.random().toString(36).substring(2, 8).toUpperCase();

    db.run('UPDATE users SET reset_code = ? WHERE id = ?', [resetCode, row.id], (err2) => {
      if (err2) return res.status(500).json({ error: 'DB error' });

      // Send email
      const mailOptions = {
        from: '"V E R I F Y" <noreply@flurryvale.duckdns.org>',
        to: row.email,
        subject: 'Password Reset Code',
        text: `Your code is ${resetCode}, or go to https://flurryvale.duckdns.org/pwdreset?type=email,code=${resetCode}`
      };

      transporter.sendMail(mailOptions, (error) => {
        if (error) return res.status(500).json({ error: 'Failed to send email' });
        res.json({ success: true, message: 'Reset code sent via email' });
      });
    });
  });
});

// Reset password using code
router.post('/pwdreset/reset', async (req, res) => {
  const { username, code, newPassword } = req.body;
  if (!username || !code || !newPassword) return res.status(400).json({ error: 'Missing fields' });

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(400).json({ error: 'User not found' });
    if (row.reset_code !== code) return res.status(400).json({ error: 'Invalid reset code' });

    const hash = await bcrypt.hash(newPassword, SALT_ROUNDS);
    db.run('UPDATE users SET password = ?, reset_code = NULL WHERE id = ?', [hash, row.id], (err2) => {
      if (err2) return res.status(500).json({ error: 'DB error' });
      res.json({ success: true, message: 'Password reset successful' });
    });
  });
});

module.exports = router;
