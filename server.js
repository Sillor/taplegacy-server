const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
app.use(express.json());

const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
});

const handleDatabaseError = (res, err) => {
    console.log(err);
    res.json({
        status: 'error',
        error: err.code === 'ER_DUP_ENTRY' ? 'Username already in use' : 'Database error',
    });
};

app.post('/api/signup', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password || password.length < 6 || username.length < 4) {
        return res.json({ status: 'error', error: 'Invalid username/password' });
    }

    try {
        await db.query(
            'INSERT INTO user_credentials (username, password, date_created) VALUES (?, ?, ?)',
            [username, await bcrypt.hash(password, 10), new Date()]
        );
        res.json({ status: 'success', message: 'User created' });
    } catch (err) {
        handleDatabaseError(res, err);
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const [results] = await db.query('SELECT * FROM user_credentials WHERE username = ?', [username]);
        const isValidPassword = results[0] && await bcrypt.compare(password, results[0].password);

        res.json({
            status: isValidPassword ? 'success' : 'error',
            message: isValidPassword ? 'Login successful' : 'Invalid username/password',
        });
    } catch (err) {
        handleDatabaseError(res, err);
    }
});

app.listen(process.env.PORT || 5000, () =>
    console.log(`Server running on port ${process.env.PORT || 5000}`)
);