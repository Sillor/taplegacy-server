const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
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

        const accessToken = generateAccessToken({ username });
        const refreshToken = jwt.sign({ username }, process.env.REFRESH_TOKEN_SECRET);

        res.json({
            status: isValidPassword ? 'success' : 'error',
            message: isValidPassword ? 'Login successful' : 'Invalid username/password',
            accessToken: isValidPassword ? accessToken : null,
        });
    } catch (err) {
        handleDatabaseError(res, err);
    }
});

app.get('/api/users', authenticateToken, async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM user_credentials WHERE username = ?', [req.user.username]);
        res.json({ status: 'success', users: results });
    } catch (err) {
        handleDatabaseError(res, err);
    }
});

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '5m' });
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

app.listen(process.env.PORT || 5000, () =>
    console.log(`Server running on port ${process.env.PORT || 5000}`)
);