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

    if (!username || !password || password.length < 6 || username.length < 4)
        return res.json({ status: 'error', error: 'Invalid username/password' });

    try {
        const [[existingUser]] = await db.query('SELECT * FROM credentials WHERE username = ?', [username]);
        if (existingUser) {
            return res.json({ status: 'error', error: 'Username already exists' });
        }

        const [{ insertId }] = await db.query('INSERT INTO users (taps, timeSpent) VALUES (0, 0)');
        await db.query(
            'INSERT INTO credentials (username, password, date_created, userId) VALUES (?, ?, ?, ?)',
            [username, await bcrypt.hash(password, 10), new Date(), insertId]
        );
        res.json({ status: 'success', message: 'User created' });
    } catch (err) {
        handleDatabaseError(res, err);
    }
});

app.put('/api/user', authenticateToken, async (req, res) => {
    try {
        const { taps, timeSpent } = req.body;
        await db.query('UPDATE users SET taps = ?, timeSpent = ? WHERE id = ?', [taps, timeSpent, req.user.userId]);
        res.json({ status: 'success', message: 'User updated' });
    } catch (err) {
        handleDatabaseError(res, err);
    }
});

app.put('/api/user/upgrades', authenticateToken, async (req, res) => {
    try {
        for (const [name, amount] of Object.entries(req.body)) {
            await db.query(
                'INSERT INTO upgrades (userId, upgradeName, upgradeValue) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE upgradeValue = ?',
                [req.user.userId, name, amount, amount]
            );
        }
        res.json({ status: 'success', message: 'User upgrades updated' });
    } catch (err) {
        handleDatabaseError(res, err);
    }
});

app.put('/api/user/stats', authenticateToken, async (req, res) => {
    try {
        const { buttonClicked, upgradesPurchased, maxCps } = req.body;
        await db.query('INSERT INTO stats (userId, buttonClicked, upgradesPurchased, maxCps) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE buttonClicked = ?, upgradesPurchased = ?, maxCps = ?', [req.user.userId, buttonClicked, upgradesPurchased, maxCps, buttonClicked, upgradesPurchased, maxCps]);
        res.json({ status: 'success', message: 'User updated' });
    } catch (err) {
        handleDatabaseError(res, err);
    };
});

app.post('/api/login', async (req, res) => {
    try {
        const [[user]] = await db.query('SELECT * FROM credentials WHERE username = ?', [req.body.username]);
        const isValid = user && await bcrypt.compare(req.body.password, user.password);

        res.json(isValid ? {
            status: 'success',
            message: 'Login successful',
            accessToken: generateAccessToken({ userId: user.userId }),
        } : {
            status: 'error',
            message: 'Invalid username/password',
        });
    } catch (err) {
        handleDatabaseError(res, err);
    }
});

app.get('/api/user', authenticateToken, async (req, res) => {
    try {
        const [[results]] = await db.query('SELECT * FROM users WHERE id = ?', [req.user.userId]);
        res.json({ status: 'success', data: results });
    } catch (err) {
        handleDatabaseError(res, err);
    }
});

app.get('/api/user/upgrades', authenticateToken, async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM upgrades WHERE userId = ?', [req.user.userId]);
        const upgrades = results.reduce((acc, upgrade) => {
            acc[upgrade.upgradeName] = upgrade.upgradeValue;
            return acc;
        }, {});
        res.json({ status: 'success', data: upgrades });
    } catch (err) {
        handleDatabaseError(res, err);
    }
});

app.get('/api/user/stats', authenticateToken, async (req, res) => {
    try {
        const [results] = await db.query('SELECT buttonClicked, upgradesPurchased, maxCps FROM stats WHERE userId = ?', [req.user.userId]);
        res.json({ status: 'success', data: results[0] });
    } catch (err) {
        handleDatabaseError(res, err);
    }
}
);

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '5m' });
}

function authenticateToken(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

app.listen(process.env.PORT || 5000, () =>
    console.log(`Server running on port ${process.env.PORT || 5000}`)
);