const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

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
        message: err.code === 'ER_DUP_ENTRY' ? 'Username already in use' : 'Database error',
    });
};

app.post('/api/signup', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password || password.length < 6 || username.length < 4)
        return res.json({ status: 'error', message: 'Invalid username/password' });

    try {
        const [[existingUser]] = await db.query('SELECT * FROM credentials WHERE username = ?', [username]);
        if (existingUser) {
            return res.json({ status: 'error', message: 'Username already exists' });
        }

        const [{ insertId }] = await db.query('INSERT INTO users (taps) VALUES (0)');
        await db.query(
            'INSERT INTO credentials (username, password, date_created, userId) VALUES (?, ?, ?, ?)',
            [username, await bcrypt.hash(password, 10), new Date(), insertId]
        );
        await db.query('INSERT INTO stats (userId, buttonClicked, upgradesPurchased, maxCps, timeSpent) VALUES (?, 0, 0, 0, 0) ON DUPLICATE KEY UPDATE buttonClicked = 0, upgradesPurchased = 0, maxCps = 0, timeSpent = 0', [insertId]);
        res.json({ status: 'success', message: 'User created' });
    } catch (err) {
        handleDatabaseError(res, err);
    }
});

app.put('/api/user', authenticateToken, async (req, res) => {
    try {
        const { taps, timeSpent } = req.body;
        await db.query('UPDATE users SET taps = ? WHERE id = ?', [taps, req.user.userId]);
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
        const { buttonClicked, upgradesPurchased, maxCps, timeSpent } = req.body;
        await db.query('INSERT INTO stats (userId, buttonClicked, upgradesPurchased, maxCps, timeSpent) VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE buttonClicked = ?, upgradesPurchased = ?, maxCps = ?, timeSpent = ?', [req.user.userId, buttonClicked, upgradesPurchased, maxCps, timeSpent, buttonClicked, upgradesPurchased, maxCps, timeSpent]);
        res.json({ status: 'success', message: 'User updated' });
    } catch (err) {
        handleDatabaseError(res, err);
    };
});

app.put('/api/user/update', authenticateToken, async (req, res) => {
    try {
        const { taps, upgrades, stats } = req.body;

        // Update users table
        await db.query('UPDATE users SET taps = ? WHERE id = ?', [taps, req.user.userId]);

        // Update upgrades table
        for (const [name, amount] of Object.entries(upgrades)) {
            // Check if the upgrade already exists for the user
            const [existingUpgrade] = await db.query('SELECT * FROM upgrades WHERE userId = ? AND upgradeName = ?', [req.user.userId, name]);

            // If the upgrade doesn't exist, insert it
            if (!existingUpgrade.length) {
                await db.query(
                    'INSERT INTO upgrades (userId, upgradeName, upgradeValue) VALUES (?, ?, ?)',
                    [req.user.userId, name, amount]
                );
            }
        }

        // Update stats table
        const { buttonClicked, upgradesPurchased, maxCps, timeSpent } = stats;
        await db.query('INSERT INTO stats (userId, buttonClicked, upgradesPurchased, maxCps, timeSpent) VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE buttonClicked = ?, upgradesPurchased = ?, maxCps = ?, timeSpent = ?', [req.user.userId, buttonClicked, upgradesPurchased, maxCps, timeSpent, buttonClicked, upgradesPurchased, maxCps, timeSpent]);

        res.json({ status: 'success', message: 'User updated' });
    } catch (err) {
        handleDatabaseError(res, err);
    }
});

app.delete('/api/user/data', authenticateToken, async (req, res) => {
    try {
        await db.query('UPDATE users SET taps = 0 WHERE id = ?', [req.user.userId]);
        await db.query('DELETE FROM upgrades WHERE userId = ?', [req.user.userId]);
        await db.query('INSERT INTO stats (userId, buttonClicked, upgradesPurchased, maxCps, timeSpent) VALUES (?, 0, 0, 0, 0) ON DUPLICATE KEY UPDATE buttonClicked = 0, upgradesPurchased = 0, maxCps = 0, timeSpent = 0', [insertId]);
        res.json({ status: 'success', message: 'User data deleted' });
    } catch (err) {
        handleDatabaseError(res, err);
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const [[user]] = await db.query('SELECT * FROM credentials WHERE username = ?', [req.body.username]);
        const isValid = user && await bcrypt.compare(req.body.password, user.password);

        const refreshToken = jwt.sign({ userId: user.userId }, process.env.REFRESH_TOKEN_SECRET);
        await db.query('UPDATE credentials SET refreshToken = ? WHERE userId = ?', [refreshToken, user.userId]);

        res.json(isValid ? {
            status: 'success',
            message: 'Login successful',
            accessToken: generateAccessToken({ userId: user.userId }),
            refreshToken,
        } : {
            status: 'error',
            message: 'Invalid username/password',
        });
    } catch (err) {
        handleDatabaseError(res, err);
    }
});

app.post('/api/logout', authenticateToken, async (req, res) => {
    try {
        // Invalidate the refresh token
        await db.query('UPDATE credentials SET refreshToken = NULL WHERE userId = ?', [req.user.userId]);

        // Instruct the client to delete the token
        res.json({ status: 'success', message: 'Logout successful' });
    } catch (err) {
        handleDatabaseError(res, err);
    }
});

app.get('/api/user/complete', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;

        // Get user data
        const [[user]] = await db.query('SELECT * FROM users WHERE id = ?', [userId]);

        // Get upgrades data
        let [upgrades] = await db.query('SELECT * FROM upgrades WHERE userId = ?', [req.user.userId]);
        upgrades = upgrades.reduce((acc, upgrade) => {
            acc[upgrade.upgradeName] = upgrade.upgradeValue;
            return acc;
        }, {});

        // Get stats data
        const [[stats]] = await db.query('SELECT * FROM stats WHERE userId = ?', [userId]);

        // Send the data in the response
        res.json({ taps: user.taps, upgrades, stats: { buttonClicked: stats.buttonClicked, upgradesPurchased: stats.upgradesPurchased, maxCps: stats.maxCps, timeSpent: stats.timeSpent } });
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

app.get('/api/protected', authenticateToken, (req, res) => {
    res.json({ status: 'success', message: 'Protected route' });
});

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
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

app.post('/api/token', async (req, res) => {
    const refreshToken = req.body.refreshToken;
    if (refreshToken == null) return res.sendStatus(401);

    const [[user]] = await db.query('SELECT * FROM credentials WHERE refreshToken = ?', [refreshToken]);
    if (!user) return res.sendStatus(403);

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        const accessToken = generateAccessToken({ userId: user.userId });
        res.json({ accessToken });
    });
});

app.get('/api/leaderboard', async (req, res) => {
    try {
        const [results] = await db.query('SELECT users.taps, credentials.username FROM users JOIN credentials ON users.id = credentials.userId ORDER BY users.taps DESC LIMIT 10');
        res.json({ status: 'success', data: results });
    } catch (err) {
        handleDatabaseError(res, err);
    }
});

app.listen(process.env.PORT || 5000, () =>
    console.log(`Server running on port ${process.env.PORT || 5000}`)
);