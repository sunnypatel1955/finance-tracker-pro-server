require('dotenv').config();  // Make sure this is at the top

const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json());

// Use environment variables from .env locally,
// but on Heroku use DATABASE_URL with SSL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
      rejectUnauthorized: false
    }
});

// Registration endpoint
app.post('/api/register', async (req, res) => {
    const { fullName, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (email, password_hash, full_name) VALUES ($1, $2, $3) RETURNING user_id',
            [email, hashedPassword, fullName]
        );
        const token = jwt.sign({ user_id: result.rows[0].user_id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(201).json({ token });
    } catch (err) {
        console.error(err);
        if (err.code === '23505') {
            res.status(409).json({ message: 'Email already registered.' });
        } else {
            res.status(500).json({ message: 'Registration failed.' });
        }
    }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query(
            'SELECT user_id, full_name, password_hash FROM users WHERE email = $1', 
            [email]
        );
        if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid email or password' });

        const valid = await bcrypt.compare(password, result.rows[0].password_hash);
        if (!valid) return res.status(401).json({ error: 'Invalid email or password' });

        const token = jwt.sign(
            { user_id: result.rows[0].user_id }, 
            process.env.JWT_SECRET, 
            { expiresIn: '1h' }
        );

        // Send token, email, and full name
        res.status(200).json({
            token,
            email,
            fullName: result.rows[0].full_name
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Login failed' });
    }
});

console.log('Server starting...');

app.get('/', (req, res) => {
  console.log('Root / route accessed');
  res.send('Server is running');
});

console.log('process.env.PORT =', process.env.PORT);


// --- REPLACE app.listen WITH THE FOLLOWING ---

const PORT = process.env.PORT;
if (!PORT) {
  console.error('ERROR: PORT env variable is not set!');
  process.exit(1); // Exit if PORT is missing so you catch it immediately
}

app.listen(PORT, () => {
  console.log('Server running on port ' + PORT);
});

// Authentication Middleware
function authenticateToken(req, res, next) {
    console.log('Middleware: authenticateToken() called');
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Get token from "Bearer <token>"

    if (!token) return res.status(401).json({ error: 'Token missing' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error(err);
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

// Save complete finance data (JSON)
app.post('/api/financeServerData', authenticateToken, async (req, res) => {
    console.log('📥 Server: Received POST /api/financeServerData');

    const userId = req.user.user_id;
    const { financeServerData } = req.body;

    console.log('🔐 Authenticated userId:', userId);
    console.log('📊 Received financeServerData:', financeServerData);

    try {
        const result = await pool.query(
            'INSERT INTO finance_data (user_id, data, updated_at) VALUES ($1, $2, NOW()) ON CONFLICT (user_id) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()',
            [userId, financeServerData]
        );
        console.log('✅ Database operation result:', result.rowCount);
        
        res.status(200).json({ message: 'Finance data saved successfully on server' });
    } catch (err) {
        console.error('❌ Error during DB operation:', err);
        res.status(500).json({ error: 'Failed to save finance data' });
    }
});

// Fetch complete finance data
app.get('/api/financeServerData', authenticateToken, async (req, res) => {
    const userId = req.user.user_id;

    try {
        const result = await pool.query(
            'SELECT data FROM finance_data WHERE user_id = $1',
            [userId]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'No data found for user' });
        }
        const savedData = result.rows[0].data;
        console.log('📤 Server: Sending finance data:', savedData);
        res.status(200).json({
            data: savedData.data,
            version: savedData.version,
            timestamp: savedData.timestamp,
            historicalNetWorth: savedData.historicalNetWorth
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch finance data' });
    }
});

// Change Password API
app.post('/api/change-password', authenticateToken, async (req, res) => {
    console.log('Change password API called');
    const { email, currentPassword, newPassword } = req.body;
    
    try {
        const result = await pool.query(
            'SELECT user_id, password_hash FROM users WHERE email = $1',
            [email]
        );
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        const valid = await bcrypt.compare(currentPassword, result.rows[0].password_hash);
        if (!valid) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await pool.query(
            'UPDATE users SET password_hash = $1 WHERE user_id = $2',
            [hashedPassword, result.rows[0].user_id]
        );
        res.status(200).json({ message: 'Password changed successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to change password' });
    }
});


// Add Transaction
/*app.post('/api/transactions', authenticateToken, async (req, res) => {
    const { type, amount, description } = req.body;
    const userId = req.user.user_id;

    if (!type || !amount) {
        return res.status(400).json({ error: 'Type and amount are required' });
    }

    try {
        const result = await pool.query(
            'INSERT INTO transactions (user_id, type, amount, description) VALUES ($1, $2, $3, $4) RETURNING *',
            [userId, type, amount, description]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to add transaction' });
    }
});


// Fetch Transactions API
app.get('/api/transactions', authenticateToken, async (req, res) => {
    const user_id = req.user.user_id;
    try {
        const result = await pool.query(
            'SELECT transaction_id, type, amount, category, description, date FROM transactions WHERE user_id = $1 ORDER BY date DESC',
            [user_id]
        );
        res.status(200).json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch transactions' });
    }
});

// Delete Transaction API
app.delete('/api/transactions/:id', authenticateToken, async (req, res) => {
    const user_id = req.user.user_id;
    const transaction_id = req.params.id;
    try {
        const result = await pool.query(
            'DELETE FROM transactions WHERE transaction_id = $1 AND user_id = $2 RETURNING *',
            [transaction_id, user_id]
        );
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Transaction not found or unauthorized' });
        }
        res.status(200).json({ message: 'Transaction deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to delete transaction' });
    }
});*/