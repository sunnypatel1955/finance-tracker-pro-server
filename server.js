require('dotenv').config();

const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const app = express();

// CORS configuration - clean and consistent
const corsOptions = {
    origin: [
        'http://localhost:3000',
        'http://localhost:5000',
        'http://127.0.0.1:5500',
        'http://127.0.0.1:5501',
        'https://sunnypatel1955.github.io'
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));

// Database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? {
        rejectUnauthorized: false
    } : false,
    // Connection pool config
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000
});

// Handle pool errors
pool.on('error', (err, client) => {
    console.error('Unexpected error on idle client', err);
    // Don't exit the process, just log the error
});

// Test database connection
pool.connect((err, client, release) => {
    if (err) {
        console.error('❌ Error connecting to database:', err);
    } else {
        console.log('✅ Database connected successfully');
        release();
    }
});

// Authentication Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT verification error:', err);
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

// Health check endpoint
app.get('/', (req, res) => {
    res.json({ 
        message: 'Finance Tracker Server is running',
        timestamp: new Date().toISOString()
    });
});

// Registration endpoint
app.post('/api/register', async (req, res) => {
    const { fullName, email, password } = req.body || {};
    
    // Input validation
    if (!fullName || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (password.length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    
    try {
        const hashedPassword = await bcrypt.hash(password, 12);
        const result = await pool.query(
            'INSERT INTO users (email, password_hash, full_name) VALUES ($1, $2, $3) RETURNING user_id, email, full_name',
            [email.toLowerCase(), hashedPassword, fullName]
        );
        
        res.status(201).json({ 
            message: 'User registered successfully',
            user: {
                id: result.rows[0].user_id,
                email: result.rows[0].email,
                fullName: result.rows[0].full_name
            }
        });
    } catch (err) {
        console.error('Registration error:', err);
        if (err.code === '23505') {
            res.status(409).json({ error: 'Email already exists' });
        } else {
            res.status(500).json({ error: 'Registration failed' });
        }
    }
});

// Login endpoint - FIXED to match frontend expectations
app.post('/api/login', async (req, res) => {
    if (!req.body) {
        return res.status(400).json({ error: 'Request body is missing' });
    }

    const { email, password, rememberMe } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        const result = await pool.query(
            'SELECT user_id, full_name, password_hash FROM users WHERE email = $1',
            [email.toLowerCase()]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const valid = await bcrypt.compare(password, result.rows[0].password_hash);
        if (!valid) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const expiresIn = rememberMe ? '30d' : '24h';
        const token = jwt.sign(
            {
                user_id: result.rows[0].user_id,
                email: email.toLowerCase()
            },
            process.env.JWT_SECRET,
            { expiresIn }
        );

        res.status(200).json({
            token,
            email: email.toLowerCase(),
            fullName: result.rows[0].full_name
        });

    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Change Password - FIXED to match frontend
app.post('/api/change-password', authenticateToken, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.user_id;
    
    if (!currentPassword || !newPassword) {
        return res.status(400).json({ error: 'Current and new passwords are required' });
    }
    
    if (newPassword.length < 8) {
        return res.status(400).json({ error: 'New password must be at least 8 characters' });
    }
    
    try {
        const result = await pool.query(
            'SELECT password_hash FROM users WHERE user_id = $1',
            [userId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const valid = await bcrypt.compare(currentPassword, result.rows[0].password_hash);
        if (!valid) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }
        
        const hashedPassword = await bcrypt.hash(newPassword, 12);
        await pool.query(
            'UPDATE users SET password_hash = $1 WHERE user_id = $2',
            [hashedPassword, userId]
        );
        
        res.status(200).json({ message: 'Password changed successfully' });
    } catch (err) {
        console.error('Change password error:', err);
        res.status(500).json({ error: 'Failed to change password' });
    }
});

// Save finance data - ENHANCED
app.post('/api/financeServerData', authenticateToken, async (req, res) => {
    const userId = req.user.user_id;
    const { financeServerData } = req.body;

    if (!financeServerData) {
        return res.status(400).json({ error: 'Finance data is required' });
    }

    try {
        const result = await pool.query(
            `INSERT INTO finance_data (user_id, data, updated_at) 
             VALUES ($1, $2, NOW()) 
             ON CONFLICT (user_id) 
             DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()
             RETURNING updated_at`,
            [userId, financeServerData]
        );
        
        console.log('✅ Finance data saved for user:', userId);
        res.status(200).json({ 
            message: 'Data saved successfully',
            timestamp: result.rows[0].updated_at
        });
    } catch (err) {
        console.error('❌ Save finance data error:', err);
        res.status(500).json({ error: 'Failed to save finance data' });
    }
});

// Get finance data - ENHANCED
app.get('/api/financeServerData', authenticateToken, async (req, res) => {
    const userId = req.user.user_id;

    try {
        const result = await pool.query(
            'SELECT data, updated_at FROM finance_data WHERE user_id = $1',
            [userId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'No data found for user' });
        }
        
        const savedData = result.rows[0].data;
        
        // Return the exact structure frontend expects
        res.status(200).json({
            data: savedData.data || {},
            version: savedData.version || 1,
            timestamp: savedData.timestamp || result.rows[0].updated_at,
            historicalNetWorth: savedData.historicalNetWorth || [],
            checksum: savedData.checksum
        });
    } catch (err) {
        console.error('❌ Get finance data error:', err);
        res.status(500).json({ error: 'Failed to fetch finance data' });
    }
});

// DELETE finance data - MISSING ENDPOINT ADDED
app.delete('/api/financeServerData', authenticateToken, async (req, res) => {
    const userId = req.user.user_id;

    try {
        const result = await pool.query(
            'DELETE FROM finance_data WHERE user_id = $1 RETURNING user_id',
            [userId]
        );
        
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'No data found to delete' });
        }
        
        console.log('✅ Finance data deleted for user:', userId);
        res.status(200).json({ message: 'All finance data deleted successfully' });
    } catch (err) {
        console.error('❌ Delete finance data error:', err);
        res.status(500).json({ error: 'Failed to delete finance data' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📊 Finance Tracker API is ready!`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully');
    server.close(() => {
        pool.end(() => {
            console.log('Database pool closed');
            process.exit(0);
        });
    });
});

// Handle uncaught errors
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
    // Don't exit on database errors
    if (!err.message.includes('client_termination')) {
        process.exit(1);
    }
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});
