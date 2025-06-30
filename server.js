require('dotenv').config();

const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

console.log('🔍 Environment Variables Check:');
console.log('DATABASE_URL exists:', !!process.env.DATABASE_URL);
console.log('JWT_SECRET exists:', !!process.env.JWT_SECRET);
console.log('PORT:', process.env.PORT);

// Simple pool configuration with Supavisor (IPv4 compatible)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    },
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
});

// Test connection on startup
async function testConnection() {
    try {
        console.log('🔄 Testing Supavisor connection...');
        const client = await pool.connect();
        const result = await client.query('SELECT NOW() as current_time, version() as postgres_version');
        
        console.log('✅ Supavisor connection successful!');
        console.log('🕐 Database time:', result.rows[0].current_time);
        console.log('📊 PostgreSQL version:', result.rows[0].postgres_version.split(' ')[0]);
        
        // Test tables
        const tablesResult = await client.query(`
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
            ORDER BY table_name
        `);
        console.log('📋 Available tables:', tablesResult.rows.map(row => row.table_name));
        
        client.release();
        console.log('🎉 Database is fully operational via Supavisor!');
        
    } catch (err) {
        console.error('❌ Supavisor connection failed:');
        console.error('Error message:', err.message);
        console.error('Error code:', err.code);
        console.error('Full error:', err);
    }
}

testConnection();

console.log('Server starting...');

app.get('/', (req, res) => {
    console.log('Root / route accessed');
    res.send('Server is running with Supavisor (IPv4 compatible) connection');
});

app.get('/health', async (req, res) => {
    try {
        const result = await pool.query('SELECT NOW() as current_time');
        res.status(200).json({ 
            status: 'healthy', 
            database: 'connected via Supavisor',
            timestamp: result.rows[0].current_time,
            connection_type: 'Supavisor (IPv4 compatible)'
        });
    } catch (error) {
        console.error('Health check failed:', error);
        res.status(500).json({ 
            status: 'unhealthy', 
            database: 'disconnected',
            error: error.message
        });
    }
});

const PORT = process.env.PORT;
if (!PORT) {
    console.error('ERROR: PORT env variable is not set!');
    process.exit(1);
}

app.listen(PORT, () => {
    console.log('Server running on port ' + PORT);
});

// Authentication Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Token missing' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

// Registration endpoint
app.post('/api/register', async (req, res) => {
    console.log('📝 Registration attempt via Supavisor');
    const { fullName, email, password } = req.body;
    
    if (!fullName || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (email, password_hash, full_name) VALUES ($1, $2, $3) RETURNING user_id',
            [email, hashedPassword, fullName]
        );
        
        console.log('✅ User created with ID:', result.rows[0].user_id);
        const token = jwt.sign({ user_id: result.rows[0].user_id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(201).json({ token });
        
    } catch (err) {
        console.error('❌ Registration error:', err.message);
        if (err.code === '23505') {
            res.status(409).json({ message: 'Email already registered.' });
        } else {
            res.status(500).json({ message: 'Registration failed.' });
        }
    }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
    console.log('🔑 Login attempt via Supavisor');
    const { email, password } = req.body;
    
    try {
        const result = await pool.query(
            'SELECT user_id, full_name, password_hash FROM users WHERE email = $1', 
            [email]
        );
        
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const valid = await bcrypt.compare(password, result.rows[0].password_hash);
        if (!valid) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const token = jwt.sign({ user_id: result.rows[0].user_id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        
        res.status(200).json({
            token,
            email,
            fullName: result.rows[0].full_name
        });

    } catch (err) {
        console.error('❌ Login error:', err);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Your other endpoints (finance data, change password, etc.)
app.post('/api/financeServerData', authenticateToken, async (req, res) => {
    const userId = req.user.user_id;
    const { financeServerData } = req.body;

    try {
        const result = await pool.query(
            'INSERT INTO finance_data (user_id, data, updated_at) VALUES ($1, $2, NOW()) ON CONFLICT (user_id) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()',
            [userId, financeServerData]
        );
        res.status(200).json({ message: 'Finance data saved successfully on server' });
    } catch (err) {
        console.error('❌ Error during DB operation:', err);
        res.status(500).json({ error: 'Failed to save finance data' });
    }
});

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

app.post('/api/change-password', authenticateToken, async (req, res) => {
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
