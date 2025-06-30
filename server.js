require('dotenv').config();  // Make sure this is at the top

const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const dns = require('dns'); // Add this import

const app = express();

app.use(cors());
app.use(express.json());

// Force IPv4 DNS resolution
dns.setDefaultResultOrder('ipv4first');

console.log('🔍 Environment Variables Check:');
console.log('DATABASE_URL exists:', !!process.env.DATABASE_URL);
console.log('JWT_SECRET exists:', !!process.env.JWT_SECRET);
console.log('PORT:', process.env.PORT);

// Parse the DATABASE_URL to extract components and force IPv4
const dbUrl = new URL(process.env.DATABASE_URL);

console.log('🔧 Database connection details:');
console.log('Host:', dbUrl.hostname);
console.log('Port:', dbUrl.port);
console.log('Database:', dbUrl.pathname.slice(1));
console.log('User:', dbUrl.username);

// Create pool with IPv4-specific configuration
const pool = new Pool({
    host: dbUrl.hostname,
    port: parseInt(dbUrl.port) || 5432,
    database: dbUrl.pathname.slice(1), // Remove leading slash
    user: dbUrl.username,
    password: dbUrl.password,
    ssl: {
        rejectUnauthorized: false
    },
    // Force IPv4 connection
    family: 4,
    // Connection pool settings
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
});

// Enhanced connection event logging
pool.on('connect', (client) => {
    console.log('✅ Database client connected via IPv4');
});

pool.on('error', (err) => {
    console.error('❌ Database pool error:', err);
});

pool.on('acquire', () => {
    console.log('🔗 Database connection acquired from pool');
});

pool.on('release', () => {
    console.log('🔓 Database connection released back to pool');
});

// Test the IPv4 connection on startup
async function testConnection() {
    try {
        console.log('🔄 Testing IPv4 database connection...');
        
        const client = await pool.connect();
        const result = await client.query('SELECT NOW() as current_time, version() as postgres_version');
        
        console.log('✅ IPv4 connection successful!');
        console.log('🕐 Database time:', result.rows[0].current_time);
        console.log('📊 PostgreSQL version:', result.rows[0].postgres_version.split(' ')[0]);
        
        // Test if tables exist
        const tablesResult = await client.query(`
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
            ORDER BY table_name
        `);
        console.log('📋 Available tables:', tablesResult.rows.map(row => row.table_name));
        
        client.release();
        console.log('🎉 Database is fully operational with IPv4!');
        
    } catch (err) {
        console.error('❌ IPv4 connection test failed:');
        console.error('Error message:', err.message);
        console.error('Error code:', err.code);
        console.error('Error address:', err.address);
        console.error('Full error:', err);
    }
}

// Call test connection
testConnection();

console.log('Server starting...');

app.get('/', (req, res) => {
    console.log('Root / route accessed');
    res.send('Server is running with IPv4 database connection');
});

// Health check endpoint
app.get('/health', async (req, res) => {
    try {
        const result = await pool.query('SELECT NOW() as current_time');
        res.status(200).json({ 
            status: 'healthy', 
            database: 'connected via IPv4',
            timestamp: result.rows[0].current_time,
            connection_type: 'IPv4 forced'
        });
    } catch (error) {
        console.error('Health check failed:', error);
        res.status(500).json({ 
            status: 'unhealthy', 
            database: 'disconnected',
            error: error.message,
            error_code: error.code
        });
    }
});

console.log('process.env.PORT =', process.env.PORT);

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
    console.log('Middleware: authenticateToken() called');
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

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

// Enhanced Registration endpoint with IPv4 logging
app.post('/api/register', async (req, res) => {
    console.log('📝 Registration attempt started (IPv4 connection)');
    console.log('Request body received:', !!req.body);
    
    const { fullName, email, password } = req.body;
    
    if (!fullName || !email || !password) {
        console.log('❌ Missing required fields');
        return res.status(400).json({ error: 'All fields are required' });
    }
    
    try {
        console.log('🔐 Hashing password...');
        const hashedPassword = await bcrypt.hash(password, 10);
        
        console.log('💾 Inserting user into database via IPv4...');
        const result = await pool.query(
            'INSERT INTO users (email, password_hash, full_name) VALUES ($1, $2, $3) RETURNING user_id',
            [email, hashedPassword, fullName]
        );
        
        console.log('✅ User created successfully with ID:', result.rows[0].user_id);
        
        const token = jwt.sign({ user_id: result.rows[0].user_id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        
        console.log('🎫 JWT token generated successfully');
        res.status(201).json({ token });
        
    } catch (err) {
        console.error('❌ Registration error:');
        console.error('Error message:', err.message);
        console.error('Error code:', err.code);
        console.error('Error syscall:', err.syscall);
        console.error('Error address:', err.address);
        
        if (err.code === '23505') {
            res.status(409).json({ message: 'Email already registered.' });
        } else {
            res.status(500).json({ message: 'Registration failed: ' + err.message });
        }
    }
});

// Login endpoint (keep your existing login code but with enhanced logging)
app.post('/api/login', async (req, res) => {
    console.log('🔑 Login attempt started (IPv4 connection)');
    const { email, password } = req.body;
    
    try {
        const result = await pool.query(
            'SELECT user_id, full_name, password_hash FROM users WHERE email = $1', 
            [email]
        );
        
        if (result.rows.length === 0) {
            console.log('❌ User not found for email:', email);
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const valid = await bcrypt.compare(password, result.rows[0].password_hash);
        if (!valid) {
            console.log('❌ Invalid password for email:', email);
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const token = jwt.sign(
            { user_id: result.rows[0].user_id }, 
            process.env.JWT_SECRET, 
            { expiresIn: '1h' }
        );

        console.log('✅ Login successful for user:', result.rows[0].user_id);
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

// Keep all your other endpoints (finance data, change password, etc.) as they were
// Save complete finance data (JSON)
app.post('/api/financeServerData', authenticateToken, async (req, res) => {
    console.log('📥 Server: Received POST /api/financeServerData (IPv4)');

    const userId = req.user.user_id;
    const { financeServerData } = req.body;

    console.log('🔐 Authenticated userId:', userId);

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
        console.log('📤 Server: Sending finance data');
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
    console.log('🔒 Change password API called (IPv4)');
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
        console.log('✅ Password changed successfully');
        res.status(200).json({ message: 'Password changed successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to change password' });
    }
});
