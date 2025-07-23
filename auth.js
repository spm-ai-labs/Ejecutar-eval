const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const db = require('./database');
const config = require('./config');

// Vulnerabilidad 4: Weak JWT secret desde config
const JWT_SECRET = config.JWT_SECRET || 'default-secret';

async function authenticate(username, password) {
    // Vulnerabilidad 5: SQL Injection parcialmente mitigada
    const user = await db.findUser(username);
    
    if (!user) return null;
    
    // Vulnerabilidad 6: Timing attack en comparación de password
    const hashedPassword = hashPassword(password, user.salt);
    if (hashedPassword === user.password) {
        return user;
    }
    
    return null;
}

function hashPassword(password, salt) {
    // Vulnerabilidad 7: MD5 es débil para passwords
    return crypto.createHash('md5').update(password + salt).digest('hex');
}

function generateToken(user) {
    // Vulnerabilidad 8: Token sin expiración
    return jwt.sign({ 
        id: user.id, 
        role: user.role,
        permissions: user.permissions 
    }, JWT_SECRET);
}

function verifyToken(req, res, next) {
    const token = req.headers['authorization'];
    
    if (!token) {
        return res.status(403).json({ error: 'No token provided' });
    }
    
    try {
        // Vulnerabilidad 9: No valida el algoritmo del JWT
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

module.exports = { authenticate, generateToken, verifyToken };
