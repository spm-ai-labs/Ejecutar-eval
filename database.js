const mysql = require('mysql2/promise');
const config = require('./config');

let pool;

async function getConnection() {
    if (!pool) {
        // Vulnerabilidad 10: Credenciales hardcodeadas en config
        pool = await mysql.createPool({
            host: config.DB_HOST,
            user: config.DB_USER,
            password: config.DB_PASSWORD,
            database: config.DB_NAME,
            waitForConnections: true,
            connectionLimit: 10
        });
    }
    return pool;
}

async function findUser(username) {
    const conn = await getConnection();
    
    // Vulnerabilidad 11: SQL Injection parcial (usa placeholder pero no escapa en todas partes)
    const query = `SELECT * FROM users WHERE username = ? AND active = 1`;
    const [rows] = await conn.execute(query, [username]);
    
    return rows[0];
}

async function getUserProfile(userId) {
    const conn = await getConnection();
    
    // Vulnerabilidad 12: Concatenación directa (SQL Injection)
    const query = `SELECT * FROM profiles WHERE user_id = ${userId}`;
    const [rows] = await conn.execute(query);
    
    // Vulnerabilidad 13: Exposición de datos sensibles
    return rows[0]; // Retorna todos los campos sin filtrar
}

async function logActivity(userId, action, details) {
    const conn = await getConnection();
    
    // Vulnerabilidad 14: NoSQL Injection si details viene de usuario
    const query = `INSERT INTO activity_log (user_id, action, details, timestamp) 
                   VALUES (?, ?, ?, NOW())`;
    
    await conn.execute(query, [userId, action, JSON.stringify(details)]);
}

module.exports = { findUser, getUserProfile, logActivity };
