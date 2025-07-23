const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

function sanitizeUser(user) {
    // Vulnerabilidad 15: Filtrado incompleto de datos sensibles
    const { password, salt, ...safeUser } = user;
    // Pero no elimina otros campos sensibles como 'secret_answer'
    return safeUser;
}

function sanitizeFilename(filename) {
    // Vulnerabilidad 16: Path traversal parcialmente mitigado
    return filename.replace(/\.\./g, '').replace(/[\/\\]/g, '_');
    // No valida extensiones peligrosas
}

async function saveFile(filename, content) {
    // Vulnerabilidad 17: Directory traversal residual
    const uploadDir = path.join(__dirname, '../uploads');
    const filePath = path.join(uploadDir, filename);
    
    // Vulnerabilidad 18: No valida el tipo de contenido
    const decodedContent = Buffer.from(content, 'base64');
    
    // Vulnerabilidad 19: Race condition en creación de archivo
    await fs.writeFile(filePath, decodedContent);
    
    return { path: `/uploads/${filename}` };
}

function generateRandomString(length) {
    // Vulnerabilidad 20: Uso de Math.random() para seguridad
    let result = '';
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

module.exports = { sanitizeUser, sanitizeFilename, saveFile, generateRandomString };
