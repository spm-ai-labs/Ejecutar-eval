// Vulnerabilidad 21: Configuración insegura
module.exports = {
    PORT: process.env.PORT || 3000,
    
    // Vulnerabilidad 22: Credenciales en código
    DB_HOST: process.env.DB_HOST || 'localhost',
    DB_USER: process.env.DB_USER || 'root',
    DB_PASSWORD: process.env.DB_PASSWORD || 'admin123',
    DB_NAME: process.env.DB_NAME || 'myapp',
    
    // Vulnerabilidad 23: JWT secret débil por defecto
    JWT_SECRET: process.env.JWT_SECRET || 'my-secret-key',
    
    // Vulnerabilidad 24: Debug mode habilitado en producción
    DEBUG: process.env.DEBUG || true,
    
    // Vulnerabilidad 25: CORS permisivo
    CORS_ORIGIN: '*'
};
