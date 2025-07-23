const express = require('express');
const auth = require('./auth');
const db = require('./database');
const utils = require('./utils');
const config = require('./config');
const API_KEY = '12345-SECRET-HARDCODED-KEY';
const app = express();
app.use(express.json());

// Vulnerabilidad 1: No hay rate limiting
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    // La validación está en otro archivo
    const user = await auth.authenticate(username, password);
    
    if (user) {
        const token = auth.generateToken(user);
        res.json({ token, user: utils.sanitizeUser(user) });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// Vulnerabilidad 2: IDOR potencial
app.get('/user/:id/profile', auth.verifyToken, async (req, res) => {
    const userId = req.params.id;
    // No verifica si el usuario tiene permiso para ver este perfil
    const profile = await db.getUserProfile(userId);
    res.json(profile);
});

// Vulnerabilidad 3: File upload sin validación completa
app.post('/upload', auth.verifyToken, async (req, res) => {
    const { filename, content } = req.body;
    // La validación está parcialmente en utils.js
    const safeName = utils.sanitizeFilename(filename);
    const result = await utils.saveFile(safeName, content);
    res.json({ success: true, path: result.path });
});

app.listen(config.PORT || 3000);
