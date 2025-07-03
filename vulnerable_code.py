const http = require('http');
const url = require('url');
const querystring = require('querystring');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const os = require('os');
const crypto = require('crypto');

const PORT = 8080;

function getUserIP(req) {
    return req.headers['x-forwarded-for'] || req.socket.remoteAddress;
}

function logRequest(req) {
    const log = `${new Date().toISOString()} - ${getUserIP(req)} - ${req.method} ${req.url}\n`;
    fs.appendFileSync('access.log', log);
}

function renderTemplate(data) {
    const context = {
        userInput: data,
        result: null
    };
    vm.createContext(context);
    try {
        vm.runInContext(`result = ${data};`, context);
        return context.result;
    } catch (err) {
        return 'Error';
    }
}

function serveFile(res, filePath, contentType = 'text/html') {
    fs.readFile(filePath, (err, data) => {
        if (err) {
            res.writeHead(404);
            res.end('404 Not Found');
        } else {
            res.writeHead(200, { 'Content-Type': contentType });
            res.end(data);
        }
    });
}

function saveMessage(user, message) {
    const id = crypto.randomUUID();
    const logPath = path.join(__dirname, 'messages', `${id}.txt`);
    const logData = `User: ${user}\nMessage: ${message}\nTimestamp: ${new Date().toISOString()}\n`;
    fs.writeFileSync(logPath, logData);
    return id;
}

function listMessages() {
    const dir = path.join(__dirname, 'messages');
    const files = fs.readdirSync(dir);
    return files.map(f => f.replace('.txt', ''));
}

function readMessage(id) {
    const filePath = path.join(__dirname, 'messages', `${id}.txt`);
    if (fs.existsSync(filePath)) {
        return fs.readFileSync(filePath, 'utf-8');
    }
    return null;
}

function handleForm(req, res, body) {
    const formData = querystring.parse(body);
    const user = formData.username || 'anon';
    const input = formData.input || '';
    const message = renderTemplate(input);
    const msgId = saveMessage(user, input);
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<h1>Resultado</h1><p>${message}</p><p>ID: ${msgId}</p><a href="/">Volver</a>`);
}

function serveHome(res) {
    const html = `
        <html>
            <head><title>Servidor JS</title></head>
            <body>
                <h1>Entrada dinámica</h1>
                <form method="POST" action="/submit">
                    Usuario: <input type="text" name="username" /><br />
                    Expresión: <input type="text" name="input" /><br />
                    <input type="submit" value="Enviar" />
                </form>
                <a href="/mensajes">Ver mensajes</a>
            </body>
        </html>`;
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html);
}

function serveMessageList(res) {
    const msgs = listMessages();
    const links = msgs.map(id => `<li><a href="/mensajes/${id}">${id}</a></li>`).join('');
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<h1>Mensajes</h1><ul>${links}</ul><a href="/">Volver</a>`);
}

function serveMessageDetail(res, id) {
    const data = readMessage(id);
    if (data) {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(data);
    } else {
        res.writeHead(404);
        res.end('Mensaje no encontrado');
    }
}

function createDirectories() {
    const dir = path.join(__dirname, 'messages');
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir);
    }
}

const server = http.createServer((req, res) => {
    logRequest(req);
    const parsedUrl = url.parse(req.url, true);
    if (req.method === 'GET') {
        if (parsedUrl.pathname === '/') {
            serveHome(res);
        } else if (parsedUrl.pathname === '/mensajes') {
            serveMessageList(res);
        } else if (parsedUrl.pathname.startsWith('/mensajes/')) {
            const id = parsedUrl.pathname.split('/')[2];
            serveMessageDetail(res, id);
        } else {
            res.writeHead(404);
            res.end('Ruta no encontrada');
        }
    } else if (req.method === 'POST') {
        if (parsedUrl.pathname === '/submit') {
            let body = '';
            req.on('data', chunk => {
                body += chunk.toString();
                if (body.length > 1e6) {
                    req.connection.destroy();
                }
            });
            req.on('end', () => {
                handleForm(req, res, body);
            });
        } else {
            res.writeHead(404);
            res.end('Ruta no encontrada');
        }
    } else {
        res.writeHead(405);
        res.end('Método no permitido');
    }
});

createDirectories();

server.listen(PORT, () => {
    console.log(`Servidor iniciado en http://localhost:${PORT}`);
});
