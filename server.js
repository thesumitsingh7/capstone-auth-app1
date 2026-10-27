/**
 * Task 04 Capstone — Authenticated Full Stack Web Application
 * Level 4 of 4 · Capstone — the portfolio piece you show an employer.
 *
 * Requirements Met:
 * - Login with hashed passwords (using cryptographic scrypt + per-user salt)
 * - Data scoped to the signed-in user (queries strictly filtered by user_id)
 * - Deployed on a free tier with a public URL (Render / Vercel configs included)
 * - Persistent relational database with SQLite
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const CapstoneDatabase = require('./db.js');
const { hashPassword, verifyPassword, generateToken, verifyToken } = require('./auth.js');

const db = new CapstoneDatabase();

let express;
try {
  express = require('express');
} catch (e) {
  express = null;
}

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');

const VALID_CATEGORIES = ['Work', 'Personal', 'Study', 'Finance', 'Ideas'];

// Helper to extract authenticated user from Authorization header
function getAuthenticatedUser(authHeader) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.substring(7).trim();
  return verifyToken(token);
}

// Controller Handlers
function handleRegister(body, res) {
  const { name, email, password } = body || {};
  if (!name || typeof name !== 'string' || name.trim().length < 2) {
    return res.status(400).json({ error: "Validation error: 'name' is required (minimum 2 characters)" });
  }
  if (!email || typeof email !== 'string' || !email.includes('@') || !email.includes('.')) {
    return res.status(400).json({ error: "Validation error: valid 'email' is required" });
  }
  if (!password || typeof password !== 'string' || password.length < 6) {
    return res.status(400).json({ error: "Validation error: 'password' must be at least 6 characters" });
  }

  const existing = db.getUserByEmail(email);
  if (existing) {
    return res.status(409).json({ error: 'An account with this email address already exists' });
  }

  const { hash, salt } = hashPassword(password);
  const newUser = db.createUser({ name, email, passwordHash: hash, salt });
  const token = generateToken(newUser);

  res.status(201).json({
    message: 'User account created successfully',
    token,
    user: { id: newUser.id, name: newUser.name, email: newUser.email }
  });
}

function handleLogin(body, res) {
  const { email, password } = body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const user = db.getUserByEmail(email);
  if (!user) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const isMatch = verifyPassword(password, user.password_hash, user.salt);
  if (!isMatch) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const token = generateToken(user);
  res.status(200).json({
    message: 'Login successful',
    token,
    user: { id: user.id, name: user.name, email: user.email }
  });
}

function handleGetNotes(user, query, res) {
  const notes = db.getNotesByUser(user.userId, query);
  res.status(200).json(notes);
}

function handleCreateNote(user, body, res) {
  const { title, content, category, isPinned } = body || {};

  if (!title || typeof title !== 'string' || title.trim().length < 2 || title.trim().length > 120) {
    return res.status(400).json({ error: "Validation error: 'title' is required (2-120 chars)" });
  }
  if (!content || typeof content !== 'string' || content.trim().length < 1) {
    return res.status(400).json({ error: "Validation error: 'content' cannot be empty" });
  }
  if (category && !VALID_CATEGORIES.includes(category)) {
    return res.status(400).json({ error: `Category must be one of: ${VALID_CATEGORIES.join(', ')}` });
  }

  const newNote = db.createNote({
    userId: user.userId,
    title: title.trim(),
    content: content.trim(),
    category: category || 'Work',
    isPinned: Boolean(isPinned)
  });

  res.status(201).json(newNote);
}

function handleDeleteNote(user, noteId, res) {
  const deleted = db.deleteNote(noteId, user.userId);
  if (!deleted) {
    return res.status(404).json({ error: 'Note not found or you do not have permission to delete it' });
  }
  res.status(200).json({ message: 'Note deleted successfully', deleted });
}

// Server Startup
if (express) {
  const app = express();
  app.use(express.json());
  app.use(express.static(PUBLIC_DIR));

  // Auth Middleware
  function authMiddleware(req, res, next) {
    const user = getAuthenticatedUser(req.headers['authorization']);
    if (!user) {
      return res.status(401).json({ error: 'Authentication required. Please sign in.' });
    }
    req.user = user;
    next();
  }

  app.post('/api/auth/register', (req, res) => handleRegister(req.body, res));
  app.post('/api/auth/login', (req, res) => handleLogin(req.body, res));
  app.get('/api/auth/me', authMiddleware, (req, res) => res.status(200).json({ user: req.user }));

  app.get('/api/notes', authMiddleware, (req, res) => handleGetNotes(req.user, req.query, res));
  app.post('/api/notes', authMiddleware, (req, res) => handleCreateNote(req.user, req.body, res));
  app.delete('/api/notes/:id', authMiddleware, (req, res) => handleDeleteNote(req.user, req.params.id, res));

  const server = app.listen(PORT, () => {
    console.log(`[Express] Capstone app running at http://localhost:${PORT}`);
  });

  module.exports = { app, server, db };
} else {
  const server = http.createServer((req, res) => {
    res.status = function (code) {
      this.statusCode = code;
      return this;
    };
    res.json = function (data) {
      this.setHeader('Content-Type', 'application/json; charset=utf-8');
      this.end(JSON.stringify(data, null, 2));
    };

    const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = parsedUrl.pathname.replace(/\/+$/, '') || '/';
    const method = req.method.toUpperCase();

    // Serve Frontend
    if (method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
      const htmlPath = path.join(PUBLIC_DIR, 'index.html');
      if (fs.existsSync(htmlPath)) {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.end(fs.readFileSync(htmlPath));
      }
    }

    let rawBody = '';
    req.on('data', chunk => rawBody += chunk);
    req.on('end', () => {
      req.body = {};
      if (rawBody.trim()) {
        try {
          req.body = JSON.parse(rawBody);
        } catch (e) {
          return res.status(400).json({ error: 'Malformed JSON body' });
        }
      }

      // Public Auth Routes
      if (method === 'POST' && pathname === '/api/auth/register') {
        return handleRegister(req.body, res);
      }
      if (method === 'POST' && pathname === '/api/auth/login') {
        return handleLogin(req.body, res);
      }

      // Protected Routes
      const user = getAuthenticatedUser(req.headers['authorization']);
      if (!user) {
        return res.status(401).json({ error: 'Authentication required. Please sign in.' });
      }

      if (method === 'GET' && pathname === '/api/auth/me') {
        return res.status(200).json({ user });
      }

      if (method === 'GET' && pathname === '/api/notes') {
        const query = Object.fromEntries(parsedUrl.searchParams.entries());
        return handleGetNotes(user, query, res);
      }

      if (method === 'POST' && pathname === '/api/notes') {
        return handleCreateNote(user, req.body, res);
      }

      const matchNoteId = pathname.match(/^\/api\/notes\/([^/]+)$/);
      if (matchNoteId) {
        const noteId = matchNoteId[1];
        if (method === 'DELETE') {
          return handleDeleteNote(user, noteId, res);
        }
      }

      res.status(404).json({ error: `Cannot ${method} ${pathname}` });
    });
  });

  server.listen(PORT, () => {
    console.log(`[VaultNotes Server] listening at http://localhost:${PORT}`);
  });

  module.exports = { server, db };
}
