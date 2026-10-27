/**
 * Database & User-Scoped Storage Layer for Task 04 Capstone App
 *
 * Implements:
 * - Relational tables for Users and User-Scoped Notes in SQLite
 * - Foreign key relationships and cascade rules
 * - Strict tenant isolation: every query enforces user_id ownership
 */

const fs = require('fs');
const path = require('path');
const { hashPassword } = require('./auth.js');

const DB_FILE = path.join(__dirname, 'capstone.db');

let sqliteEngine = null;
try {
  const { DatabaseSync } = require('node:sqlite');
  sqliteEngine = DatabaseSync;
} catch (e) {
  sqliteEngine = null;
}

class CapstoneDatabase {
  constructor(dbPath = DB_FILE) {
    this.dbPath = dbPath;
    this.isSqlite = !!sqliteEngine;

    if (this.isSqlite) {
      this.initSqlite();
    } else {
      this.initJsonFallback();
    }
  }

  initSqlite() {
    this.db = new sqliteEngine(this.dbPath);

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        category TEXT NOT NULL CHECK(category IN ('Work', 'Personal', 'Study', 'Finance', 'Ideas')),
        is_pinned BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes(user_id);
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    `);

    const userCount = this.db.prepare('SELECT COUNT(*) as count FROM users').get();
    if (userCount.count === 0) {
      this.seedInitialUsersAndNotes();
    }
  }

  seedInitialUsersAndNotes() {
    // 1. Seed Alex Developer
    const alexCreds = hashPassword('Password123!');
    const alexInsert = this.db.prepare(`
      INSERT INTO users (name, email, password_hash, salt)
      VALUES (?, ?, ?, ?)
    `).run('Alex Developer', 'alex@example.com', alexCreds.hash, alexCreds.salt);
    const alexId = alexInsert.lastInsertRowid;

    // 2. Seed Sam Designer
    const samCreds = hashPassword('Password123!');
    const samInsert = this.db.prepare(`
      INSERT INTO users (name, email, password_hash, salt)
      VALUES (?, ?, ?, ?)
    `).run('Sam Designer', 'sam@example.com', samCreds.hash, samCreds.salt);
    const samId = samInsert.lastInsertRowid;

    // 3. Seed Alex's private notes (User 1)
    const noteInsert = this.db.prepare(`
      INSERT INTO notes (user_id, title, content, category, is_pinned)
      VALUES (?, ?, ?, ?, ?)
    `);

    noteInsert.run(
      alexId,
      'Backend Microservices Roadmap',
      'Refactor API gateway, implement rate limiting with Redis, and transition to Docker containers.',
      'Work',
      1
    );
    noteInsert.run(
      alexId,
      'Full Stack System Architecture Notes',
      'Maintain clear separation between authentication middleware and resource handlers for tenant isolation.',
      'Study',
      0
    );

    // 4. Seed Sam's private notes (User 2)
    noteInsert.run(
      samId,
      'Design System Typography Tokens',
      'Switch main body font to Inter, headings to Plus Jakarta Sans. Maintain 8px spatial grid.',
      'Work',
      1
    );
    noteInsert.run(
      samId,
      'Mobile App Wireframe Sketches',
      'Create high-fidelity Figma prototypes for user dashboard and profile settings screens.',
      'Ideas',
      0
    );
  }

  initJsonFallback() {
    this.fallbackPath = this.dbPath.endsWith('.db') ? this.dbPath.replace(/\.db$/, '.json') : `${this.dbPath}.json`;
    if (!fs.existsSync(this.fallbackPath)) {
      const alexCreds = hashPassword('Password123!');
      const samCreds = hashPassword('Password123!');
      const initial = {
        users: [
          { id: 1, name: 'Alex Developer', email: 'alex@example.com', password_hash: alexCreds.hash, salt: alexCreds.salt, created_at: new Date().toISOString() },
          { id: 2, name: 'Sam Designer', email: 'sam@example.com', password_hash: samCreds.hash, salt: samCreds.salt, created_at: new Date().toISOString() }
        ],
        notes: [
          { id: 1, user_id: 1, title: 'Backend Microservices Roadmap', content: 'Refactor API gateway, implement rate limiting.', category: 'Work', is_pinned: 1, created_at: new Date().toISOString() },
          { id: 2, user_id: 2, title: 'Design System Typography Tokens', content: 'Switch main body font to Inter.', category: 'Work', is_pinned: 1, created_at: new Date().toISOString() }
        ]
      };
      fs.writeFileSync(this.fallbackPath, JSON.stringify(initial, null, 2), 'utf-8');
    }
  }

  // --- User Operations ---

  createUser({ name, email, passwordHash, salt }) {
    const cleanEmail = email.toLowerCase().trim();
    if (this.isSqlite) {
      const stmt = this.db.prepare(`
        INSERT INTO users (name, email, password_hash, salt)
        VALUES (?, ?, ?, ?)
      `);
      const res = stmt.run(name.trim(), cleanEmail, passwordHash, salt);
      return this.getUserById(res.lastInsertRowid);
    } else {
      const data = JSON.parse(fs.readFileSync(this.fallbackPath, 'utf-8'));
      const id = data.users.length > 0 ? Math.max(...data.users.map(u => u.id)) + 1 : 1;
      const user = { id, name: name.trim(), email: cleanEmail, password_hash: passwordHash, salt, created_at: new Date().toISOString() };
      data.users.push(user);
      fs.writeFileSync(this.fallbackPath, JSON.stringify(data, null, 2), 'utf-8');
      return user;
    }
  }

  getUserByEmail(email) {
    const cleanEmail = (email || '').toLowerCase().trim();
    if (this.isSqlite) {
      return this.db.prepare('SELECT * FROM users WHERE email = ?').get(cleanEmail) || null;
    } else {
      const data = JSON.parse(fs.readFileSync(this.fallbackPath, 'utf-8'));
      return data.users.find(u => u.email.toLowerCase() === cleanEmail) || null;
    }
  }

  getUserById(id) {
    const numId = parseInt(id, 10);
    if (isNaN(numId)) return null;
    if (this.isSqlite) {
      return this.db.prepare('SELECT id, name, email, created_at FROM users WHERE id = ?').get(numId) || null;
    } else {
      const data = JSON.parse(fs.readFileSync(this.fallbackPath, 'utf-8'));
      const u = data.users.find(u => u.id === numId);
      if (!u) return null;
      return { id: u.id, name: u.name, email: u.email, created_at: u.created_at };
    }
  }

  // --- User-Scoped Data Operations (Strictly enforced by userId) ---

  getNotesByUser(userId, filter = {}) {
    const numUserId = parseInt(userId, 10);
    if (this.isSqlite) {
      let query = 'SELECT * FROM notes WHERE user_id = ?';
      const params = [numUserId];

      if (filter.category) {
        query += ' AND category = ?';
        params.push(filter.category);
      }

      query += ' ORDER BY is_pinned DESC, id DESC';
      return this.db.prepare(query).all(...params);
    } else {
      const data = JSON.parse(fs.readFileSync(this.fallbackPath, 'utf-8'));
      return data.notes.filter(n => {
        if (n.user_id !== numUserId) return false;
        if (filter.category && n.category !== filter.category) return false;
        return true;
      }).sort((a, b) => (b.is_pinned || 0) - (a.is_pinned || 0) || b.id - a.id);
    }
  }

  getNoteByIdAndUser(noteId, userId) {
    const numNoteId = parseInt(noteId, 10);
    const numUserId = parseInt(userId, 10);
    if (isNaN(numNoteId) || isNaN(numUserId)) return null;

    if (this.isSqlite) {
      const stmt = this.db.prepare('SELECT * FROM notes WHERE id = ? AND user_id = ?');
      return stmt.get(numNoteId, numUserId) || null;
    } else {
      const data = JSON.parse(fs.readFileSync(this.fallbackPath, 'utf-8'));
      return data.notes.find(n => n.id === numNoteId && n.user_id === numUserId) || null;
    }
  }

  createNote({ userId, title, content, category, isPinned }) {
    const numUserId = parseInt(userId, 10);
    const cleanPinned = isPinned ? 1 : 0;
    const cleanCategory = category || 'Work';

    if (this.isSqlite) {
      const stmt = this.db.prepare(`
        INSERT INTO notes (user_id, title, content, category, is_pinned)
        VALUES (?, ?, ?, ?, ?)
      `);
      const res = stmt.run(numUserId, title, content, cleanCategory, cleanPinned);
      return this.getNoteByIdAndUser(res.lastInsertRowid, numUserId);
    } else {
      const data = JSON.parse(fs.readFileSync(this.fallbackPath, 'utf-8'));
      const id = data.notes.length > 0 ? Math.max(...data.notes.map(n => n.id)) + 1 : 1;
      const note = {
        id,
        user_id: numUserId,
        title,
        content,
        category: cleanCategory,
        is_pinned: cleanPinned,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };
      data.notes.push(note);
      fs.writeFileSync(this.fallbackPath, JSON.stringify(data, null, 2), 'utf-8');
      return note;
    }
  }

  updateNote(noteId, userId, fields) {
    const existing = this.getNoteByIdAndUser(noteId, userId);
    if (!existing) return null;

    const numNoteId = parseInt(noteId, 10);
    const numUserId = parseInt(userId, 10);

    const updated = {
      title: fields.title !== undefined ? fields.title : existing.title,
      content: fields.content !== undefined ? fields.content : existing.content,
      category: fields.category !== undefined ? fields.category : existing.category,
      is_pinned: fields.is_pinned !== undefined ? (fields.is_pinned ? 1 : 0) : existing.is_pinned
    };

    if (this.isSqlite) {
      const stmt = this.db.prepare(`
        UPDATE notes
        SET title = ?, content = ?, category = ?, is_pinned = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND user_id = ?
      `);
      stmt.run(updated.title, updated.content, updated.category, updated.is_pinned, numNoteId, numUserId);
      return this.getNoteByIdAndUser(numNoteId, numUserId);
    } else {
      const data = JSON.parse(fs.readFileSync(this.fallbackPath, 'utf-8'));
      const idx = data.notes.findIndex(n => n.id === numNoteId && n.user_id === numUserId);
      if (idx === -1) return null;
      data.notes[idx] = { ...data.notes[idx], ...updated, updated_at: new Date().toISOString() };
      fs.writeFileSync(this.fallbackPath, JSON.stringify(data, null, 2), 'utf-8');
      return data.notes[idx];
    }
  }

  deleteNote(noteId, userId) {
    const existing = this.getNoteByIdAndUser(noteId, userId);
    if (!existing) return null;

    const numNoteId = parseInt(noteId, 10);
    const numUserId = parseInt(userId, 10);

    if (this.isSqlite) {
      this.db.prepare('DELETE FROM notes WHERE id = ? AND user_id = ?').run(numNoteId, numUserId);
      return existing;
    } else {
      let data = JSON.parse(fs.readFileSync(this.fallbackPath, 'utf-8'));
      data.notes = data.notes.filter(n => !(n.id === numNoteId && n.user_id === numUserId));
      fs.writeFileSync(this.fallbackPath, JSON.stringify(data, null, 2), 'utf-8');
      return existing;
    }
  }

  close() {
    if (this.isSqlite && this.db && typeof this.db.close === 'function') {
      this.db.close();
    }
  }
}

module.exports = CapstoneDatabase;
