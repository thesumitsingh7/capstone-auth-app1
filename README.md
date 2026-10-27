# Task 04 — Capstone: Authenticated App with Scoped Data
**Internship:** UpStartInterns · Full Stack Development  
**Student Intern:** Sumit Kumar  
**Project:** VaultNotes · Secure Authenticated Workspace  
**Database:** Relational SQLite (`capstone.db`)  
**Deployment:** Production-ready for Render / Railway / Vercel (Free Tier)  

---

## 🌟 Overview

**VaultNotes** is a full-stack, authenticated web application built as the **Capstone Project (Level 4 of 4)** for UpStartInterns. It features secure cryptographic user authentication, password hashing using memory-hard `scrypt`, and strict tenant isolation where users can only view, create, and manage their own private records.

---

## ✅ Acceptance Criteria & Feature Checklist

| Requirement | Implementation Details | Status |
| :--- | :--- | :---: |
| **Login with Hashed Passwords** | Implemented using Node.js native `crypto.scryptSync` with unique 16-byte cryptographic salts per user. Plaintext passwords are never stored. Constant-time verification prevents timing attacks. | **PASSED** |
| **Data Scoped to Signed-In User** | Every database query enforces `WHERE user_id = ?`. Users cannot read, modify, or delete another user's notes under any condition. | **PASSED** |
| **Relational SQLite Database** | Relational schema in `capstone.db` with foreign keys, indexes, and cascade deletion. | **PASSED** |
| **Session Authentication** | Signed HMAC-SHA256 session tokens with 24-hour expiration. Protected API routes reject unauthenticated requests with `401 Unauthorized`. | **PASSED** |
| **Free-Tier Deployment Ready** | Pre-configured with `render.yaml`, `Procfile`, and zero native compile steps for instant 1-click deployment on Render / Railway. | **PASSED** |
| **Automated Tests** | 20 automated tests in `test-auth-scope.js` verifying password hashing, token validation, and cross-user data isolation. | **PASSED** |

---

## 👥 Instant Test Accounts (Pre-Seeded)

The database includes two distinct users so reviewers can immediately verify that data is strictly scoped:

| User | Email | Password | Role | Pre-Seeded Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Alex** | `alex@example.com` | `Password123!` | Developer | 2 private engineering notes |
| **Sam** | `sam@example.com` | `Password123!` | Designer | 2 private design system notes |

> **How to verify data scoping:**
> 1. Sign in as **Alex** (`alex@example.com`). You will see Alex's private engineering notes.
> 2. Create a new note as Alex.
> 3. Click **Sign Out** and sign in as **Sam** (`sam@example.com`).
> 4. Notice that none of Alex's notes or the newly created note appear. Only Sam's design notes are visible!

---

## 🔒 Security & Data Scoping Architecture

### 1. Password Hashing (`auth.js`)
```javascript
// Each user gets a unique 16-byte random salt
const salt = crypto.randomBytes(16).toString('hex');
// Scrypt memory-hard hashing resistant to brute-force and GPU cracking
const derivedKey = crypto.scryptSync(password, salt, 64);
const passwordHash = derivedKey.toString('hex');
```

### 2. Strict Tenant Data Scoping (`db.js`)
```sql
-- All notes queries are bound to the authenticated user ID
SELECT * FROM notes WHERE user_id = ?;

-- Deletion verifies both note ID and ownership
DELETE FROM notes WHERE id = ? AND user_id = ?;
```

---

## 🚀 How to Run Locally

### 1. Start the Server
```bash
node server.js
```
The server will start listening at:
```text
http://localhost:3000
```
Open `http://localhost:3000` in any modern web browser to access the complete application.

### 2. Run the Verification Tests
To run the automated test suite verifying password hashing, token security, and user-scoped data:
```bash
node test-auth-scope.js
```

---

## 🌐 60-Second Free Tier Deployment (Render)

You can deploy this repository to **Render** completely free in 3 steps:

1. Go to **[dashboard.render.com](https://dashboard.render.com)** and click **New +** → **Web Service**.
2. Connect your public GitHub repository: `https://github.com/thesumitsingh7/capstone-auth-app`.
3. Set:
   - **Runtime**: `Node`
   - **Build Command**: `npm install` (or leave empty)
   - **Start Command**: `node server.js`
   - **Plan**: `Free`
4. Click **Create Web Service**. Within 60 seconds, Render will provide your public live URL:
   ```text
   https://capstone-auth-app-xxxx.onrender.com
   ```

---

## 📡 API Endpoints

### Authentication
- `POST /api/auth/register` — Create a new account with hashed password.
- `POST /api/auth/login` — Authenticate and receive a signed session token.
- `GET /api/auth/me` — Retrieve current authenticated user profile.

### Scoped Data (Requires `Authorization: Bearer <token>`)
- `GET /api/notes` — List all notes belonging exclusively to the authenticated user.
- `POST /api/notes` — Create a new note automatically bound to the authenticated user's ID.
- `DELETE /api/notes/:id` — Delete a note owned by the authenticated user.
