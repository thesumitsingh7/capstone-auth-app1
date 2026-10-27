/**
 * Authentication & Security Module
 *
 * Implements:
 * - Cryptographic password hashing using Node.js native 'crypto.scryptSync' with unique per-user salts
 * - Constant-time comparison to prevent timing attacks
 * - Signed HMAC-SHA256 session tokens with expiration
 */

const crypto = require('crypto');

const JWT_SECRET = process.env.JWT_SECRET || 'capstone-auth-secret-key-upstart-2026-xyz789';
const TOKEN_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 hours

// Hash password with a unique cryptographic salt using memory-hard scrypt
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(password, salt, 64);
  return {
    salt,
    hash: derivedKey.toString('hex')
  };
}

// Verify password against stored hash and salt in constant time
function verifyPassword(password, storedHash, salt) {
  const derivedKey = crypto.scryptSync(password, salt, 64);
  const hashBuffer = Buffer.from(storedHash, 'hex');
  const derivedBuffer = derivedKey;
  if (hashBuffer.length !== derivedBuffer.length) return false;
  return crypto.timingSafeEqual(hashBuffer, derivedBuffer);
}

// Generate signed authentication token
function generateToken(user) {
  const payload = {
    userId: user.id,
    email: user.email,
    name: user.name,
    exp: Date.now() + TOKEN_EXPIRY_MS
  };
  const payloadBase64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', JWT_SECRET).update(payloadBase64).digest('base64url');
  return `${payloadBase64}.${signature}`;
}

// Verify and decode signed token
function verifyToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;

  const [payloadBase64, providedSignature] = parts;
  const expectedSignature = crypto.createHmac('sha256', JWT_SECRET).update(payloadBase64).digest('base64url');

  if (providedSignature !== expectedSignature) return null;

  try {
    const payloadJson = Buffer.from(payloadBase64, 'base64url').toString('utf-8');
    const payload = JSON.parse(payloadJson);
    if (Date.now() > payload.exp) return null; // Token expired
    return payload;
  } catch (e) {
    return null;
  }
}

module.exports = {
  hashPassword,
  verifyPassword,
  generateToken,
  verifyToken
};
