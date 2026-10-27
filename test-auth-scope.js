/**
 * Automated Verification Suite for Task 04 Capstone App
 * Tests password hashing, authentication flow, and strict user data scoping.
 */

const CapstoneDatabase = require('./db.js');
const { hashPassword, verifyPassword, generateToken, verifyToken } = require('./auth.js');

function runCapstoneTests() {
  console.log('===============================================================');
  console.log('🧪 RUNNING TASK 04 CAPSTONE TESTS: AUTHENTICATION & DATA SCOPING');
  console.log('===============================================================\n');

  let passed = 0;
  let failed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`  ✅ PASS: ${message}`);
      passed++;
    } else {
      console.error(`  ❌ FAIL: ${message}`);
      failed++;
    }
  }

  const db = new CapstoneDatabase();

  // 1. Password Hashing Verification
  console.log('1. Testing Password Hashing & Salt Randomness:');
  const pass = 'SuperSecret2026!';
  const hash1 = hashPassword(pass);
  const hash2 = hashPassword(pass);
  assert(hash1.hash !== pass, 'Password is never stored in plaintext');
  assert(hash1.salt !== hash2.salt, 'Unique cryptographic salt generated per hash');
  assert(hash1.hash !== hash2.hash, 'Different salt produces different hash for same password');
  assert(verifyPassword(pass, hash1.hash, hash1.salt) === true, 'Valid password verifies correctly');
  assert(verifyPassword('WrongPass', hash1.hash, hash1.salt) === false, 'Invalid password is rejected');

  // 2. Token Security Verification
  console.log('\n2. Testing Signed Session Token Flow:');
  const testUser = { id: 99, email: 'test@example.com', name: 'Tester' };
  const token = generateToken(testUser);
  const decoded = verifyToken(token);
  assert(decoded !== null, 'Token verified and decoded successfully');
  assert(decoded.userId === 99, 'Token preserves user ID');
  assert(verifyToken(token + 'tampered') === null, 'Tampered token signature is rejected');

  // 3. User Seed Data Verification
  console.log('\n3. Testing Pre-seeded Users (Alex & Sam):');
  const alex = db.getUserByEmail('alex@example.com');
  const sam = db.getUserByEmail('sam@example.com');
  assert(alex !== null, 'Alex Developer exists in database');
  assert(sam !== null, 'Sam Designer exists in database');
  assert(alex.id !== sam.id, 'Users have distinct unique user IDs');

  // 4. Data Scoping Verification (The Core Requirement)
  console.log('\n4. Testing Strict Data Scoping (User 1 vs User 2):');
  const alexNotes = db.getNotesByUser(alex.id);
  const samNotes = db.getNotesByUser(sam.id);

  assert(alexNotes.length >= 2, `Alex has ${alexNotes.length} notes`);
  assert(samNotes.length >= 2, `Sam has ${samNotes.length} notes`);

  // Verify Alex's query returns ONLY Alex's notes
  const alexLeak = alexNotes.some(n => n.user_id !== alex.id);
  assert(alexLeak === false, 'Alex can ONLY see notes belonging to User ID ' + alex.id);

  // Verify Sam's query returns ONLY Sam's notes
  const samLeak = samNotes.some(n => n.user_id !== sam.id);
  assert(samLeak === false, 'Sam can ONLY see notes belonging to User ID ' + sam.id);

  // 5. Cross-User Unauthorized Access Prevention
  console.log('\n5. Testing Cross-Tenant Access Restrictions:');
  const alexNoteId = alexNotes[0].id;
  const samAttemptAccess = db.getNoteByIdAndUser(alexNoteId, sam.id);
  assert(samAttemptAccess === null, 'Sam CANNOT view Alex’s private note (Returns null / 404)');

  const samAttemptDelete = db.deleteNote(alexNoteId, sam.id);
  assert(samAttemptDelete === null, 'Sam CANNOT delete Alex’s private note (Blocked)');

  const alexStillHasNote = db.getNoteByIdAndUser(alexNoteId, alex.id);
  assert(alexStillHasNote !== null, 'Alex’s note remains safe and untampered');

  // 6. Creating a New Scoped Note
  console.log('\n6. Testing Creating a New Scoped Note:');
  const newAlexNote = db.createNote({
    userId: alex.id,
    title: 'Cloud Deployment Checklist',
    content: 'Deploy capstone app to free tier on Render or Railway with public URL.',
    category: 'Work',
    isPinned: true
  });
  assert(newAlexNote.user_id === alex.id, 'New note automatically stamped with Alex’s User ID');

  const samAfterAlexAdded = db.getNotesByUser(sam.id);
  const samSawAlexNewNote = samAfterAlexAdded.some(n => n.id === newAlexNote.id);
  assert(samSawAlexNewNote === false, 'Sam does NOT see Alex’s newly created note');

  // Clean up test note
  db.deleteNote(newAlexNote.id, alex.id);

  console.log('\n===============================================================');
  console.log(`TOTAL: ${passed} passed, ${failed} failed`);
  console.log('===============================================================');

  process.exit(failed > 0 ? 1 : 0);
}

runCapstoneTests();
