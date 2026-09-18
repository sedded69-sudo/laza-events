// Gatekeep backend — Express + MongoDB
// ENV VARS REQUIRED: MONGODB_URI, JWT_SECRET
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json({ limit: '15mb' }));

const JWT_SECRET = process.env.JWT_SECRET || 'change-me';
const PORT = process.env.PORT || 4000;

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB error:', err.message));

// ---------- schemas ----------
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  passwordHash: String,
  role: { type: String, enum: ['admin', 'staff'], default: 'staff' },
  permissions: {
    scan: { type: Boolean, default: true },
    generate: { type: Boolean, default: false },
    passes: { type: Boolean, default: false }
  },
  createdAt: { type: Date, default: Date.now }
});
const LoginLogSchema = new mongoose.Schema({
  username: String,
  success: Boolean,
  at: { type: Date, default: Date.now }
});
const ConfigSchema = new mongoose.Schema({
  key: { type: String, unique: true },
  eventName: String,
  secret: String
});
const CategorySchema = new mongoose.Schema({
  tier: { type: String, unique: true },
  imageBase64: String
});
const TicketSchema = new mongoose.Schema({
  _id: String, // the pass ID itself
  tier: String,
  name: String,
  sig: String,
  used: { type: Boolean, default: false },
  usedAt: Date,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const LoginLog = mongoose.model('LoginLog', LoginLogSchema);
const Config = mongoose.model('Config', ConfigSchema);
const Category = mongoose.model('Category', CategorySchema);
const Ticket = mongoose.model('Ticket', TicketSchema);

// ---------- helpers ----------
function sign(id, tier, secret) {
  return crypto.createHmac('sha256', secret).update(id + '|' + tier).digest('hex').slice(0, 16);
}
function randomId() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const block = () => Array.from({ length: 4 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
  return [block(), block(), block()].join('-');
}
async function getSecret() {
  let cfg = await Config.findOne({ key: 'main' });
  if (!cfg) {
    cfg = await Config.create({ key: 'main', eventName: '', secret: crypto.randomBytes(24).toString('hex') });
  }
  return cfg.secret;
}

// auth middleware
function auth(requiredPerm) {
  return async (req, res, next) => {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      req.user = payload;
      if (requiredPerm && payload.role !== 'admin' && !payload.permissions?.[requiredPerm]) {
        return res.status(403).json({ error: 'No permission' });
      }
      next();
    } catch (e) {
      return res.status(401).json({ error: 'Invalid token' });
    }
  };
}

// ---------- bootstrap first admin ----------
app.post('/api/bootstrap-admin', async (req, res) => {
  const existingAdmin = await User.findOne({ role: 'admin' });
  if (existingAdmin) return res.status(400).json({ error: 'Admin already exists' });
  const { username, password } = req.body;
  if (!username || !password || password.length < 4) return res.status(400).json({ error: 'Invalid input' });
  const passwordHash = await bcrypt.hash(password, 10);
  await User.create({ username, passwordHash, role: 'admin', permissions: { scan: true, generate: true, passes: true } });
  res.json({ ok: true });
});
app.get('/api/has-admin', async (req, res) => {
  const existingAdmin = await User.findOne({ role: 'admin' });
  res.json({ hasAdmin: !!existingAdmin });
});

// PIN-protected account creation — lets you (re)create an admin account
// any time, even if one already exists, using a fixed PIN.
const CREATE_ACCOUNT_PIN = process.env.CREATE_ACCOUNT_PIN || '7878';
app.post('/api/create-account', async (req, res) => {
  const { username, password, pin } = req.body;
  if (pin !== CREATE_ACCOUNT_PIN) return res.status(403).json({ error: 'Wrong PIN' });
  if (!username || !password || password.length < 4) return res.status(400).json({ error: 'Invalid input' });
  const passwordHash = await bcrypt.hash(password, 10);
  await User.findOneAndUpdate(
    { username },
    { username, passwordHash, role: 'admin', permissions: { scan: true, generate: true, passes: true } },
    { upsert: true }
  );
  res.json({ ok: true });
});

// ---------- login ----------
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  const ok = user && await bcrypt.compare(password, user.passwordHash);
  await LoginLog.create({ username, success: !!ok });
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ username: user.username, role: user.role, permissions: user.permissions }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token, role: user.role, permissions: user.permissions, username: user.username });
});

// ---------- staff management (admin only) ----------
app.get('/api/users', auth(), async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const users = await User.find({}, '-passwordHash').sort({ createdAt: -1 });
  const logins = await LoginLog.find().sort({ at: -1 }).limit(100);
  res.json({ users, logins });
});
app.post('/api/users', auth(), async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { username, password, permissions } = req.body;
  if (!username || !password || password.length < 4) return res.status(400).json({ error: 'Invalid input' });
  const passwordHash = await bcrypt.hash(password, 10);
  try {
    await User.create({ username, passwordHash, role: 'staff', permissions: permissions || { scan: true } });
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: 'Username already exists' });
  }
});
app.delete('/api/users/:username', auth(), async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  await User.deleteOne({ username: req.params.username, role: 'staff' });
  res.json({ ok: true });
});

// ---------- config ----------
app.get('/api/config', async (req, res) => {
  const cfg = await Config.findOne({ key: 'main' });
  res.json({ eventName: cfg?.eventName || '' });
});
app.put('/api/config', auth(), async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  await getSecret();
  await Config.updateOne({ key: 'main' }, { $set: { eventName: req.body.eventName } });
  res.json({ ok: true });
});

// ---------- categories (pass artwork per tier) ----------
app.get('/api/categories', async (req, res) => {
  const cats = await Category.find();
  res.json(cats);
});
app.post('/api/categories', auth('generate'), async (req, res) => {
  const { tier, imageBase64 } = req.body;
  await Category.findOneAndUpdate({ tier }, { tier, imageBase64 }, { upsert: true });
  res.json({ ok: true });
});

// ---------- tickets ----------
app.post('/api/tickets/generate', auth('generate'), async (req, res) => {
  const { tier, qty, names } = req.body;
  if (!tier || !qty || qty < 1 || qty > 5000) return res.status(400).json({ error: 'Invalid input' });
  const secret = await getSecret();
  const docs = [];
  for (let i = 0; i < qty; i++) {
    const id = randomId();
    docs.push({ _id: id, tier, name: (names && names[i]) || '', sig: sign(id, tier, secret), used: false });
  }
  await Ticket.insertMany(docs);
  res.json({ ok: true, count: docs.length });
});
app.get('/api/tickets', auth('passes'), async (req, res) => {
  const tickets = await Ticket.find().sort({ createdAt: -1 });
  res.json(tickets);
});
app.delete('/api/tickets', auth(), async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  await Ticket.deleteMany({});
  res.json({ ok: true });
});
// atomic check-in — the $set only applies if used:false, so two simultaneous
// scans of the same pass can never both succeed.
app.post('/api/tickets/checkin', auth('scan'), async (req, res) => {
  const { raw } = req.body;
  const parts = (raw || '').split('.');
  if (parts.length !== 3) return res.json({ ok: false, reason: 'not_a_pass' });
  const [id, tier, sig] = parts;
  const secret = await getSecret();
  if (sign(id, tier, secret) !== sig) return res.json({ ok: false, reason: 'invalid_signature' });

  const updated = await Ticket.findOneAndUpdate(
    { _id: id, used: false },
    { $set: { used: true, usedAt: new Date() } },
    { new: true }
  );
  if (updated) return res.json({ ok: true, ticket: updated });

  const existing = await Ticket.findById(id);
  if (!existing) return res.json({ ok: false, reason: 'not_found' });
  return res.json({ ok: false, reason: 'already_used', usedAt: existing.usedAt, ticket: existing });
});

app.get('/', (req, res) => res.send('Gatekeep API running'));
app.listen(PORT, () => console.log('Listening on ' + PORT));
