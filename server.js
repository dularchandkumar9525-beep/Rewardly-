++++++require("dotenv").config();
const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");


const { initializeApp, cert } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");


initializeApp();

++const jwt = require("jsonwebtoken");
const Razorpay = require("razorpay");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || "rewardly-super-secret-key-2026";
const DATA_FILE = path.join(__dirname, "data.json");

// Middleware Setup
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Initialize Razorpay Instance
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID || "YOUR_RAZORPAY_KEY_ID",
  key_secret: process.env.RAZORPAY_KEY_SECRET || "YOUR_RAZORPAY_KEY_SECRET",
});

// Database Initialization
const defaultData = {
  users: [],
  tasks: [
    { id: 1, title: "Daily Quiz", description: "Complete the quiz task.", reward: 300, active: true },
    { id: 2, title: "Quick Survey", description: "Complete an eligible survey.", reward: 500, active: true },
    { id: 3, title: "Partner Offer", description: "Complete a verified offer.", reward: 1000, active: true }
  ],
  completions: [],
  transactions: [],
  withdrawals: [],
  payments: []
};

if (!fs.existsSync(DATA_FILE)) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(defaultData, null, 2));
}

let db = JSON.parse(fs.readFileSync(DATA_FILE));

// Helpers
const saveData = () => fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
const generateReferralCode = () => "RW" + Math.random().toString(36).slice(2, 8).toUpperCase();
const getSafeUser = (u) => ({ id: u.id, name: u.name, email: u.email, points: u.points, referral_code: u.referral_code, role: u.role });
const generateToken = (u) => jwt.sign({ id: u.id, role: u.role }, SECRET, { expiresIn: "7d" });
const getUserById = (id) => db.users.find((u) => u.id === Number(id));

const addPoints = (userId, type, points, note) => {
  const user = getUserById(userId);
  if (user) {
    user.points += points;
    db.transactions.push({ id: Date.now(), user_id: userId, type, points, note, at: new Date().toISOString() });
    saveData();
  }
};

// Seed Admin User
if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
  const adminEmail = process.env.ADMIN_EMAIL.toLowerCase();
  if (!db.users.some((u) => u.email === adminEmail)) {
    db.users.push({
      id: Date.now(),
      name: "Admin",
      email: adminEmail,
      password_hash: bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12),
      points: 0,
      referral_code: generateReferralCode(),
      role: "admin"
    });
    saveData();
  }
}

// Auth Middlewares
const authMiddleware = (req, res, next) => {
  try {
    const token = (req.headers.authorization || "").replace(/^Bearer /, "");
    req.me = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Unauthorized access" });
  }
};

const adminMiddleware = (req, res, next) => {
  authMiddleware(req, res, () => {
    if (getUserById(req.me.id)?.role === "admin") return next();
    res.status(403).json({ error: "Admin access required" });
  });
};

// --- AUTH ROUTES ---

app.post("/api/auth/firebase", async (req, res) => {
  try {
    const { idToken } = req.body;

    if (!idToken) {
      return res.status(400).json({ ok: false, error: "Firebase ID token is required" });
    }

    const decoded = await getAuth().verifyIdToken(idToken);

    const uid = decoded.uid;
    const email = (decoded.email || "").toLowerCase();
    const name = decoded.name || decoded.email?.split("@")[0] || decoded.phone_number || "Rewardly User";

    let user = db.users.find(u => u.firebase_uid === uid);

    if (!user && email) {
      user = db.users.find(u => u.email === email);
    }

    if (!user) {
      user = {
        id: Date.now(),
        firebase_uid: uid,
        name,
        email,
        password_hash: "",
        points: 0,
        referral_code: generateReferralCode(),
        role: "user"
      };

      db.users.push(user);
      saveData();
    } else {
      user.firebase_uid = uid;
      if (!user.name && name) user.name = name;
      saveData();
    }

    const token = generateToken(user);

    return res.json({
      ok: true,
      token,
      user: getSafeUser(user)
    });

  } catch (error) {
    console.error("Firebase auth error:", error);
    return res.status(401).json({
      ok: false,
      error: "Firebase authentication failed"
    });
  }
});

app.post("/api/register", async (req, res) => {
  const { name, email, password, referralCode } = req.body || {};
  if (!name || !email || !password || password.length < 8) {
    return res.status(400).json({ error: "Provide name, email, and password (min 8 chars)." });
  }

  const cleanEmail = email.trim().toLowerCase();
  if (db.users.some((u) => u.email === cleanEmail)) {
    return res.status(409).json({ error: "Email already registered" });
  }

  const referrer = db.users.find((u) => u.referral_code === (referralCode || "").trim().toUpperCase());
  const newUser = {
    id: Date.now(),
    name: name.trim(),
    email: cleanEmail,
    password_hash: await bcrypt.hash(password, 12),
    points: 0,
    referral_code: generateReferralCode(),
    role: "user"
  };

  db.users.push(newUser);
  if (referrer) {
    addPoints(referrer.id, "referral", 500, "Referral signup bonus");
  }
  saveData();

  res.json({ token: generateToken(newUser), user: getSafeUser(newUser) });
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body || {};
  const cleanEmail = String(email || "").trim().toLowerCase();
  const user = db.users.find((x) => x.email === cleanEmail);

  if (!user || !(await bcrypt.compare(String(password || ""), user.password_hash))) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  res.json({ token: generateToken(user), user: getSafeUser(user) });
});

app.get("/api/me", authMiddleware, (req, res) => {
  res.json({ user: getSafeUser(getUserById(req.me.id)) });
});

// --- TASK & BONUS ROUTES ---
app.get("/api/tasks", authMiddleware, (req, res) => {
  res.json({ tasks: db.tasks.filter((t) => t.active) });
});

app.post("/api/tasks/:id", authMiddleware, (req, res) => {
  const task = db.tasks.find((x) => x.id === Number(req.params.id) && x.active);
  if (!task) return res.status(404).json({ error: "Task not found" });

  if (db.completions.some((x) => x.user_id === req.me.id && x.task_id === task.id)) {
    return res.status(409).json({ error: "Task already completed" });
  }

  db.completions.push({ user_id: req.me.id, task_id: task.id, at: new Date().toISOString() });
  addPoints(req.me.id, "task", task.reward, task.title);
  res.json({ user: getSafeUser(getUserById(req.me.id)) });
});

app.post("/api/bonus", authMiddleware, (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  const alreadyClaimed = db.transactions.some(
    (x) => x.user_id === req.me.id && x.type === "bonus" && x.at.slice(0, 10) === today
  );

  if (alreadyClaimed) return res.status(409).json({ error: "Daily bonus already claimed today" });

  addPoints(req.me.id, "bonus", 200, "Daily bonus");
  res.json({ user: getSafeUser(getUserById(req.me.id)) });
});

// --- WALLET & WITHDRAWAL ROUTES ---
app.get("/api/wallet", authMiddleware, (req, res) => {
  const user = getUserById(req.me.id);
  const txs = db.transactions.filter((x) => x.user_id === req.me.id);
  const withdrawals = db.withdrawals.filter((x) => x.user_id === req.me.id);
  res.json({ user: getSafeUser(user), transactions: txs, withdrawals });
});

app.post("/api/withdraw", authMiddleware, (req, res) => {
  const { points, method, destination } = req.body || {};
  const user = getUserById(req.me.id);
  const p = Number(points);

  if (!Number.isInteger(p) || p < 10000) return res.status(400).json({ error: "Minimum withdrawal is 10,000 points" });
  if (!["UPI", "BANK"].includes(method)) return res.status(400).json({ error: "Invalid payment method" });
  if (!destination) return res.status(400).json({ error: "Enter valid payout details" });
  if (user.points < p) return res.status(400).json({ error: "Insufficient points balance" });

  addPoints(req.me.id, "withdrawal_hold", -p, "Withdrawal request");
  db.withdrawals.push({
    id: Date.now(),
    user_id: req.me.id,
    points: p,
    method,
    destination,
    status: "pending",
    at: new Date().toISOString()
  });
  saveData();

  res.json({ user: getSafeUser(user) });
});

// --- REAL PAYMENT METHOD (RAZORPAY INTEGRATION) ---

// 1. Create Payment Order
app.post("/api/payment/create-order", authMiddleware, async (req, res) => {
  const { amount } = req.body; // Amount in INR
  if (!amount || amount < 10) return res.status(400).json({ error: "Minimum deposit is ₹10" });

  const options = {
    amount: amount * 100, // Convert to Paisa
    currency: "INR",
    receipt: `rcpt_${Date.now()}`
  };

  try {
    const order = await razorpay.orders.create(options);
    res.json({ order, key_id: process.env.RAZORPAY_KEY_ID });
  } catch (err) {
    res.status(500).json({ error: "Failed to create payment order" });
  }
});

// 2. Verify Payment Signature
app.post("/api/payment/verify", authMiddleware, (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature, amount } = req.body;

  const body = razorpay_order_id + "|" + razorpay_payment_id;
  const expectedSignature = crypto
    .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET || "YOUR_RAZORPAY_KEY_SECRET")
    .update(body.toString())
    .digest("hex");

  if (expectedSignature === razorpay_signature) {
    // Payment Successful -> Convert ₹1 = 100 Points
    const addedPoints = amount * 100;
    addPoints(req.me.id, "deposit", addedPoints, `Added via Razorpay (${razorpay_payment_id})`);

    db.payments.push({
      order_id: razorpay_order_id,
      payment_id: razorpay_payment_id,
      user_id: req.me.id,
      amount,
      at: new Date().toISOString()
    });
    saveData();

    return res.json({ status: "success", points: addedPoints, user: getSafeUser(getUserById(req.me.id)) });
  } else {
    return res.status(400).json({ error: "Invalid payment signature" });
  }
});

// --- ADMIN ROUTES ---
app.get("/api/admin", adminMiddleware, (req, res) => {
  const users = db.users.filter((u) => u.role === "user").map(getSafeUser);
  const withdrawals = db.withdrawals.slice().reverse().map((w) => ({
    ...w,
    name: getUserById(w.user_id)?.name,
    email: getUserById(w.user_id)?.email
  }));
  res.json({ users, withdrawals });
});

app.post("/api/admin/withdraw/:id", adminMiddleware, (req, res) => {
  const w = db.withdrawals.find((x) => x.id === Number(req.params.id));
  if (!w || w.status !== "pending") return res.status(409).json({ error: "Invalid or non-pending withdrawal" });

  const { status } = req.body;
  if (!["approved", "rejected"].includes(status)) return res.status(400).json({ error: "Invalid status status" });

  w.status = status;
  if (status === "rejected") {
    addPoints(w.user_id, "refund", w.points, "Withdrawal rejected");
  } else {
    saveData();
  }

  res.json({ ok: true });
});

// Default Fallback Route
app.use((req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`🚀 Rewardly server running on http://localhost:${PORT}`);
});
