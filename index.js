const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const fs = require("fs");

const { MongoClient, ServerApiVersion } = require("mongodb");
const admin = require("firebase-admin");

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

// Middlewares
app.use(cors());
app.use(express.json());

// -------------------- Firebase Admin Init --------------------
const serviceAccountPath = process.env.FIREBASE_SERVICE_ACCOUNT_PATH || "./serviceAccountKey.json";
const serviceAccount = JSON.parse(fs.readFileSync(serviceAccountPath, "utf8"));

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// verify token middleware (Authorization: Bearer <token>)
async function verifyFirebaseToken(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;

    if (!token) return res.status(401).json({ message: "Missing token" });

    const decoded = await admin.auth().verifyIdToken(token); // official way [web:409]
    req.firebase = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid/expired token" });
  }
}

// -------------------- MongoDB Connection --------------------
let mongoClient;
let db;

async function connectMongo() {
  if (db) return db;

  const uri = process.env.MONGO_URI;
  if (!uri) throw new Error("MONGO_URI is missing in .env");

  mongoClient = new MongoClient(uri, {
    serverApi: {
      version: ServerApiVersion.v1,
      strict: true,
      deprecationErrors: true,
    },
  });

  await mongoClient.connect();

  // Ping to confirm a successful connection [web:444]
  await mongoClient.db("admin").command({ ping: 1 });
  console.log("Pinged your deployment. You successfully connected to MongoDB!");

  db = mongoClient.db(process.env.MONGO_DB_NAME || "progresslyhub");
  return db;
}

function getDB() {
  if (!db) throw new Error("Database not connected yet.");
  return db;
}

// -------------------- Routes --------------------

// Express hello route (like docs) [web:453]
app.get("/", (req, res) => {
  res.send("ProgresslyHub API is running!");
});

app.get("/api/health", (req, res) => {
  res.json({ ok: true });
});

// Protected test route
app.get("/api/me", verifyFirebaseToken, (req, res) => {
  res.json({
    uid: req.firebase.uid,
    email: req.firebase.email,
    claims: req.firebase,
  });
});

// Example DB test route (optional)
app.get("/api/db-test", async (req, res) => {
  try {
    const database = getDB();
    const collections = await database.listCollections().toArray();
    res.json({ ok: true, collections: collections.map((c) => c.name) });
  } catch (e) {
    res.status(500).json({ ok: false, message: e.message });
  }
});

// -------------------- Start Server --------------------
async function start() {
  await connectMongo();
  app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
  });
}

start().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
