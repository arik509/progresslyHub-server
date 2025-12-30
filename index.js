const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const fs = require("fs");

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const admin = require("firebase-admin");

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

// -------------------- Firebase Admin Init --------------------
let serviceAccount;

if (process.env.FIREBASE_SERVICE_ACCOUNT_BASE64) {
  console.log("Loading Firebase credentials from environment variable");
  const decoded = Buffer.from(
    process.env.FIREBASE_SERVICE_ACCOUNT_BASE64,
    "base64"
  ).toString("utf8");
  serviceAccount = JSON.parse(decoded);
} else {
  console.log("Loading Firebase credentials from file");
  const serviceAccountPath =
    process.env.FIREBASE_SERVICE_ACCOUNT_PATH || "./serviceAccountKey.json";
  serviceAccount = JSON.parse(fs.readFileSync(serviceAccountPath, "utf8"));
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// -------------------- Middleware --------------------
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "http://localhost:5000",
      "https://progressly-hub-client.vercel.app"
    ],
    credentials: true,
  })
);

app.use(express.json());

// -------------------- MongoDB Connection (Serverless Optimized) --------------------
let cachedClient = null;
let cachedDb = null;

async function connectToDatabase() {
  if (cachedClient && cachedDb) {
    return {
      client: cachedClient,
      db: cachedDb,
      offices: cachedDb.collection("offices"),
      memberships: cachedDb.collection("memberships"),
      users: cachedDb.collection("users"),
      projects: cachedDb.collection("projects"),
      tasks: cachedDb.collection("tasks"),
    };
  }

  const uri = process.env.MONGO_URI;
  if (!uri) throw new Error("MONGO_URI is missing in environment variables");

  const client = new MongoClient(uri, {
    serverApi: {
      version: ServerApiVersion.v1,
      strict: true,
      deprecationErrors: true,
    },
  });

  await client.connect();
  console.log("✅ Connected to MongoDB!");

  const db = client.db(process.env.MONGO_DB_NAME || "progresslyhub");

  cachedClient = client;
  cachedDb = db;

  return {
    client,
    db,
    offices: db.collection("offices"),
    memberships: db.collection("memberships"),
    users: db.collection("users"),
    projects: db.collection("projects"),
    tasks: db.collection("tasks"),
  };
}

function now() {
  return new Date();
}

// -------------------- Auth Middleware --------------------
async function verifyFirebaseToken(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;

    if (!token) return res.status(401).json({ message: "Missing token" });

    const decoded = await admin.auth().verifyIdToken(token);
    req.firebase = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid/expired token" });
  }
}

function requireRole(allowedRoles = []) {
  return (req, res, next) => {
    const role = req.firebase?.role || "EMPLOYEE";
    if (!allowedRoles.includes(role)) {
      return res.status(403).json({ message: "Forbidden (role)" });
    }
    next();
  };
}

async function mergeCustomClaims(uid, claimsToAdd) {
  const user = await admin.auth().getUser(uid);
  const current = user.customClaims || {};
  const merged = { ...current, ...claimsToAdd };
  await admin.auth().setCustomUserClaims(uid, merged);
  return merged;
}

// -------------------- Routes --------------------
app.get("/", (req, res) => {
  res.send("ProgresslyHub API is running!");
});

app.get("/api/health", (req, res) => {
  res.json({ ok: true });
});

app.get("/api/me", verifyFirebaseToken, (req, res) => {
  res.json({
    uid: req.firebase.uid,
    email: req.firebase.email,
    claims: req.firebase,
  });
});

app.get("/api/db-test", async (req, res) => {
  try {
    const { db } = await connectToDatabase();
    const collections = await db.listCollections().toArray();
    res.json({ ok: true, collections: collections.map((c) => c.name) });
  } catch (e) {
    res.status(500).json({ ok: false, message: e.message });
  }
});

// -------------------- Office Routes --------------------
app.post("/api/offices", verifyFirebaseToken, async (req, res) => {
  try {
    const { offices, memberships, users } = await connectToDatabase();
    const { name } = req.body;

    if (!name || name.trim().length < 2) {
      return res.status(400).json({ message: "Office name is required" });
    }

    const uid = req.firebase.uid;
    const email = req.firebase.email || null;

    await users.updateOne(
      { uid },
      {
        $set: { uid, email, updatedAt: now() },
        $setOnInsert: { createdAt: now() },
      },
      { upsert: true }
    );

    const officeDoc = {
      name: name.trim(),
      createdByUid: uid,
      createdAt: now(),
      updatedAt: now(),
    };

    const officeResult = await offices.insertOne(officeDoc);
    const officeId = officeResult.insertedId;

    await memberships.insertOne({
      officeId,
      userUid: uid,
      userEmail: email,
      role: "CEO",
      createdAt: now(),
      updatedAt: now(),
    });

    const claims = await mergeCustomClaims(uid, {
      role: "CEO",
      officeId: officeId.toString(),
    });

    res.status(201).json({
      message: "Office created",
      office: { ...officeDoc, _id: officeId },
      claims,
    });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

app.get("/api/offices/my", verifyFirebaseToken, async (req, res) => {
  try {
    const { offices, memberships } = await connectToDatabase();
    const uid = req.firebase.uid;

    const myMemberships = await memberships.find({ userUid: uid }).toArray();
    const officeIds = myMemberships.map((m) => m.officeId);

    const myOffices = await offices
      .find({ _id: { $in: officeIds } })
      .sort({ createdAt: -1 })
      .toArray();

    res.json({ memberships: myMemberships, offices: myOffices });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

// -------------------- Member Routes --------------------
app.post(
  "/api/offices/:officeId/members",
  verifyFirebaseToken,
  requireRole(["CEO", "ADMIN", "MANAGER"]),
  async (req, res) => {
    try {
      const { memberships, users } = await connectToDatabase();
      const { officeId } = req.params;
      const { email, role } = req.body;

      const allowedRoles = ["ADMIN", "MANAGER", "EMPLOYEE"];
      if (!email) return res.status(400).json({ message: "Email is required" });
      if (!role || !allowedRoles.includes(role)) {
        return res.status(400).json({ message: "Invalid role" });
      }

      const officeObjectId = new ObjectId(officeId);
      const userRecord = await admin.auth().getUserByEmail(email);

      await memberships.updateOne(
        { officeId: officeObjectId, userUid: userRecord.uid },
        {
          $set: {
            officeId: officeObjectId,
            userUid: userRecord.uid,
            userEmail: userRecord.email || email,
            role,
            updatedAt: now(),
          },
          $setOnInsert: { createdAt: now() },
        },
        { upsert: true }
      );

      await users.updateOne(
        { uid: userRecord.uid },
        {
          $set: {
            uid: userRecord.uid,
            email: userRecord.email || email,
            updatedAt: now(),
          },
          $setOnInsert: { createdAt: now() },
        },
        { upsert: true }
      );

      const claims = await mergeCustomClaims(userRecord.uid, {
        role,
        officeId: officeId.toString(),
      });

      res.json({
        message: "Member added/updated",
        uid: userRecord.uid,
        claims,
      });
    } catch (e) {
      res.status(500).json({ message: e.message });
    }
  }
);

app.get(
  "/api/offices/:officeId/members",
  verifyFirebaseToken,
  requireRole(["CEO", "ADMIN", "MANAGER"]),
  async (req, res) => {
    try {
      const { memberships } = await connectToDatabase();
      const { officeId } = req.params;

      const officeObjectId = new ObjectId(officeId);

      const members = await memberships
        .find({ officeId: officeObjectId })
        .sort({ createdAt: -1 })
        .toArray();

      res.json({ members });
    } catch (e) {
      res.status(500).json({ message: e.message });
    }
  }
);

// -------------------- Project Routes --------------------
app.post(
  "/api/offices/:officeId/projects",
  verifyFirebaseToken,
  requireRole(["CEO", "ADMIN", "MANAGER"]),
  async (req, res) => {
    try {
      const { projects } = await connectToDatabase();
      const { officeId } = req.params;
      const { name, description, status } = req.body;

      if (!name)
        return res.status(400).json({ message: "Project name is required" });

      const officeObjectId = new ObjectId(officeId);

      const doc = {
        officeId: officeObjectId,
        name: name.trim(),
        description: description || "",
        status: status || "PLANNING",
        createdByUid: req.firebase.uid,
        createdAt: now(),
        updatedAt: now(),
      };

      const result = await projects.insertOne(doc);
      res.status(201).json({
        message: "Project created",
        project: { ...doc, _id: result.insertedId },
      });
    } catch (e) {
      res.status(500).json({ message: e.message });
    }
  }
);

app.get(
  "/api/offices/:officeId/projects",
  verifyFirebaseToken,
  async (req, res) => {
    try {
      const { projects } = await connectToDatabase();
      const { officeId } = req.params;
      const officeObjectId = new ObjectId(officeId);

      const list = await projects
        .find({ officeId: officeObjectId })
        .sort({ createdAt: -1 })
        .toArray();
      res.json({ projects: list });
    } catch (e) {
      res.status(500).json({ message: e.message });
    }
  }
);

app.put(
  "/api/offices/:officeId/projects/:projectId",
  verifyFirebaseToken,
  requireRole(["CEO", "ADMIN", "MANAGER"]),
  async (req, res) => {
    try {
      const { projects } = await connectToDatabase();
      const { projectId } = req.params;
      const { name, description, status } = req.body;

      const update = { updatedAt: now() };
      if (name) update.name = name.trim();
      if (description !== undefined) update.description = description;
      if (status) update.status = status;

      const result = await projects.updateOne(
        { _id: new ObjectId(projectId) },
        { $set: update }
      );

      if (result.matchedCount === 0) {
        return res.status(404).json({ message: "Project not found" });
      }

      res.json({ message: "Project updated" });
    } catch (e) {
      res.status(500).json({ message: e.message });
    }
  }
);

app.delete(
  "/api/offices/:officeId/projects/:projectId",
  verifyFirebaseToken,
  requireRole(["CEO", "ADMIN", "MANAGER"]),
  async (req, res) => {
    try {
      const { projects } = await connectToDatabase();
      const { projectId } = req.params;

      const result = await projects.deleteOne({ _id: new ObjectId(projectId) });

      if (result.deletedCount === 0) {
        return res.status(404).json({ message: "Project not found" });
      }

      res.json({ message: "Project deleted" });
    } catch (e) {
      res.status(500).json({ message: e.message });
    }
  }
);

// -------------------- Task Routes --------------------
app.post(
  "/api/offices/:officeId/tasks",
  verifyFirebaseToken,
  requireRole(["CEO", "ADMIN", "MANAGER"]),
  async (req, res) => {
    try {
      const { tasks } = await connectToDatabase();
      const { officeId } = req.params;
      const { title, description, status, priority, assignedTo } = req.body;

      if (!title)
        return res.status(400).json({ message: "Task title is required" });

      const officeObjectId = new ObjectId(officeId);

      const doc = {
        officeId: officeObjectId,
        title: title.trim(),
        description: description || "",
        status: status || "TODO",
        priority: priority || "MEDIUM",
        assignedTo: assignedTo || null,
        createdByUid: req.firebase.uid,
        createdAt: now(),
        updatedAt: now(),
      };

      const result = await tasks.insertOne(doc);
      res.status(201).json({
        message: "Task created",
        task: { ...doc, _id: result.insertedId },
      });
    } catch (e) {
      res.status(500).json({ message: e.message });
    }
  }
);

app.get(
  "/api/offices/:officeId/tasks",
  verifyFirebaseToken,
  async (req, res) => {
    try {
      const { tasks } = await connectToDatabase();
      const { officeId } = req.params;
      const officeObjectId = new ObjectId(officeId);

      const list = await tasks
        .find({ officeId: officeObjectId })
        .sort({ createdAt: -1 })
        .toArray();
      res.json({ tasks: list });
    } catch (e) {
      res.status(500).json({ message: e.message });
    }
  }
);

app.put(
  "/api/offices/:officeId/tasks/:taskId",
  verifyFirebaseToken,
  async (req, res) => {
    try {
      const { tasks } = await connectToDatabase();
      const { taskId } = req.params;
      const { title, description, status, priority, assignedTo } = req.body;

      const task = await tasks.findOne({ _id: new ObjectId(taskId) });

      if (!task) {
        return res.status(404).json({ message: "Task not found" });
      }

      const userRole = req.firebase?.role || "EMPLOYEE";
      const userEmail = req.firebase?.email;
      const userUid = req.firebase?.uid;

      const isManager = ["CEO", "ADMIN", "MANAGER"].includes(userRole);
      const isAssignedToUser =
        task.assignedTo === userEmail || task.assignedTo === userUid;

      if (!isManager && !isAssignedToUser) {
        return res.status(403).json({
          message: "You can only update tasks assigned to you",
        });
      }

      const update = { updatedAt: now() };

      if (!isManager) {
        if (status) update.status = status;
      } else {
        if (title) update.title = title.trim();
        if (description !== undefined) update.description = description;
        if (status) update.status = status;
        if (priority) update.priority = priority;
        if (assignedTo !== undefined) update.assignedTo = assignedTo;
      }

      const result = await tasks.updateOne(
        { _id: new ObjectId(taskId) },
        { $set: update }
      );

      if (result.matchedCount === 0) {
        return res.status(404).json({ message: "Task not found" });
      }

      res.json({
        message: "Task updated",
        allowedFields: isManager ? "all" : "status only",
      });
    } catch (e) {
      res.status(500).json({ message: e.message });
    }
  }
);

app.delete(
  "/api/offices/:officeId/tasks/:taskId",
  verifyFirebaseToken,
  requireRole(["CEO", "ADMIN", "MANAGER"]),
  async (req, res) => {
    try {
      const { tasks } = await connectToDatabase();
      const { taskId } = req.params;

      const result = await tasks.deleteOne({ _id: new ObjectId(taskId) });

      if (result.deletedCount === 0) {
        return res.status(404).json({ message: "Task not found" });
      }

      res.json({ message: "Task deleted" });
    } catch (e) {
      res.status(500).json({ message: e.message });
    }
  }
);

// -------------------- Start Server --------------------
if (process.env.NODE_ENV !== "production") {
  app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
  });
}

module.exports = app;