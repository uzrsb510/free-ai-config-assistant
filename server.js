require("dotenv").config();

const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const helmet = require("helmet");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const UPLOAD_DIR = path.join(DATA_DIR, "uploads");

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, "app.sqlite"));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    messages TEXT NOT NULL DEFAULT '[]'
  );
`);

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public")));

app.use(session({
  store: new SQLiteStore({
    db: "sessions.sqlite",
    dir: DATA_DIR
  }),
  secret: process.env.SESSION_SECRET || "change-this-secret-before-deploy",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 30 * 24 * 60 * 60 * 1000
  }
}));

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (_req, file, cb) => {
    cb(null, Date.now() + "-" + path.basename(file.originalname));
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 12 * 1024 * 1024 }
});

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: "ابتدا وارد حساب خود شوید."
    });
  }

  next();
}

app.get("/api/me", (req, res) => {
  if (!req.session.userId) {
    const count = db.prepare(
      "SELECT COUNT(*) AS count FROM users"
    ).get().count;

    return res.json({
      user: null,
      needsSetup: count === 0
    });
  }

  const user = db.prepare(
    "SELECT id, username FROM users WHERE id = ?"
  ).get(req.session.userId);

  res.json({ user: user || null });
});

app.post("/api/register", async (req, res) => {
  const count = db.prepare(
    "SELECT COUNT(*) AS count FROM users"
  ).get().count;

  if (count > 0) {
    return res.status(403).json({
      error: "حساب اولیه قبلاً ساخته شده است."
    });
  }

  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  const confirmPassword = String(req.body.confirmPassword || "");

  if (username.length < 3 || username.length > 30) {
    return res.status(400).json({
      error: "نام کاربری باید بین ۳ تا ۳۰ نویسه باشد."
    });
  }

  if (password.length < 8) {
    return res.status(400).json({
      error: "رمز عبور باید حداقل ۸ نویسه داشته باشد."
    });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({
      error: "رمز عبور و تکرار آن یکسان نیستند."
    });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);

    const result = db.prepare(`
      INSERT INTO users (username, password_hash)
      VALUES (?, ?)
    `).run(username, passwordHash);

    req.session.userId = result.lastInsertRowid;

    res.json({
      user: {
        id: result.lastInsertRowid,
        username
      }
    });
  } catch {
    res.status(400).json({
      error: "ساخت حساب ناموفق بود."
    });
  }
});

app.post("/api/login", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  const user = db.prepare(
    "SELECT * FROM users WHERE username = ?"
  ).get(username);

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({
      error: "نام کاربری یا رمز عبور نادرست است."
    });
  }

  req.session.regenerate((err) => {
    if (err) {
      return res.status(500).json({
        error: "ورود ناموفق بود."
      });
    }

    req.session.userId = user.id;

    if (req.body.remember !== true) {
      req.session.cookie.maxAge = null;
    }

    res.json({
      user: {
        id: user.id,
        username: user.username
      }
    });
  });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ ok: true });
  });
});

app.post("/api/change-password", requireLogin, async (req, res) => {
  const oldPassword = String(req.body.oldPassword || "");
  const newPassword = String(req.body.newPassword || "");

  if (newPassword.length < 8) {
    return res.status(400).json({
      error: "رمز جدید باید حداقل ۸ نویسه باشد."
    });
  }

  const user = db.prepare(
    "SELECT * FROM users WHERE id = ?"
  ).get(req.session.userId);

  if (!user || !(await bcrypt.compare(oldPassword, user.password_hash))) {
    return res.status(400).json({
      error: "رمز فعلی نادرست است."
    });
  }

  const hash = await bcrypt.hash(newPassword, 12);

  db.prepare(
    "UPDATE users SET password_hash = ? WHERE id = ?"
  ).run(hash, user.id);

  res.json({ ok: true });
});

app.get("/api/chats", requireLogin, (req, res) => {
  const chats = db.prepare(`
    SELECT id, title
    FROM chats
    WHERE user_id = ?
    ORDER BY id DESC
  `).all(req.session.userId);

  res.json({ chats });
});

app.post("/api/chats", requireLogin, (req, res) => {
  const title = String(
    req.body.title || "گفت‌وگوی جدید"
  ).slice(0, 80);

  const result = db.prepare(`
    INSERT INTO chats (user_id, title, messages)
    VALUES (?, ?, '[]')
  `).run(req.session.userId, title);

  res.json({
    id: result.lastInsertRowid,
    title
  });
});

app.get("/api/chats/:id", requireLogin, (req, res) => {
  const chat = db.prepare(`
    SELECT id, title, messages
    FROM chats
    WHERE id = ? AND user_id = ?
  `).get(Number(req.params.id), req.session.userId);

  if (!chat) {
    return res.status(404).json({
      error: "گفت‌وگو پیدا نشد."
    });
  }

  res.json({
    chat: {
      ...chat,
      messages: JSON.parse(chat.messages)
    }
  });
});

app.put("/api/chats/:id", requireLogin, (req, res) => {
  const messages = Array.isArray(req.body.messages)
    ? req.body.messages.slice(-100)
    : [];

  const title = String(
    req.body.title || "گفت‌وگوی جدید"
  ).slice(0, 80);

  const result = db.prepare(`
    UPDATE chats
    SET title = ?, messages = ?
    WHERE id = ? AND user_id = ?
  `).run(
    title,
    JSON.stringify(messages),
    Number(req.params.id),
    req.session.userId
  );

  if (!result.changes) {
    return res.status(404).json({
      error: "گفت‌وگو پیدا نشد."
    });
  }

  res.json({ ok: true });
});

app.delete("/api/chats/:id", requireLogin, (req, res) => {
  db.prepare(`
    DELETE FROM chats
    WHERE id = ? AND user_id = ?
  `).run(Number(req.params.id), req.session.userId);

  res.json({ ok: true });
});

app.post(
  "/api/upload",
  requireLogin,
  upload.single("file"),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        error: "فایلی انتخاب نشده است."
      });
    }

    res.json({
      file: {
        name: req.file.originalname,
        url: "/uploads/" + encodeURIComponent(req.file.filename),
        mimeType: req.file.mimetype
      }
    });
  }
);

app.use("/uploads", express.static(UPLOAD_DIR));

app.post("/api/chat", requireLogin, async (req, res) => {
  const message = String(req.body.message || "").trim();

  if (!message) {
    return res.status(400).json({
      error: "پیام خود را بنویسید."
    });
  }

  if (!process.env.KIRA_API_KEY) {
    return res.status(503).json({
      error: "کلید Kira هنوز در تنظیمات Render وارد نشده است."
    });
  }

  const baseUrl = (
    process.env.KIRA_BASE_URL ||
    "https://kiraai.vn/api/v1"
  ).replace(/\/+$/, "");

  const model = process.env.KIRA_MODEL || "kira";

  try {
    const response = await fetch(
      baseUrl + "/chat/completions",
      {
        method: "POST",
        headers: {
          Authorization: "Bearer " + process.env.KIRA_API_KEY,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          model,
          messages: [
            {
              role: "system",
              content: "تو دستیار کانفیگ‌ساز رایگان هستی. فارسی و روشن پاسخ بده."
            },
            {
              role: "user",
              content: message
            }
          ]
        })
      }
    );

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      return res.status(502).json({
        error: data.error?.message ||
          "اتصال به Kira ناموفق بود. نام مدل و آدرس API را بررسی کنید."
      });
    }

    const answer = data.choices?.[0]?.message?.content;

    if (!answer) {
      return res.status(502).json({
        error: "پاسخ معتبری از هوش مصنوعی دریافت نشد."
      });
    }

    res.json({ answer });
  } catch {
    res.status(502).json({
      error: "ارتباط با سرویس هوش مصنوعی برقرار نشد."
    });
  }
});

app.get("*", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log("دستیار کانفیگ‌ساز روی پورت " + PORT + " اجرا شد.");
});
