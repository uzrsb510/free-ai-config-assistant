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
const PORT = Number(process.env.PORT) || 3000;

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const UPLOAD_DIR = path.join(DATA_DIR, "uploads");

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, "app.sqlite"));

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

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
messages TEXT NOT NULL DEFAULT '[]',
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

app.disable("x-powered-by");
app.set("trust proxy", 1);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));

app.use(express.static(path.join(__dirname, "public")));

const sessionSecret = process.env.SESSION_SECRET;

if (process.env.NODE_ENV === "production" && !sessionSecret) {
console.error("خطا: متغیر SESSION_SECRET در تنظیمات سرور تعریف نشده است.");
process.exit(1);
}

app.use(
session({
name: "dastyar.sid",
store: new SQLiteStore({
db: "sessions.sqlite",
dir: DATA_DIR
}),
secret: sessionSecret || "development-only-secret-change-me",
resave: false,
saveUninitialized: false,
cookie: {
httpOnly: true,
sameSite: "lax",
secure: process.env.NODE_ENV === "production",
maxAge: 30 * 24 * 60 * 60 * 1000
}
})
);

const storage = multer.diskStorage({
destination: (_req, _file, cb) => {
cb(null, UPLOAD_DIR);
},

filename: (_req, file, cb) => {
const extension = path.extname(file.originalname).slice(0, 20);
const filename = "${Date.now()}-${require("crypto").randomUUID()}${extension}";

cb(null, filename);

}
});

const upload = multer({
storage,
limits: {
fileSize: 12 * 1024 * 1024,
files: 1
}
});

function requireLogin(req, res, next) {
if (!req.session || !req.session.userId) {
return res.status(401).json({
error: "ابتدا وارد حساب خود شوید."
});
}

next();
}

function handleError(err, req, res, next) {
if (res.headersSent) {
return next(err);
}

console.error("Server error:", err.message);

if (err instanceof multer.MulterError) {
return res.status(400).json({
error:
err.code === "LIMIT_FILE_SIZE"
? "حجم فایل نباید بیشتر از ۱۲ مگابایت باشد."
: "بارگذاری فایل ناموفق بود."
});
}

res.status(500).json({
error: "خطای داخلی سرور رخ داده است."
});
}

app.get("/api/health", (_req, res) => {
res.json({
ok: true,
service: "dastyar-kanfig-saz"
});
});

app.get("/api/me", (req, res) => {
if (!req.session.userId) {
const count = db
.prepare("SELECT COUNT(*) AS count FROM users")
.get().count;

return res.json({
  user: null,
  needsSetup: count === 0
});

}

const user = db
.prepare("SELECT id, username FROM users WHERE id = ?")
.get(req.session.userId);

res.json({
user: user || null,
needsSetup: false
});
});

app.post("/api/register", async (req, res, next) => {
try {
const count = db
.prepare("SELECT COUNT(*) AS count FROM users")
.get().count;

if (count > 0) {
  return res.status(403).json({
    error: "حساب اولیه قبلاً ساخته شده است."
  });
}

const username = String(req.body.username || "").trim();
const password = String(req.body.password || "");
const confirmPassword = String(req.body.confirmPassword || "");

if (!/^[a-zA-Z0-9_.-]{3,30}$/.test(username)) {
  return res.status(400).json({
    error: "نام کاربری باید ۳ تا ۳۰ نویسه انگلیسی، عدد یا علامت مجاز باشد."
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

const passwordHash = await bcrypt.hash(password, 12);

const result = db
  .prepare(`
    INSERT INTO users (username, password_hash)
    VALUES (?, ?)
  `)
  .run(username, passwordHash);

req.session.regenerate((err) => {
  if (err) {
    return next(err);
  }

  req.session.userId = Number(result.lastInsertRowid);

  req.session.save((saveErr) => {
    if (saveErr) {
      return next(saveErr);
    }

    res.status(201).json({
      user: {
        id: Number(result.lastInsertRowid),
        username
      }
    });
  });
});

} catch (err) {
if (err.code === "SQLITE_CONSTRAINT_UNIQUE") {
return res.status(409).json({
error: "این نام کاربری قبلاً استفاده شده است."
});
}

next(err);

}
});

app.post("/api/login", async (req, res, next) => {
try {
const username = String(req.body.username || "").trim();
const password = String(req.body.password || "");

const user = db
  .prepare("SELECT * FROM users WHERE username = ?")
  .get(username);

if (
  !user ||
  !(await bcrypt.compare(password, user.password_hash))
) {
  return res.status(401).json({
    error: "نام کاربری یا رمز عبور نادرست است."
  });
}

req.session.regenerate((err) => {
  if (err) {
    return next(err);
  }

  req.session.userId = user.id;

  if (req.body.remember !== true) {
    req.session.cookie.expires = false;
  }

  req.session.save((saveErr) => {
    if (saveErr) {
      return next(saveErr);
    }

    res.json({
      user: {
        id: user.id,
        username: user.username
      }
    });
  });
});

} catch (err) {
next(err);
}
});

app.post("/api/logout", (req, res, next) => {
if (!req.session) {
res.clearCookie("dastyar.sid");
return res.json({ ok: true });
}

req.session.destroy((err) => {
if (err) {
return next(err);
}

res.clearCookie("dastyar.sid", {
  httpOnly: true,
  sameSite: "lax",
  secure: process.env.NODE_ENV === "production"
});

res.json({ ok: true });

});
});

app.post("/api/change-password", requireLogin, async (req, res, next) => {
try {
const oldPassword = String(req.body.oldPassword || "");
const newPassword = String(req.body.newPassword || "");

if (newPassword.length < 8) {
  return res.status(400).json({
    error: "رمز جدید باید حداقل ۸ نویسه داشته باشد."
  });
}

const user = db
  .prepare("SELECT * FROM users WHERE id = ?")
  .get(req.session.userId);

if (
  !user ||
  !(await bcrypt.compare(oldPassword, user.password_hash))
) {
  return res.status(400).json({
    error: "رمز فعلی نادرست است."
  });
}

const hash = await bcrypt.hash(newPassword, 12);

db.prepare(
  "UPDATE users SET password_hash = ? WHERE id = ?"
).run(hash, user.id);

res.json({ ok: true });

} catch (err) {
next(err);
}
});

app.get("/api/chats", requireLogin, (req, res) => {
const chats = db
.prepare("SELECT id, title FROM chats WHERE user_id = ? ORDER BY id DESC")
.all(req.session.userId);

res.json({ chats });
});

app.post("/api/chats", requireLogin, (req, res) => {
const title = String(req.body.title || "گفت‌وگوی جدید")
.trim()
.slice(0, 80) || "گفت‌وگوی جدید";

const result = db
.prepare("INSERT INTO chats (user_id, title, messages) VALUES (?, ?, '[]')")
.run(req.session.userId, title);

res.status(201).json({
id: Number(result.lastInsertRowid),
title
});
});

app.get("/api/chats/:id", requireLogin, (req, res) => {
const id = Number(req.params.id);

if (!Number.isSafeInteger(id) || id < 1) {
return res.status(400).json({
error: "شناسه گفت‌وگو نامعتبر است."
});
}

const chat = db
.prepare("SELECT id, title, messages FROM chats WHERE id = ? AND user_id = ?")
.get(id, req.session.userId);

if (!chat) {
return res.status(404).json({
error: "گفت‌وگو پیدا نشد."
});
}

let messages;

try {
messages = JSON.parse(chat.messages);
} catch {
messages = [];
}

res.json({
chat: {
...chat,
messages
}
});
});

app.put("/api/chats/:id", requireLogin, (req, res) => {
const id = Number(req.params.id);

if (!Number.isSafeInteger(id) || id < 1) {
return res.status(400).json({
error: "شناسه گفت‌وگو نامعتبر است."
});
}

if (
req.body.messages !== undefined &&
!Array.isArray(req.body.messages)
) {
return res.status(400).json({
error: "ساختار پیام‌ها نامعتبر است."
});
}

const messages = Array.isArray(req.body.messages)
? req.body.messages.slice(-100)
: [];

const title = String(req.body.title || "گفت‌وگوی جدید")
.trim()
.slice(0, 80) || "گفت‌وگوی جدید";

const result = db
.prepare("UPDATE chats SET title = ?, messages = ? WHERE id = ? AND user_id = ?")
.run(
title,
JSON.stringify(messages),
id,
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
const id = Number(req.params.id);

if (!Number.isSafeInteger(id) || id < 1) {
return res.status(400).json({
error: "شناسه گفت‌وگو نامعتبر است."
});
}

db.prepare("DELETE FROM chats WHERE id = ? AND user_id = ?").run(id, req.session.userId);

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

res.status(201).json({
  file: {
    name: req.file.originalname,
    url: "/uploads/" + encodeURIComponent(req.file.filename),
    mimeType: req.file.mimetype,
    size: req.file.size
  }
});

}
);

app.use("/uploads", requireLogin, express.static(UPLOAD_DIR));

app.post("/api/chat", requireLogin, async (req, res) => {
const message = String(req.body.message || "").trim();

if (!message) {
return res.status(400).json({
error: "پیام خود را بنویسید."
});
}

if (message.length > 20000) {
return res.status(400).json({
error: "پیام بیش از حد طولانی است."
});
}

if (!process.env.KIRA_API_KEY) {
return res.status(503).json({
error: "کلید Kira در تنظیمات سرور تعریف نشده است."
});
}

const baseUrl = (
process.env.KIRA_BASE_URL || "https://kiraai.vn/api/v1"
).replace(//+$/, "");

const model = process.env.KIRA_MODEL || "kira";

try {
const controller = new AbortController();
const timeout = setTimeout(() => controller.abort(), 60000);

let response;

try {
  response = await fetch(`${baseUrl}/chat/completions`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.KIRA_API_KEY}`,
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
    }),
    signal: controller.signal
  });
} finally {
  clearTimeout(timeout);
}

const data = await response.json().catch(() => ({}));

if (!response.ok) {
  console.error("Kira API status:", response.status);

  return res.status(502).json({
    error:
      data.error?.message ||
      "اتصال به سرویس Kira ناموفق بود. کلید API، آدرس سرویس و نام مدل را بررسی کنید."
  });
}

const answer = data.choices?.[0]?.message?.content;

if (typeof answer !== "string" || !answer.trim()) {
  return res.status(502).json({
    error: "پاسخ معتبری از هوش مصنوعی دریافت نشد."
  });
}

res.json({ answer });

} catch (err) {
console.error("AI request failed:", err.message);

res.status(502).json({
  error:
    err.name === "AbortError"
      ? "زمان انتظار برای پاسخ هوش مصنوعی تمام شد."
      : "ارتباط با سرویس هوش مصنوعی برقرار نشد."
});

}
});

app.use((req, res, next) => {
if (req.path.startsWith("/api/")) {
return res.status(404).json({
error: "مسیر API پیدا نشد."
});
}

next();
});

app.get("*", (_req, res, next) => {
const indexPath = path.join(__dirname, "public", "index.html");

if (!fs.existsSync(indexPath)) {
return res.status(404).send(
"فایل public/index.html پیدا نشد. پوشه public را بررسی کنید."
);
}

res.sendFile(indexPath, (err) => {
if (err) next(err);
});
});

app.use(handleError);

const server = app.listen(PORT, "0.0.0.0", () => {
console.log("دستیار کانفیگ‌ساز روی پورت ${PORT} اجرا شد.");
});

function shutdown() {
server.close(() => {
try {
db.close();
} finally {
process.exit(0);
}
});

setTimeout(() => process.exit(1), 10000).unref();
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
