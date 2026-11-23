const express = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Simple JSON Database ----------
const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "db.json");

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function loadDB() {
  try {
    if (fs.existsSync(DB_FILE)) {
      return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
    }
  } catch (e) {
    console.error("DB load error:", e.message);
  }
  return {
    users: [],
    students: [],
    classes: [],
    attendance: [],
    nextId: { user: 1, student: 1, class: 1, attendance: 1 }
  };
}

function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

let db = loadDB();

// Seed initial data if empty
if (db.users.length === 0) {
  const hash = bcrypt.hashSync("ChangeMe123!", 10);
  db.users.push({
    id: db.nextId.user++,
    username: "admin",
    password_hash: hash,
    full_name: "Administrator",
    role: "admin",
    created_at: new Date().toISOString()
  });
  console.log("Created admin / ChangeMe123!");
}

if (db.students.length === 0) {
  const samples = [
    ["John Kamau", "DIT-001", "Diploma in IT"],
    ["Mary Wanjiku", "DIT-002", "Diploma in IT"],
    ["Brian Otieno", "DIT-003", "Diploma in IT"],
    ["Lucy Achieng", "DIT-004", "Diploma in IT"],
    ["Kevin Mwangi", "DIT-005", "Diploma in IT"],
    ["Faith Njeri", "DIT-006", "Diploma in IT"]
  ];
  samples.forEach(([name, reg_no, course]) => {
    db.students.push({
      id: db.nextId.student++,
      name,
      reg_no,
      course,
      created_at: new Date().toISOString()
    });
  });
}

if (db.classes.length === 0) {
  db.classes.push(
    {
      id: db.nextId.class++,
      name: "Morning Lecture",
      course: "Diploma in IT",
      start_time: "09:00",
      duration_minutes: 90,
      grace_minutes: 15,
      active: 1,
      created_at: new Date().toISOString()
    },
    {
      id: db.nextId.class++,
      name: "Afternoon Lab",
      course: "Diploma in IT",
      start_time: "14:00",
      duration_minutes: 120,
      grace_minutes: 10,
      active: 1,
      created_at: new Date().toISOString()
    }
  );
}

saveDB(db);

// ---------- Middleware ----------
app.use(express.json());
app.use(cookieParser());
app.use(
  session({
    secret: process.env.SESSION_SECRET || "attendance-secret-2026",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000,
      sameSite: "lax"
    }
  })
);

app.use(express.static(path.join(__dirname, "public")));

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  next();
}

// ---------- Auth ----------
app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  db = loadDB();
  const user = db.users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.fullName = user.full_name;
  req.session.role = user.role;

  res.json({
    success: true,
    user: {
      id: user.id,
      username: user.username,
      fullName: user.full_name,
      role: user.role
    }
  });
});

app.post("/api/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ success: true });
  });
});

app.get("/api/auth/me", (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Not authenticated" });
  db = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user) return res.status(401).json({ error: "Not authenticated" });
  res.json({
    id: user.id,
    username: user.username,
    fullName: user.full_name,
    role: user.role
  });
});

app.post("/api/auth/change-password", requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: "Current password and new password (min 6 chars) required" });
  }

  db = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user || !bcrypt.compareSync(currentPassword, user.password_hash)) {
    return res.status(401).json({ error: "Current password is incorrect" });
  }

  user.password_hash = bcrypt.hashSync(newPassword, 10);
  saveDB(db);
  res.json({ success: true, message: "Password updated successfully" });
});

// ---------- Students ----------
app.get("/api/students", requireAuth, (req, res) => {
  db = loadDB();
  let list = [...db.students];
  const q = (req.query.q || "").trim().toLowerCase();
  if (q) {
    list = list.filter(s =>
      `${s.name} ${s.reg_no} ${s.course}`.toLowerCase().includes(q)
    );
  }
  list.sort((a, b) => a.name.localeCompare(b.name));
  res.json(list);
});

app.get("/api/students/:id", requireAuth, (req, res) => {
  db = loadDB();
  const student = db.students.find(s => s.id === +req.params.id);
  if (!student) return res.status(404).json({ error: "Student not found" });
  res.json(student);
});

app.post("/api/students", requireAuth, (req, res) => {
  const { name, reg_no, course } = req.body || {};
  if (!name || !reg_no || !course) {
    return res.status(400).json({ error: "name, reg_no and course are required" });
  }

  db = loadDB();
  if (db.students.some(s => s.reg_no === reg_no.trim())) {
    return res.status(400).json({ error: "Registration number already exists" });
  }

  const student = {
    id: db.nextId.student++,
    name: name.trim(),
    reg_no: reg_no.trim(),
    course: course.trim(),
    created_at: new Date().toISOString()
  };
  db.students.push(student);
  saveDB(db);
  res.status(201).json(student);
});

app.put("/api/students/:id", requireAuth, (req, res) => {
  const { name, reg_no, course } = req.body || {};
  if (!name || !reg_no || !course) {
    return res.status(400).json({ error: "name, reg_no and course are required" });
  }

  db = loadDB();
  const student = db.students.find(s => s.id === +req.params.id);
  if (!student) return res.status(404).json({ error: "Student not found" });

  if (db.students.some(s => s.reg_no === reg_no.trim() && s.id !== student.id)) {
    return res.status(400).json({ error: "Registration number already exists" });
  }

  student.name = name.trim();
  student.reg_no = reg_no.trim();
  student.course = course.trim();
  saveDB(db);
  res.json(student);
});

app.delete("/api/students/:id", requireAuth, (req, res) => {
  db = loadDB();
  const idx = db.students.findIndex(s => s.id === +req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Student not found" });

  const id = db.students[idx].id;
  db.students.splice(idx, 1);
  db.attendance = db.attendance.filter(a => a.student_id !== id);
  saveDB(db);
  res.json({ success: true });
});

// ---------- Classes ----------
app.get("/api/classes", requireAuth, (req, res) => {
  db = loadDB();
  const list = db.classes.filter(c => c.active !== 0);
  list.sort((a, b) => a.start_time.localeCompare(b.start_time) || a.name.localeCompare(b.name));
  res.json(list);
});

app.post("/api/classes", requireAuth, (req, res) => {
  const { name, course, start_time, duration_minutes, grace_minutes } = req.body || {};
  if (!name || !start_time) {
    return res.status(400).json({ error: "name and start_time are required" });
  }
  if (!/^\d{2}:\d{2}$/.test(start_time)) {
    return res.status(400).json({ error: "start_time must be HH:MM" });
  }

  db = loadDB();
  const cls = {
    id: db.nextId.class++,
    name: name.trim(),
    course: (course || "").trim(),
    start_time,
    duration_minutes: duration_minutes || 90,
    grace_minutes: grace_minutes ?? 15,
    active: 1,
    created_at: new Date().toISOString()
  };
  db.classes.push(cls);
  saveDB(db);
  res.status(201).json(cls);
});

app.put("/api/classes/:id", requireAuth, (req, res) => {
  const { name, course, start_time, duration_minutes, grace_minutes, active } = req.body || {};
  if (!name || !start_time) {
    return res.status(400).json({ error: "name and start_time are required" });
  }

  db = loadDB();
  const cls = db.classes.find(c => c.id === +req.params.id);
  if (!cls) return res.status(404).json({ error: "Class not found" });

  cls.name = name.trim();
  cls.course = (course || "").trim();
  cls.start_time = start_time;
  cls.duration_minutes = duration_minutes || 90;
  cls.grace_minutes = grace_minutes ?? 15;
  cls.active = active === 0 ? 0 : 1;
  saveDB(db);
  res.json(cls);
});

app.delete("/api/classes/:id", requireAuth, (req, res) => {
  db = loadDB();
  const cls = db.classes.find(c => c.id === +req.params.id);
  if (!cls) return res.status(404).json({ error: "Class not found" });
  cls.active = 0;
  saveDB(db);
  res.json({ success: true });
});

// Helper for auto late
function decideStatus(classId, requestedStatus) {
  if (!classId || requestedStatus === "Absent") return requestedStatus || "Absent";
  db = loadDB();
  const cls = db.classes.find(c => c.id === classId);
  if (!cls) return requestedStatus || "Present";

  const now = new Date();
  const [h, m] = cls.start_time.split(":").map(Number);
  const start = new Date(now);
  start.setHours(h, m, 0, 0);
  const graceEnd = new Date(start.getTime() + (cls.grace_minutes || 15) * 60 * 1000);

  if (now <= graceEnd) return "Present";
  const end = new Date(start.getTime() + (cls.duration_minutes || 90) * 60 * 1000);
  if (now <= end) return "Late";
  return requestedStatus || "Late";
}

// ---------- Attendance ----------
app.get("/api/attendance/today", requireAuth, (req, res) => {
  db = loadDB();
  const date = new Date().toISOString().slice(0, 10);
  const students = [...db.students].sort((a, b) => a.name.localeCompare(b.name));
  const records = db.attendance.filter(a => a.date === date);

  const map = {};
  records.forEach(r => (map[r.student_id] = r.status));

  let present = 0, late = 0, absent = 0;
  const list = students.map(s => {
    const status = map[s.id] || "Absent";
    if (status === "Present") present++;
    else if (status === "Late") late++;
    else absent++;
    return { ...s, status };
  });

  const total = students.length;
  const rate = total ? Math.round(((present + late) / total) * 100) : 0;

  res.json({ date, total, present, late, absent, rate, list });
});

app.get("/api/attendance", requireAuth, (req, res) => {
  db = loadDB();
  const date = req.query.date || new Date().toISOString().slice(0, 10);
  const classId = req.query.class_id ? +req.query.class_id : null;

  const students = [...db.students].sort((a, b) => a.name.localeCompare(b.name));
  let records = db.attendance.filter(a => a.date === date);
  if (classId) {
    records = records.filter(a => a.class_id === classId);
  }

  res.json({ date, class_id: classId, records, students });
});

app.post("/api/attendance", requireAuth, (req, res) => {
  const { date, class_id, records, auto_late } = req.body || {};
  if (!date || !Array.isArray(records)) {
    return res.status(400).json({ error: "date and records array required" });
  }

  db = loadDB();
  const nowIso = new Date().toISOString();

  for (const r of records) {
    let status = r.status || "Absent";
    if (auto_late && class_id && status !== "Absent") {
      status = decideStatus(class_id, status);
    }

    // find existing
    const existing = db.attendance.find(
      a => a.student_id === r.student_id && a.date === date && a.class_id == class_id
    );

    if (existing) {
      existing.status = status;
      existing.marked_at = nowIso;
    } else {
      db.attendance.push({
        id: db.nextId.attendance++,
        student_id: r.student_id,
        class_id: class_id || null,
        date,
        status,
        marked_at: nowIso
      });
    }
  }

  saveDB(db);
  res.json({ success: true, message: "Attendance saved successfully" });
});

// ---------- Reports ----------
app.get("/api/reports", requireAuth, (req, res) => {
  db = loadDB();
  const q = (req.query.q || "").trim().toLowerCase();
  const students = [...db.students];

  const stats = {};
  students.forEach(s => {
    stats[s.id] = { present: 0, absent: 0, late: 0 };
  });

  db.attendance.forEach(r => {
    if (!stats[r.student_id]) return;
    const key = r.status.toLowerCase();
    if (key === "present") stats[r.student_id].present++;
    else if (key === "late") stats[r.student_id].late++;
    else stats[r.student_id].absent++;
  });

  let performance = students.map(s => {
    const st = stats[s.id];
    const total = st.present + st.absent + st.late;
    const rate = total ? Math.round(((st.present + st.late) / total) * 100) : 0;
    return {
      id: s.id,
      name: s.name,
      reg_no: s.reg_no,
      course: s.course,
      present: st.present,
      absent: st.absent,
      late: st.late,
      rate
    };
  });

  if (q) {
    performance = performance.filter(p =>
      `${p.name} ${p.reg_no} ${p.course}`.toLowerCase().includes(q)
    );
  }

  res.json({ performance });
});

// Export
app.get("/api/export", requireAuth, (req, res) => {
  db = loadDB();
  res.json({
    students: db.students,
    classes: db.classes,
    attendance: db.attendance,
    exportedAt: new Date().toISOString()
  });
});

// Fallback
app.get("*", (req, res, next) => {
  if (req.path.startsWith("/api")) return next();
  const file = path.join(__dirname, "public", req.path === "/" ? "index.html" : req.path);
  if (fs.existsSync(file) && file.endsWith(".html")) {
    return res.sendFile(file);
  }
  next();
});

app.listen(PORT, () => {
  console.log(`Student Attendance System running on port ${PORT}`);
  console.log("Login: admin / ChangeMe123!");
});

