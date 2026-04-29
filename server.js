const express = require("express");
const cors = require("cors");
const path = require("path");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const db = require("./db");

const app = express();
const SECRET_KEY = "mysecretkey123";
const TEACHER_SECRET = "teachersecretkey456";
const STUDENT_SECRET = "studentsecretkey789";

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

/* ================= AUTH MIDDLEWARE ================= */
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
  if (!token) return res.status(403).json({ message: "No token" });
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Invalid token" });
    req.user = decoded;
    next();
  });
}

function verifyTeacherToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
  if (!token) return res.status(403).json({ message: "No token" });
  jwt.verify(token, TEACHER_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Invalid teacher token" });
    req.teacher = decoded;
    next();
  });
}

function verifyStudentToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
  if (!token) return res.status(403).json({ message: "No token" });
  jwt.verify(token, STUDENT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Invalid student token" });
    req.student = decoded;
    next();
  });
}

/* ================= PAGES ================= */
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "adminlogin.html")));

/* ================= ADMIN LOGIN ================= */
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.query("SELECT * FROM users WHERE username=$1 AND password=$2", [username, password], (err, result) => {
    if (err || !result || result.length === 0)
      return res.json({ success: false, message: "Invalid credentials" });
    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: "1h" });
    res.json({ success: true, token });
  });
});

/* ================= TEACHER REGISTER ================= */
app.post("/teacher-register", (req, res) => {
  const { name, email, username, password, teacherId } = req.body;
  if (!name || !email || !username || !password || !teacherId)
    return res.json({ success: false, message: "All fields required." });
  db.query("SELECT id FROM teacher_accounts WHERE email = $1 OR username = $2", [email, username], (err, existing) => {
    if (err) return res.json({ success: false, message: "Server error." });
    if (existing && existing.length > 0)
      return res.json({ success: false, message: "Email or username already taken." });
    bcrypt.hash(password, 10, (hashErr, hash) => {
      if (hashErr) return res.json({ success: false, message: "Error securing password." });
      db.query(
        "INSERT INTO teacher_accounts (name, email, username, password, teacher_id) VALUES ($1, $2, $3, $4, $5)",
        [name, email, username, hash, teacherId],
        (insertErr) => {
          if (insertErr) return res.json({ success: false, message: "Registration failed." });
          res.json({ success: true, message: "Account created successfully." });
        }
      );
    });
  });
});

/* ================= TEACHER LOGIN ================= */
app.post("/teacher-login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.json({ success: false, message: "Username and password required." });
  db.query(
    `SELECT ta.*, t.name AS "teacherName", t.course AS "teacherCourse"
     FROM teacher_accounts ta
     LEFT JOIN teachers t ON ta.teacher_id = t.id
     WHERE ta.username = $1`,
    [username],
    (err, result) => {
      if (err) return res.json({ success: false, message: "Server error." });
      if (!result || result.length === 0)
        return res.json({ success: false, message: "Username not found." });
      const account = result[0];
      bcrypt.compare(password, account.password, (compareErr, match) => {
        if (compareErr) return res.json({ success: false, message: "Server error." });
        if (!match) return res.json({ success: false, message: "Incorrect password." });
        const token = jwt.sign(
          { id: account.id, email: account.email, role: "teacher" },
          TEACHER_SECRET, { expiresIn: "8h" }
        );
        res.json({
          success: true, token,
          teacher: {
            id: account.id, name: account.name, email: account.email,
            username: account.username, teacherId: account.teacher_id,
            course: account.teacherCourse
          }
        });
      });
    }
  );
});

/* ================= TEACHER PROFILE ================= */
app.get("/teacher-profile", verifyTeacherToken, (req, res) => {
  db.query(
    `SELECT ta.id, ta.name, ta.email, ta.username, ta.teacher_id, t.course, t.name AS "fullName"
     FROM teacher_accounts ta LEFT JOIN teachers t ON ta.teacher_id = t.id WHERE ta.id = $1`,
    [req.teacher.id],
    (err, result) => {
      if (err || !result || result.length === 0)
        return res.json({ success: false, message: "Profile not found." });
      res.json({ success: true, teacher: result[0] });
    }
  );
});

/* ================= STUDENT REGISTER ================= */
app.post("/student-register", (req, res) => {
  const { name, email, username, password, studentId } = req.body;
  if (!name || !email || !username || !password || !studentId)
    return res.json({ success: false, message: "All fields required." });
  db.query("SELECT id FROM student_accounts WHERE email = $1 OR username = $2", [email, username], (err, existing) => {
    if (err) return res.json({ success: false, message: "Server error." });
    if (existing && existing.length > 0)
      return res.json({ success: false, message: "Email or username already taken." });
    bcrypt.hash(password, 10, (hashErr, hash) => {
      if (hashErr) return res.json({ success: false, message: "Error securing password." });
      db.query(
        "INSERT INTO student_accounts (name, email, username, password, student_id) VALUES ($1, $2, $3, $4, $5)",
        [name, email, username, hash, studentId],
        (insertErr) => {
          if (insertErr) return res.json({ success: false, message: "Registration failed." });
          res.json({ success: true, message: "Account created successfully." });
        }
      );
    });
  });
});

/* ================= STUDENT LOGIN ================= */
app.post("/student-login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.json({ success: false, message: "Username and password required." });
  db.query(
    `SELECT sa.*, s.name AS "studentName", s.email AS "studentEmail", s.course AS "studentCourse"
     FROM student_accounts sa
     LEFT JOIN students s ON sa.student_id = s.id
     WHERE sa.username = $1`,
    [username],
    (err, result) => {
      if (err) return res.json({ success: false, message: "Server error." });
      if (!result || result.length === 0)
        return res.json({ success: false, message: "Username not found." });
      const account = result[0];
      bcrypt.compare(password, account.password, (compareErr, match) => {
        if (compareErr) return res.json({ success: false, message: "Server error." });
        if (!match) return res.json({ success: false, message: "Incorrect password." });
        const token = jwt.sign(
          { id: account.id, email: account.email, role: "student" },
          STUDENT_SECRET, { expiresIn: "8h" }
        );
        res.json({
          success: true, token,
          student: {
            id: account.id,
            name: account.name || account.studentName,
            email: account.email || account.studentEmail,
            username: account.username,
            studentId: account.student_id,
            course: account.studentCourse
          }
        });
      });
    }
  );
});

/* ================= DASHBOARD ================= */
app.get("/dashboard", verifyToken, (req, res) => {
  db.query("SELECT COUNT(*) AS totalStudents FROM students", [], (err, studentsResult) => {
    if (err) return res.json({ totalStudents: 0, totalEnrollments: 0 });
    db.query("SELECT COUNT(*) AS totalEnrollments FROM enrollments", [], (err2, enrollmentsResult) => {
      if (err2) return res.json({ totalStudents: studentsResult[0].totalstudents, totalEnrollments: 0 });
      res.json({
        totalStudents: studentsResult[0].totalstudents,
        totalEnrollments: enrollmentsResult[0].totalenrollments,
      });
    });
  });
});

/* ================= STUDENTS ================= */
app.get("/students", (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
  if (!token) {
    db.query("SELECT id, name, email, course FROM students", [], (err, result) => res.json(result || []));
    return;
  }
  const tryAdmin = () => {
    jwt.verify(token, SECRET_KEY, (err) => {
      if (err) return res.status(401).json({ message: "Invalid token" });
      db.query("SELECT * FROM students", [], (err2, result) => res.json(result || []));
    });
  };
  const tryStudent = () => {
    jwt.verify(token, STUDENT_SECRET, (err) => {
      if (err) return tryAdmin();
      db.query("SELECT id, name, email, course FROM students", [], (err2, result) => res.json(result || []));
    });
  };
  jwt.verify(token, TEACHER_SECRET, (err) => {
    if (err) return tryStudent();
    db.query("SELECT * FROM students", [], (err2, result) => res.json(result || []));
  });
});

app.post("/students", verifyToken, (req, res) => {
  const { name, email, course } = req.body;
  if (!name || !email || !course) return res.json({ success: false });
  db.query("INSERT INTO students (name, email, course) VALUES ($1, $2, $3)", [name, email, course], (err) => {
    res.json({ success: !err });
  });
});

app.put("/students/:id", verifyToken, (req, res) => {
  const { name, email, course } = req.body;
  db.query("UPDATE students SET name=$1, email=$2, course=$3 WHERE id=$4", [name, email, course, req.params.id], (err) => {
    res.json({ success: !err });
  });
});

app.delete("/students/:id", verifyToken, (req, res) => {
  const id = req.params.id;
  db.query("DELETE FROM teacher_attendance WHERE student_id = $1", [id], () => {
    db.query("DELETE FROM teacher_grades WHERE student_id = $1", [id], () => {
      db.query("DELETE FROM enrollments WHERE student_id = $1", [id], () => {
        db.query("DELETE FROM student_accounts WHERE student_id = $1", [id], () => {
          db.query("DELETE FROM students WHERE id = $1", [id], (err) => {
            res.json({ success: !err });
          });
        });
      });
    });
  });
});

app.get("/students/search/:key", verifyToken, (req, res) => {
  const key = "%" + req.params.key + "%";
  db.query("SELECT * FROM students WHERE name ILIKE $1 OR email ILIKE $2 OR course ILIKE $3", [key, key, key], (err, result) => res.json(result || []));
});

/* ================= TEACHERS ================= */
app.get("/teachers", (req, res) => {
  db.query("SELECT * FROM teachers", [], (err, result) => res.json(result || []));
});

app.post("/teachers", verifyToken, (req, res) => {
  const { name, email, course } = req.body;
  if (!name || !email || !course) return res.json({ success: false });
  db.query("INSERT INTO teachers (name, email, course) VALUES ($1, $2, $3)", [name, email, course], (err) => res.json({ success: !err }));
});

app.put("/teachers/:id", verifyToken, (req, res) => {
  const { name, email, course } = req.body;
  db.query("UPDATE teachers SET name=$1, email=$2, course=$3 WHERE id=$4", [name, email, course, req.params.id], (err) => res.json({ success: !err }));
});

app.delete("/teachers/:id", verifyToken, (req, res) => {
  const id = req.params.id;
  db.query("DELETE FROM timetabless WHERE teacher_id = $1", [id], () => {
    db.query("DELETE FROM allocations WHERE teacher_id = $1", [id], () => {
      db.query("DELETE FROM teacher_assignments WHERE teacher_id = $1", [id], () => {
        db.query("DELETE FROM teacher_materials WHERE teacher_id = $1", [id], () => {
          db.query("DELETE FROM teacher_announcements WHERE teacher_id = $1", [id], () => {
            db.query("DELETE FROM teacher_accounts WHERE teacher_id = $1", [id], () => {
              db.query("DELETE FROM teachers WHERE id = $1", [id], (err) => {
                res.json({ success: !err });
              });
            });
          });
        });
      });
    });
  });
});

/* ================= COURSES ================= */
app.get("/courses", (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
  if (!token) return res.status(403).json({ message: "No token" });
  const tryAdmin = () => {
    jwt.verify(token, SECRET_KEY, (err) => {
      if (err) return res.status(401).json({ message: "Invalid token" });
      db.query("SELECT * FROM courses", [], (err2, result) => res.json(result || []));
    });
  };
  const tryStudent = () => {
    jwt.verify(token, STUDENT_SECRET, (err) => {
      if (err) return tryAdmin();
      db.query("SELECT * FROM courses", [], (err2, result) => res.json(result || []));
    });
  };
  jwt.verify(token, TEACHER_SECRET, (err) => {
    if (err) return tryStudent();
    db.query("SELECT * FROM courses", [], (err2, result) => res.json(result || []));
  });
});

app.post("/courses", verifyToken, (req, res) => {
  const { name, instructor, duration } = req.body;
  if (!name || !instructor || !duration) return res.json({ success: false });
  db.query("INSERT INTO courses (name, instructor, duration) VALUES ($1, $2, $3)", [name, instructor, duration], (err) => res.json({ success: !err }));
});

app.put("/courses/:id", verifyToken, (req, res) => {
  const { name, instructor, duration } = req.body;
  db.query("UPDATE courses SET name=$1, instructor=$2, duration=$3 WHERE id=$4", [name, instructor, duration, req.params.id], (err) => res.json({ success: !err }));
});

app.delete("/courses/:id", verifyToken, (req, res) => {
  const id = req.params.id;
  db.query("DELETE FROM timetabless WHERE course_id = $1", [id], () => {
    db.query("DELETE FROM allocations WHERE course_id = $1", [id], () => {
      db.query("DELETE FROM teacher_attendance WHERE course_id = $1", [id], () => {
        db.query("DELETE FROM teacher_grades WHERE course_id = $1", [id], () => {
          db.query("DELETE FROM teacher_assignments WHERE course_id = $1", [id], () => {
            db.query("DELETE FROM teacher_materials WHERE course_id = $1", [id], () => {
              db.query("DELETE FROM teacher_announcements WHERE course_id = $1", [id], () => {
                db.query("DELETE FROM enrollments WHERE course_id = $1", [id], () => {
                  db.query("DELETE FROM courses WHERE id = $1", [id], (err) => {
                    res.json({ success: !err });
                  });
                });
              });
            });
          });
        });
      });
    });
  });
});

/* ================= DEPARTMENTS ================= */
app.get("/departments", verifyToken, (req, res) => {
  db.query("SELECT * FROM departments", [], (err, result) => res.json(result || []));
});

app.post("/departments", verifyToken, (req, res) => {
  const { name, program, duration } = req.body;
  if (!name || !program || !duration) return res.json({ success: false });
  db.query("INSERT INTO departments (name, program, duration) VALUES ($1, $2, $3)", [name, program, duration], (err) => res.json({ success: !err }));
});

app.put("/departments/:id", verifyToken, (req, res) => {
  const { name, program, duration } = req.body;
  db.query("UPDATE departments SET name=$1, program=$2, duration=$3 WHERE id=$4", [name, program, duration, req.params.id], (err) => res.json({ success: !err }));
});

app.delete("/departments/:id", verifyToken, (req, res) => {
  db.query("DELETE FROM departments WHERE id=$1", [req.params.id], (err) => res.json({ success: !err }));
});

/* ================= ENROLLMENTS ================= */
app.get("/enrollments", (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
  if (!token) return res.status(403).json({ message: "No token" });
  const sql = `
    SELECT e.id, e.student_id AS "studentId", e.course_id AS "courseId",
           s.name AS "studentName", c.name AS "courseName"
    FROM enrollments e
    LEFT JOIN students s ON e.student_id = s.id
    LEFT JOIN courses c ON e.course_id = c.id
    ORDER BY e.id DESC`;
  const runQuery = () => db.query(sql, [], (err, result) => res.json(result || []));
  jwt.verify(token, TEACHER_SECRET, (err) => {
    if (err) {
      jwt.verify(token, SECRET_KEY, (err2) => {
        if (err2) return res.status(401).json({ message: "Invalid token" });
        runQuery();
      });
    } else runQuery();
  });
});

app.post("/enrollments", verifyToken, (req, res) => {
  const { studentId, courseId } = req.body;
  if (!studentId || !courseId) return res.json({ success: false });
  db.query("SELECT id FROM enrollments WHERE student_id=$1 AND course_id=$2", [studentId, courseId], (err, existing) => {
    if (err) return res.json({ success: false });
    if (existing.length > 0) return res.json({ success: false, message: "Already enrolled" });
    db.query("INSERT INTO enrollments (student_id, course_id) VALUES ($1, $2)", [studentId, courseId], (err2) => res.json({ success: !err2 }));
  });
});

app.put("/enrollments/:id", verifyToken, (req, res) => {
  const { studentId, courseId } = req.body;
  if (!studentId || !courseId) return res.json({ success: false });
  db.query("SELECT id FROM enrollments WHERE student_id=$1 AND course_id=$2 AND id<>$3", [studentId, courseId, req.params.id], (err, existing) => {
    if (err) return res.json({ success: false });
    if (existing.length > 0) return res.json({ success: false, message: "Already enrolled" });
    db.query("UPDATE enrollments SET student_id=$1, course_id=$2 WHERE id=$3", [studentId, courseId, req.params.id], (err2) => res.json({ success: !err2 }));
  });
});

app.delete("/enrollments/:id", verifyToken, (req, res) => {
  const id = req.params.id;
  db.query("SELECT student_id, course_id FROM enrollments WHERE id = $1", [id], (err, rows) => {
    if (err || !rows || rows.length === 0)
      return res.json({ success: false, message: "Enrollment not found" });
    const { student_id, course_id } = rows[0];
    db.query("DELETE FROM teacher_attendance WHERE student_id = $1 AND course_id = $2", [student_id, course_id], () => {
      db.query("DELETE FROM teacher_grades WHERE student_id = $1 AND course_id = $2", [student_id, course_id], () => {
        db.query("DELETE FROM enrollments WHERE id = $1", [id], (err2) => {
          res.json({ success: !err2 });
        });
      });
    });
  });
});

/* ================= ALLOCATIONS ================= */
app.get("/allocations", verifyToken, (req, res) => {
  db.query(
    `SELECT a.id, a.teacher_id, a.course_id, t.name AS "teacherName", c.name AS "courseName"
     FROM allocations a LEFT JOIN teachers t ON a.teacher_id = t.id
     LEFT JOIN courses c ON a.course_id = c.id ORDER BY a.id DESC`,
    [], (err, result) => res.json(result || [])
  );
});

app.post("/allocations", verifyToken, (req, res) => {
  const { teacherId, courseId } = req.body;
  if (!teacherId || !courseId) return res.json({ success: false });
  db.query("SELECT id FROM allocations WHERE teacher_id=$1 AND course_id=$2", [teacherId, courseId], (err, existing) => {
    if (err) return res.json({ success: false });
    if (existing.length > 0) return res.json({ success: false, message: "Already allocated" });
    db.query("INSERT INTO allocations (teacher_id, course_id) VALUES ($1, $2)", [teacherId, courseId], (err2) => res.json({ success: !err2 }));
  });
});

app.put("/allocations/:id", verifyToken, (req, res) => {
  const { teacherId, courseId } = req.body;
  if (!teacherId || !courseId) return res.json({ success: false });
  db.query("SELECT id FROM allocations WHERE teacher_id=$1 AND course_id=$2 AND id<>$3", [teacherId, courseId, req.params.id], (err, existing) => {
    if (err) return res.json({ success: false });
    if (existing.length > 0) return res.json({ success: false, message: "Already allocated" });
    db.query("UPDATE allocations SET teacher_id=$1, course_id=$2 WHERE id=$3", [teacherId, courseId, req.params.id], (err2) => res.json({ success: !err2 }));
  });
});

app.delete("/allocations/:id", verifyToken, (req, res) => {
  const id = req.params.id;
  db.query("SELECT teacher_id, course_id FROM allocations WHERE id = $1", [id], (err, rows) => {
    if (err || !rows || rows.length === 0)
      return res.json({ success: false, message: "Allocation not found" });
    const { teacher_id, course_id } = rows[0];
    db.query("DELETE FROM timetabless WHERE teacher_id = $1 AND course_id = $2", [teacher_id, course_id], () => {
      db.query("DELETE FROM allocations WHERE id = $1", [id], (err2) => {
        res.json({ success: !err2 });
      });
    });
  });
});

/* ================= TIMETABLES ================= */
app.get("/timetabless", (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
  if (!token) return res.status(403).json({ message: "No token" });
  const sql = `
    SELECT tt.id, tt.semester, tt.day, tt.time, tt.room,
           tt.teacher_id, tt.course_id,
           t.name AS "teacherName", c.name AS "courseName"
    FROM timetabless tt
    LEFT JOIN teachers t ON tt.teacher_id = t.id
    LEFT JOIN courses c ON tt.course_id = c.id
    ORDER BY tt.id DESC`;
  const runQuery = () => db.query(sql, [], (err, result) => res.json(result || []));
  jwt.verify(token, TEACHER_SECRET, (err) => {
    if (err) {
      jwt.verify(token, SECRET_KEY, (err2) => {
        if (err2) return res.status(401).json({ message: "Invalid token" });
        runQuery();
      });
    } else runQuery();
  });
});

app.post("/timetabless", verifyToken, (req, res) => {
  const { semester, day, time, room, teacherId, courseId } = req.body;
  if (!semester || !day || !time || !teacherId || !courseId) return res.json({ success: false });
  db.query("SELECT id FROM timetabless WHERE semester=$1 AND day=$2 AND time=$3 AND teacher_id=$4", [semester, day, time, teacherId], (err, existing) => {
    if (err) return res.json({ success: false });
    if (existing.length > 0) return res.json({ success: false, message: "Time slot already occupied" });
    db.query("INSERT INTO timetabless (semester, day, time, room, teacher_id, course_id) VALUES ($1, $2, $3, $4, $5, $6)", [semester, day, time, room, teacherId, courseId], (err2) => res.json({ success: !err2 }));
  });
});

app.put("/timetabless/:id", verifyToken, (req, res) => {
  const { semester, day, time, room, teacherId, courseId } = req.body;
  if (!semester || !day || !time || !teacherId || !courseId) return res.json({ success: false });
  db.query("SELECT id FROM timetabless WHERE semester=$1 AND day=$2 AND time=$3 AND teacher_id=$4 AND id<>$5", [semester, day, time, teacherId, req.params.id], (err, existing) => {
    if (err) return res.json({ success: false });
    if (existing.length > 0) return res.json({ success: false, message: "Time slot already occupied" });
    db.query("UPDATE timetabless SET semester=$1, day=$2, time=$3, room=$4, teacher_id=$5, course_id=$6 WHERE id=$7", [semester, day, time, room, teacherId, courseId, req.params.id], (err2) => res.json({ success: !err2 }));
  });
});

app.delete("/timetabless/:id", verifyToken, (req, res) => {
  db.query("DELETE FROM timetabless WHERE id=$1", [req.params.id], (err) => res.json({ success: !err }));
});

/* ================= SETTINGS ================= */
app.get("/settings", verifyToken, (req, res) => {
  db.query("SELECT setting_key, setting_value FROM system_settings", [], (err, rows) => {
    if (err) return res.json({});
    const settings = {};
    (rows || []).forEach(r => {
      try { settings[r.setting_key] = JSON.parse(r.setting_value); }
      catch(e) { settings[r.setting_key] = r.setting_value; }
    });
    res.json(settings);
  });
});

app.put("/settings/:key", verifyToken, (req, res) => {
  const key = req.params.key;
  const value = JSON.stringify(req.body.value);
  db.query(
    `INSERT INTO system_settings (setting_key, setting_value) VALUES ($1, $2)
     ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value`,
    [key, value],
    (err) => res.json({ success: !err })
  );
});

/* ================= SEMESTERS ================= */
app.get("/semesters", verifyToken, (req, res) => {
  db.query("SELECT * FROM semesters ORDER BY id DESC", [], (err, result) => res.json(result || []));
});

app.post("/semesters", verifyToken, (req, res) => {
  const { name, start, end, regDeadline, status } = req.body;
  if (!name) return res.json({ success: false, message: "Name required" });
  db.query(
    "INSERT INTO semesters (name, start_date, end_date, reg_deadline, status) VALUES ($1, $2, $3, $4, $5)",
    [name, start || null, end || null, regDeadline || null, status || "upcoming"],
    (err) => res.json({ success: !err })
  );
});

app.put("/semesters/:id", verifyToken, (req, res) => {
  const { name, start, end, regDeadline, status } = req.body;
  if (!name) return res.json({ success: false, message: "Name required" });
  db.query(
    "UPDATE semesters SET name=$1, start_date=$2, end_date=$3, reg_deadline=$4, status=$5 WHERE id=$6",
    [name, start || null, end || null, regDeadline || null, status || "upcoming", req.params.id],
    (err) => res.json({ success: !err })
  );
});

app.delete("/semesters/:id", verifyToken, (req, res) => {
  db.query("DELETE FROM semesters WHERE id=$1", [req.params.id], (err) => res.json({ success: !err }));
});

/* ================= GRADE BOUNDARIES ================= */
app.get("/grade-boundaries", verifyToken, (req, res) => {
  db.query("SELECT * FROM grade_boundaries ORDER BY min_percent DESC", [], (err, result) => res.json(result || []));
});

app.post("/grade-boundaries", verifyToken, (req, res) => {
  const { grade, min, max, gpa, remark } = req.body;
  if (!grade) return res.json({ success: false });
  db.query(
    "INSERT INTO grade_boundaries (grade, min_percent, max_percent, gpa_points, remark) VALUES ($1, $2, $3, $4, $5)",
    [grade, min || 0, max || 0, gpa || 0, remark || ""],
    (err) => res.json({ success: !err })
  );
});

app.put("/grade-boundaries/:id", verifyToken, (req, res) => {
  const { grade, min, max, gpa, remark } = req.body;
  db.query(
    "UPDATE grade_boundaries SET grade=$1, min_percent=$2, max_percent=$3, gpa_points=$4, remark=$5 WHERE id=$6",
    [grade, min || 0, max || 0, gpa || 0, remark || "", req.params.id],
    (err) => res.json({ success: !err })
  );
});

app.delete("/grade-boundaries/:id", verifyToken, (req, res) => {
  db.query("DELETE FROM grade_boundaries WHERE id=$1", [req.params.id], (err) => res.json({ success: !err }));
});

app.post("/grade-boundaries/replace-all", verifyToken, (req, res) => {
  const { boundaries } = req.body;
  if (!Array.isArray(boundaries)) return res.json({ success: false });
  db.query("DELETE FROM grade_boundaries", [], (err) => {
    if (err) return res.json({ success: false });
    if (boundaries.length === 0) return res.json({ success: true });
    const values = boundaries.map((b, i) => {
      const offset = i * 5;
      return `($${offset+1}, $${offset+2}, $${offset+3}, $${offset+4}, $${offset+5})`;
    }).join(", ");
    const params = boundaries.flatMap(b => [b.grade || "", b.min || 0, b.max || 0, b.gpa || 0, b.remark || ""]);
    db.query(
      `INSERT INTO grade_boundaries (grade, min_percent, max_percent, gpa_points, remark) VALUES ${values}`,
      params,
      (err2) => res.json({ success: !err2 })
    );
  });
});

/* ===============================================================
   TEACHER DASHBOARD ROUTES
   =============================================================== */

function getTeacherId(accountId, callback) {
  db.query("SELECT teacher_id FROM teacher_accounts WHERE id = $1", [accountId], (err, rows) => {
    if (err || !rows || rows.length === 0) return callback(null);
    callback(rows[0].teacher_id);
  });
}

app.get("/teacher/my-courses", verifyTeacherToken, (req, res) => {
  getTeacherId(req.teacher.id, (teacherId) => {
    if (!teacherId) return res.json([]);
    db.query(
      `SELECT c.*, a.id AS "allocationId", t.name AS "teacherName"
       FROM allocations a
       JOIN courses c ON a.course_id = c.id
       JOIN teachers t ON a.teacher_id = t.id
       WHERE a.teacher_id = $1`,
      [teacherId], (err, result) => res.json(result || [])
    );
  });
});

app.get("/teacher/course-students/:courseId", verifyTeacherToken, (req, res) => {
  db.query(
    `SELECT s.id, s.name, s.email, s.course, e.id AS "enrollmentId"
     FROM enrollments e
     JOIN students s ON e.student_id = s.id
     WHERE e.course_id = $1
     ORDER BY s.name`,
    [req.params.courseId], (err, result) => res.json(result || [])
  );
});

app.get("/teacher/my-students", verifyTeacherToken, (req, res) => {
  getTeacherId(req.teacher.id, (teacherId) => {
    if (!teacherId) return res.json([]);
    db.query(
      `SELECT DISTINCT s.id, s.name, s.email, s.course
       FROM allocations a
       JOIN enrollments e ON e.course_id = a.course_id
       JOIN students s ON s.id = e.student_id
       WHERE a.teacher_id = $1
       ORDER BY s.name`,
      [teacherId], (err, result) => res.json(result || [])
    );
  });
});

app.get("/teacher/my-timetable", verifyTeacherToken, (req, res) => {
  getTeacherId(req.teacher.id, (teacherId) => {
    if (!teacherId) return res.json([]);
    db.query(
      `SELECT tt.id, tt.semester, tt.day, tt.time, tt.room,
              tt.teacher_id, tt.course_id,
              t.name AS "teacherName", c.name AS "courseName"
       FROM timetabless tt
       LEFT JOIN teachers t ON tt.teacher_id = t.id
       LEFT JOIN courses c ON tt.course_id = c.id
       WHERE tt.teacher_id = $1
       ORDER BY
         CASE tt.day
           WHEN 'Monday' THEN 1 WHEN 'Tuesday' THEN 2 WHEN 'Wednesday' THEN 3
           WHEN 'Thursday' THEN 4 WHEN 'Friday' THEN 5 WHEN 'Saturday' THEN 6
           WHEN 'Sunday' THEN 7 END, tt.time`,
      [teacherId], (err, result) => res.json(result || [])
    );
  });
});

app.post("/teacher/attendance", verifyTeacherToken, (req, res) => {
  const { courseId, date, records } = req.body;
  if (!courseId || !date || !Array.isArray(records) || records.length === 0)
    return res.json({ success: false, message: "Missing data." });
  db.query("DELETE FROM teacher_attendance WHERE course_id = $1 AND date = $2", [courseId, date], (err) => {
    if (err) return res.json({ success: false });
    const values = records.map((r, i) => {
      const offset = i * 4;
      return `($${offset+1}, $${offset+2}, $${offset+3}, $${offset+4})`;
    }).join(", ");
    const params = records.flatMap(r => [courseId, r.studentId, date, r.status || "present"]);
    db.query(
      `INSERT INTO teacher_attendance (course_id, student_id, date, status) VALUES ${values}`,
      params, (err2) => res.json({ success: !err2 })
    );
  });
});

app.get("/teacher/attendance/:courseId", verifyTeacherToken, (req, res) => {
  db.query(
    `SELECT ta.*, s.name AS "studentName", s.email AS "studentEmail"
     FROM teacher_attendance ta
     JOIN students s ON ta.student_id = s.id
     WHERE ta.course_id = $1
     ORDER BY ta.date DESC`,
    [req.params.courseId], (err, result) => res.json(result || [])
  );
});

app.get("/teacher/attendance-all", verifyTeacherToken, (req, res) => {
  getTeacherId(req.teacher.id, (teacherId) => {
    if (!teacherId) return res.json([]);
    db.query(
      `SELECT ta.*, s.name AS "studentName", c.name AS "courseName"
       FROM teacher_attendance ta
       JOIN students s ON ta.student_id = s.id
       JOIN courses c ON ta.course_id = c.id
       JOIN allocations a ON a.course_id = ta.course_id AND a.teacher_id = $1
       ORDER BY ta.date DESC`,
      [teacherId], (err, result) => res.json(result || [])
    );
  });
});

app.post("/teacher/grades", verifyTeacherToken, (req, res) => {
  const { courseId, studentId, midterm, final, assignment } = req.body;
  if (!courseId || !studentId) return res.json({ success: false, message: "Missing data." });
  db.query(
    `INSERT INTO teacher_grades (course_id, student_id, midterm, final, assignment)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (course_id, student_id) DO UPDATE SET midterm=EXCLUDED.midterm, final=EXCLUDED.final, assignment=EXCLUDED.assignment`,
    [courseId, studentId, midterm || 0, final || 0, assignment || 0],
    (err) => res.json({ success: !err })
  );
});

app.get("/teacher/grades/:courseId", verifyTeacherToken, (req, res) => {
  db.query(
    `SELECT tg.*, s.name AS "studentName", s.email AS "studentEmail"
     FROM teacher_grades tg
     JOIN students s ON tg.student_id = s.id
     WHERE tg.course_id = $1`,
    [req.params.courseId], (err, result) => res.json(result || [])
  );
});

app.get("/teacher/assignments", verifyTeacherToken, (req, res) => {
  getTeacherId(req.teacher.id, (teacherId) => {
    if (!teacherId) return res.json([]);
    db.query(
      `SELECT ta.*, c.name AS "courseName"
       FROM teacher_assignments ta
       JOIN courses c ON ta.course_id = c.id
       WHERE ta.teacher_id = $1
       ORDER BY ta.created_at DESC`,
      [teacherId], (err, result) => res.json(result || [])
    );
  });
});

app.post("/teacher/assignments", verifyTeacherToken, (req, res) => {
  const { courseId, title, description, deadline, maxMarks } = req.body;
  if (!courseId || !title) return res.json({ success: false, message: "Missing fields." });
  getTeacherId(req.teacher.id, (teacherId) => {
    if (!teacherId) return res.json({ success: false });
    db.query(
      "INSERT INTO teacher_assignments (teacher_id, course_id, title, description, deadline, max_marks) VALUES ($1, $2, $3, $4, $5, $6)",
      [teacherId, courseId, title, description || "", deadline || null, maxMarks || 100],
      (err) => res.json({ success: !err })
    );
  });
});

app.delete("/teacher/assignments/:id", verifyTeacherToken, (req, res) => {
  db.query("DELETE FROM teacher_assignments WHERE id = $1", [req.params.id], (err) => res.json({ success: !err }));
});

app.get("/teacher/materials", verifyTeacherToken, (req, res) => {
  getTeacherId(req.teacher.id, (teacherId) => {
    if (!teacherId) return res.json([]);
    db.query(
      `SELECT tm.*, c.name AS "courseName"
       FROM teacher_materials tm
       JOIN courses c ON tm.course_id = c.id
       WHERE tm.teacher_id = $1
       ORDER BY tm.created_at DESC`,
      [teacherId], (err, result) => res.json(result || [])
    );
  });
});

app.post("/teacher/materials", verifyTeacherToken, (req, res) => {
  const { courseId, title, type, url } = req.body;
  if (!courseId || !title) return res.json({ success: false, message: "Missing fields." });
  getTeacherId(req.teacher.id, (teacherId) => {
    if (!teacherId) return res.json({ success: false });
    db.query(
      "INSERT INTO teacher_materials (teacher_id, course_id, title, type, url) VALUES ($1, $2, $3, $4, $5)",
      [teacherId, courseId, title, type || "Other", url || ""],
      (err) => res.json({ success: !err })
    );
  });
});

app.delete("/teacher/materials/:id", verifyTeacherToken, (req, res) => {
  db.query("DELETE FROM teacher_materials WHERE id = $1", [req.params.id], (err) => res.json({ success: !err }));
});

app.get("/teacher/announcements", verifyTeacherToken, (req, res) => {
  getTeacherId(req.teacher.id, (teacherId) => {
    if (!teacherId) return res.json([]);
    db.query(
      `SELECT ta.*, c.name AS "courseName"
       FROM teacher_announcements ta
       LEFT JOIN courses c ON ta.course_id = c.id
       WHERE ta.teacher_id = $1
       ORDER BY ta.created_at DESC`,
      [teacherId], (err, result) => res.json(result || [])
    );
  });
});

app.post("/teacher/announcements", verifyTeacherToken, (req, res) => {
  const { courseId, title, message } = req.body;
  if (!title || !message) return res.json({ success: false, message: "Missing fields." });
  getTeacherId(req.teacher.id, (teacherId) => {
    if (!teacherId) return res.json({ success: false });
    db.query(
      "INSERT INTO teacher_announcements (teacher_id, course_id, title, message) VALUES ($1, $2, $3, $4)",
      [teacherId, courseId || null, title, message],
      (err) => res.json({ success: !err })
    );
  });
});

app.delete("/teacher/announcements/:id", verifyTeacherToken, (req, res) => {
  db.query("DELETE FROM teacher_announcements WHERE id = $1", [req.params.id], (err) => res.json({ success: !err }));
});

/* ===============================================================
   STUDENT DASHBOARD ROUTES
   =============================================================== */

function getStudentId(accountId, callback) {
  db.query("SELECT student_id FROM student_accounts WHERE id = $1", [accountId], (err, rows) => {
    if (err || !rows || rows.length === 0) return callback(null);
    callback(rows[0].student_id);
  });
}

app.get("/student/my-courses", verifyStudentToken, (req, res) => {
  getStudentId(req.student.id, (studentId) => {
    if (!studentId) return res.json([]);
    db.query(
      `SELECT c.id, c.name, c.instructor, c.duration,
              e.id AS "enrollmentId",
              MAX(t.name) AS "teacherName"
       FROM enrollments e
       JOIN courses c ON e.course_id = c.id
       LEFT JOIN allocations a ON a.course_id = c.id
       LEFT JOIN teachers t ON a.teacher_id = t.id
       WHERE e.student_id = $1
       GROUP BY c.id, c.name, c.instructor, c.duration, e.id`,
      [studentId], (err, result) => res.json(result || [])
    );
  });
});

app.get("/student/my-attendance", verifyStudentToken, (req, res) => {
  getStudentId(req.student.id, (studentId) => {
    if (!studentId) return res.json([]);
    db.query(
      `SELECT ta.id, ta.course_id, ta.student_id, ta.date, ta.status,
              c.name AS "courseName"
       FROM teacher_attendance ta
       JOIN courses c ON ta.course_id = c.id
       WHERE ta.student_id = $1
       ORDER BY ta.date DESC`,
      [studentId], (err, result) => res.json(result || [])
    );
  });
});

app.get("/student/my-grades", verifyStudentToken, (req, res) => {
  getStudentId(req.student.id, (studentId) => {
    if (!studentId) return res.json([]);
    db.query(
      `SELECT tg.id, tg.course_id, tg.student_id,
              tg.midterm, tg.final, tg.assignment,
              c.name AS "courseName"
       FROM teacher_grades tg
       JOIN courses c ON tg.course_id = c.id
       WHERE tg.student_id = $1`,
      [studentId], (err, result) => res.json(result || [])
    );
  });
});

app.get("/student/my-timetable", verifyStudentToken, (req, res) => {
  getStudentId(req.student.id, (studentId) => {
    if (!studentId) return res.json([]);
    db.query(
      `SELECT DISTINCT
              tt.id, tt.semester, tt.day, tt.time, tt.room,
              tt.teacher_id, tt.course_id,
              c.name AS "courseName",
              t.name AS "teacherName"
       FROM timetabless tt
       JOIN courses c ON tt.course_id = c.id
       JOIN enrollments e ON e.course_id = tt.course_id
       LEFT JOIN teachers t ON tt.teacher_id = t.id
       WHERE e.student_id = $1
       ORDER BY
         CASE tt.day
           WHEN 'Monday' THEN 1 WHEN 'Tuesday' THEN 2 WHEN 'Wednesday' THEN 3
           WHEN 'Thursday' THEN 4 WHEN 'Friday' THEN 5 WHEN 'Saturday' THEN 6
           WHEN 'Sunday' THEN 7 END, tt.time`,
      [studentId], (err, result) => res.json(result || [])
    );
  });
});

app.get("/student/my-announcements", verifyStudentToken, (req, res) => {
  getStudentId(req.student.id, (studentId) => {
    if (!studentId) return res.json([]);
    db.query(
      `SELECT DISTINCT
              ta.id, ta.teacher_id, ta.course_id,
              ta.title, ta.message, ta.created_at,
              c.name AS "courseName",
              teach.name AS "teacherName"
       FROM teacher_announcements ta
       LEFT JOIN courses c ON ta.course_id = c.id
       LEFT JOIN teachers teach ON ta.teacher_id = teach.id
       WHERE ta.course_id IN (
           SELECT course_id FROM enrollments WHERE student_id = $1
       )
       UNION
       SELECT
              ta2.id, ta2.teacher_id, ta2.course_id,
              ta2.title, ta2.message, ta2.created_at,
              NULL AS "courseName",
              teach2.name AS "teacherName"
       FROM teacher_announcements ta2
       LEFT JOIN teachers teach2 ON ta2.teacher_id = teach2.id
       WHERE ta2.course_id IS NULL
       ORDER BY created_at DESC`,
      [studentId], (err, result) => res.json(result || [])
    );
  });
});

app.get("/student/my-assignments", verifyStudentToken, (req, res) => {
  getStudentId(req.student.id, (studentId) => {
    if (!studentId) return res.json([]);
    db.query(
      `SELECT ta.id, ta.teacher_id, ta.course_id,
              ta.title, ta.description, ta.deadline, ta.max_marks, ta.created_at,
              c.name AS "courseName",
              t.name AS "teacherName"
       FROM teacher_assignments ta
       JOIN courses c ON ta.course_id = c.id
       LEFT JOIN teachers t ON ta.teacher_id = t.id
       WHERE ta.course_id IN (
         SELECT course_id FROM enrollments WHERE student_id = $1
       )
       ORDER BY ta.created_at DESC`,
      [studentId], (err, result) => res.json(result || [])
    );
  });
});

app.get("/student/my-materials", verifyStudentToken, (req, res) => {
  getStudentId(req.student.id, (studentId) => {
    if (!studentId) return res.json([]);
    db.query(
      `SELECT tm.id, tm.teacher_id, tm.course_id,
              tm.title, tm.type, tm.url, tm.created_at,
              c.name AS "courseName",
              t.name AS "teacherName"
       FROM teacher_materials tm
       JOIN courses c ON tm.course_id = c.id
       LEFT JOIN teachers t ON tm.teacher_id = t.id
       WHERE tm.course_id IN (
         SELECT course_id FROM enrollments WHERE student_id = $1
       )
       ORDER BY tm.created_at DESC`,
      [studentId], (err, result) => res.json(result || [])
    );
  });
});

app.get("/student/profile", verifyStudentToken, (req, res) => {
  db.query(
    `SELECT sa.id, sa.name, sa.email, sa.username, sa.student_id,
            s.course, s.id AS "rollNo"
     FROM student_accounts sa
     LEFT JOIN students s ON sa.student_id = s.id
     WHERE sa.id = $1`,
    [req.student.id],
    (err, result) => {
      if (err || !result || result.length === 0)
        return res.json({ success: false, message: "Profile not found." });
      res.json({ success: true, student: result[0] });
    }
  );
});

/* ================= START ================= */
module.exports=app;