
require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");

const app = express();

const allowedOrigins = (process.env.ALLOWED_ORIGINS || process.env.FRONTEND_URL || "http://localhost:8080")
    .split(",").map((origin) => origin.trim()).filter(Boolean);
app.use(cors({
    origin(origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
        return callback(new Error("Origin is not allowed by CORS"));
    },
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Device-Api-Key"]
}));
app.use(express.json({ limit: "1mb" }));

const JWT_SECRET = process.env.JWT_SECRET;
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: { message: "Too many authentication attempts. Please try again later." }
});
app.use(["/api/login", "/api/signup", "/api/forgot-password", "/api/reset-password"], authLimiter);

// Protect API routes by default. Login, signup and password-reset routes remain public.
// Hardware requests use a separate secret and do not accept student-supplied identity claims.
app.use("/api", (req, res, next) => {
    const publicPaths = ["/signup", "/login", "/forgot-password", "/reset-password"];
    if (req.method === "OPTIONS" || publicPaths.includes(req.path)) return next();

    if (req.path === "/kiosk/scan") {
        const configuredKey = process.env.KIOSK_API_KEY;
        if (!configuredKey || req.get("X-Device-Api-Key") !== configuredKey) {
            return res.status(401).json({ message: "Unauthorized kiosk device." });
        }
        req.isAuthorizedDevice = true;
        return next();
    }

    if (!JWT_SECRET) {
        return res.status(503).json({ message: "Server authentication is not configured. Set JWT_SECRET." });
    }
    const header = req.get("Authorization") || "";
    const match = header.match(/^Bearer\s+(.+)$/i);
    if (!match) return res.status(401).json({ message: "Authentication required." });

    try {
        req.auth = jwt.verify(match[1], JWT_SECRET);
    } catch (error) {
        return res.status(401).json({ message: "Session is invalid or expired. Please log in again." });
    }

    const adminOnly =
        (req.method === "PUT" && /^\/equipment\/\d+$/.test(req.path)) ||
        (req.method === "POST" && req.path === "/equipment") ||
        (req.method === "GET" && ["/complaints", "/transactions"].includes(req.path)) ||
        (req.method === "PUT" && /^\/complaints\/\d+\/resolve$/.test(req.path)) ||
        req.path.startsWith("/admin/");

    if (adminOnly && String(req.auth.role).toLowerCase() !== "admin") {
        return res.status(403).json({ message: "Administrator access required." });
    }

    const userTransactions = req.path.match(/^\/transactions\/user\/(\d+)$/);
    if (userTransactions &&
        Number(userTransactions[1]) !== Number(req.auth.user_id) &&
        String(req.auth.role).toLowerCase() !== "admin") {
        return res.status(403).json({ message: "You cannot access another user's transactions." });
    }
    next();
});

// Nodemailer Gmail Setup
const EMAIL_USER = process.env.EMAIL_USER || "";
const EMAIL_PASS = process.env.EMAIL_PASS || "";

let transporter = null;

if (EMAIL_USER && EMAIL_PASS && EMAIL_USER !== "your-gmail@gmail.com") {
    transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: EMAIL_USER,
            pass: EMAIL_PASS
        }
    });
    console.log("Nodemailer Gmail Transporter configured for:", EMAIL_USER);
}

// MySQL connection
const db = mysql.createConnection({
    host: process.env.MYSQLHOST || process.env.DB_HOST || "127.0.0.1",
    user: process.env.MYSQLUSER || process.env.DB_USER || "root",
    password: process.env.MYSQLPASSWORD || process.env.DB_PASSWORD || "",
    database: process.env.MYSQLDATABASE || process.env.DB_NAME || "lems_db",
    port: Number(process.env.MYSQLPORT || process.env.DB_PORT || 3306)
});

// Connect to MySQL
db.connect((err) => {
    if (err) {
        console.error("MySQL connection failed:", err.message);
    } else {
        console.log("MySQL connected successfully!");

        // Ensure reset_token and reset_token_expires columns exist in users table
        db.query("ALTER TABLE users ADD COLUMN reset_token VARCHAR(255) NULL, ADD COLUMN reset_token_expires DATETIME NULL", (err) => {
            // Ignore error if columns already exist
        });

        // Ensure complaints table exists
        const createComplaintsTableSql = `
            CREATE TABLE IF NOT EXISTS complaints (
                complaint_id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NULL,
                equipment_id INT NULL,
                issue_description TEXT NOT NULL,
                status VARCHAR(50) DEFAULT 'PENDING',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `;
        db.query(createComplaintsTableSql, (err) => {
            if (err) console.error("Could not create complaints table:", err.message);
        });

        // Ensure total_quantity and available_quantity columns exist in equipment table
        db.query("ALTER TABLE equipment ADD COLUMN total_quantity INT DEFAULT 50, ADD COLUMN available_quantity INT DEFAULT 50", (err) => {
            db.query("UPDATE equipment SET total_quantity = 50 WHERE total_quantity IS NULL OR total_quantity = 0");
            db.query("UPDATE equipment SET available_quantity = 50 WHERE available_quantity IS NULL");
            db.query("UPDATE equipment SET status = 'AVAILABLE' WHERE available_quantity > 0 AND status NOT IN ('MAINTENANCE', 'LOST')");
        });

        // Optional secure first-admin bootstrap; never create a predictable default password.
        const bootstrapPassword = process.env.BOOTSTRAP_ADMIN_PASSWORD;
        const bootstrapId = process.env.BOOTSTRAP_ADMIN_ID;
        const bootstrapEmail = process.env.BOOTSTRAP_ADMIN_EMAIL;
        if (bootstrapPassword && bootstrapId && bootstrapEmail) {
            db.query("SELECT user_id FROM users WHERE LOWER(role) = 'admin' LIMIT 1", (adminErr, admins) => {
                if (!adminErr && admins.length === 0) {
                    bcrypt.hash(bootstrapPassword, 12).then((passwordHash) => {
                        db.query(
                            "INSERT INTO users (name, student_id, email, password, role) VALUES (?, ?, ?, ?, 'admin')",
                            [process.env.BOOTSTRAP_ADMIN_NAME || "Lab Admin", bootstrapId, bootstrapEmail, passwordHash],
                            (insertErr) => {
                                if (insertErr) console.error("Admin bootstrap failed:", insertErr.message);
                                else console.log("Bootstrap administrator created from environment configuration.");
                            }
                        );
                    }).catch((hashErr) => console.error("Admin password hashing failed:", hashErr.message));
                }
            });
        }
    }
});

// Home API
app.get("/", (req, res) => {
    res.send("LEMS Backend API is running");
});

// Get all equipment
app.get("/api/equipment", (req, res) => {
    db.query("SELECT * FROM equipment", (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }

        res.json(results);
    });
});

app.put("/api/equipment/:id", (req, res) => {
    const { id } = req.params;
    const {
        equipment_code,
        name,
        category,
        rfid_tag,
        status,
        calibration_limit
    } = req.body;

    const allowedStatuses = [
        "AVAILABLE",
        "IN_USE",
        "MAINTENANCE",
        "LOST"
    ];

    if (!equipment_code || !name || !category || !rfid_tag) {
        return res.status(400).json({
            message: "Please fill in all required fields."
        });
    }

    if (!allowedStatuses.includes(status)) {
        return res.status(400).json({
            message: "Invalid equipment status."
        });
    }

    const sql = `
        UPDATE equipment
        SET equipment_code = ?,
            name = ?,
            category = ?,
            rfid_tag = ?,
            status = ?,
            calibration_limit = ?
        WHERE equipment_id = ?
    `;

    const values = [
        equipment_code,
        name,
        category,
        rfid_tag,
        status,
        calibration_limit || 500,
        id
    ];

    db.query(sql, values, (error, result) => {
        if (error) {
            console.error("Update equipment error:", error);
            return res.status(500).json({
                message: "Could not update equipment."
            });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({
                message: "Equipment not found."
            });
        }

        res.json({
            message: "Equipment updated successfully!"
        });
    });
});

// Sign Up / Registration API
app.post("/api/signup", (req, res) => {
    const { name, student_id, email, password, role } = req.body;

    if (!name || !student_id || !email || !password) {
        return res.status(400).json({
            message: "Name, Student ID, Email, and Password are required."
        });
    }

    // Public sign-up can only create student accounts. Admins are provisioned separately.
    const userRole = "student";
    if (String(password).length < 8) {
        return res.status(400).json({ message: "Password must be at least 8 characters long." });
    }

    // Check if student_id or email already exists
    const checkSql = "SELECT user_id FROM users WHERE student_id = ? OR email = ?";
    db.query(checkSql, [student_id.trim(), email.trim()], (err, results) => {
        if (err) {
            console.error("Signup check error:", err.message);
            return res.status(500).json({ error: err.message });
        }

        if (results.length > 0) {
            return res.status(400).json({
                message: "User with this Student ID or Email already exists."
            });
        }

        // Insert new user into database
        const insertSql = `
            INSERT INTO users (name, student_id, email, password, role)
            VALUES (?, ?, ?, ?, ?)
        `;

        bcrypt.hash(password, 12).then((passwordHash) => {
            db.query(insertSql, [name.trim(), student_id.trim(), email.trim(), passwordHash, userRole], (err) => {
                if (err) {
                    console.error("Signup insert error:", err.message);
                    return res.status(500).json({ message: "Could not create account." });
                }
                res.status(201).json({ message: "Account created successfully! You can now log in." });
            });
        }).catch((hashErr) => {
            console.error("Signup password hashing error:", hashErr.message);
            res.status(500).json({ message: "Could not create account." });
        });
    });
});

app.post("/api/login", (req, res) => {
    const { student_id, password } = req.body;

    if (!student_id || !password) {
        return res.status(400).json({
            message: "Student ID and password are required"
        });
    }

    if (!JWT_SECRET) {
        return res.status(503).json({ message: "Server authentication is not configured. Set JWT_SECRET." });
    }
    const sql = "SELECT user_id, name, student_id, email, role, password FROM users WHERE student_id = ?";
    db.query(sql, [student_id.trim()], async (err, results) => {
        if (err) return res.status(500).json({ message: "Login failed." });
        if (results.length === 0) {
            return res.status(401).json({ message: "Invalid student ID or password" });
        }

        const account = results[0];
        try {
            const stored = String(account.password || "");
            const isHash = /^\$2[aby]\$/.test(stored);
            const valid = isHash ? await bcrypt.compare(password, stored) : stored === password;
            if (!valid) return res.status(401).json({ message: "Invalid student ID or password" });

            // Upgrade legacy plaintext passwords on successful login without forcing a reset.
            if (!isHash) {
                const upgradedHash = await bcrypt.hash(password, 12);
                db.query("UPDATE users SET password = ? WHERE user_id = ?", [upgradedHash, account.user_id]);
            }

            const user = {
                user_id: account.user_id,
                name: account.name,
                student_id: account.student_id,
                email: account.email,
                role: account.role
            };
            const token = jwt.sign(user, JWT_SECRET, { expiresIn: "2h", issuer: "lems-api" });
            res.json({ message: "Login successful", user, token, expiresIn: 7200 });
        } catch (verifyError) {
            console.error("Login verification error:", verifyError.message);
            res.status(500).json({ message: "Login failed." });
        }
    });
});

// Forgot Password API - Generates reset link & sends real email
app.post("/api/forgot-password", (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ message: "Email is required." });
    }

    const checkSql = "SELECT user_id, name, email FROM users WHERE email = ?";
    db.query(checkSql, [email.trim()], (err, users) => {
        if (err) {
            console.error("Forgot password SQL error:", err);
            return res.status(500).json({ error: err.message });
        }

        if (users.length === 0) {
            return res.json({ message: "If an account exists for that email, a password reset link will be sent." });
        }

        const user = users[0];
        const token = crypto.randomBytes(20).toString("hex");
        // Expires in 1 hour
        const expires = new Date(Date.now() + 3600000);

        const updateSql = "UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE user_id = ?";
        db.query(updateSql, [token, expires, user.user_id], (err) => {
            if (err) {
                console.error("Token save error:", err);
                return res.status(500).json({ error: err.message });
            }

            const frontendUrl = (process.env.FRONTEND_URL || "http://localhost:8080").split(",")[0].trim().replace(/\/$/, "");
            const resetLink = `${frontendUrl}/reset-password.html?token=${token}`;

            // Send real email if Gmail credentials are provided
            if (transporter) {
                const mailOptions = {
                    from: `"LEMS System" <${EMAIL_USER}>`,
                    to: user.email,
                    subject: "LEMS - Password Reset Request",
                    html: `
                        <div style="font-family: Arial, sans-serif; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
                            <h2 style="color: #1976d2;">LEMS - Password Reset Request</h2>
                            <p>Hello <strong>${String(user.name || "User")}</strong>,</p>
                            <p>You requested to reset your password for your LEMS account.</p>
                            <p>Click the button below to reset your password (link expires in 1 hour):</p>
                            <p style="margin: 20px 0;">
                                <a href="${resetLink}" style="display: inline-block; padding: 12px 24px; background-color: #1976d2; color: white; text-decoration: none; border-radius: 6px; font-weight: bold;">
                                    Reset Password
                                </a>
                            </p>
                            <p style="color: #666; font-size: 13px;">Or copy and paste this URL into your browser:</p>
                            <p style="color: #1976d2; font-size: 13px;">${resetLink}</p>
                            <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                            <p style="font-size: 12px; color: #999;">If you did not request a password reset, please ignore this email.</p>
                        </div>
                    `
                };

                transporter.sendMail(mailOptions, (mailErr, info) => {
                    if (mailErr) {
                        console.error("Nodemailer Email delivery error:", mailErr.message);
                    } else {
                        console.log("Real email sent to:", user.email, "| Status:", info.response);
                    }
                });
            }

            res.json({
                message: "If an account exists for that email, a password reset link will be sent."
            });
        });
    });
});

// Reset Password API - Updates password using token
app.post("/api/reset-password", (req, res) => {
    const { token, new_password } = req.body;

    if (!token || !new_password) {
        return res.status(400).json({ message: "Token and new password are required." });
    }

    const checkSql = "SELECT user_id, reset_token_expires FROM users WHERE reset_token = ?";
    db.query(checkSql, [token.trim()], (err, users) => {
        if (err) {
            console.error("Reset password check error:", err);
            return res.status(500).json({ error: err.message });
        }

        if (users.length === 0) {
            return res.status(400).json({ message: "Invalid or unrecognized password reset token." });
        }

        const user = users[0];

        // Expiration check in JS to prevent MySQL timezone mismatches
        if (!user.reset_token_expires || new Date(user.reset_token_expires).getTime() <= Date.now()) {
            return res.status(400).json({ message: "Password reset link has expired. Please request a new one." });
        }

        if (String(new_password).length < 8) {
            return res.status(400).json({ message: "New password must be at least 8 characters long." });
        }
        const userId = user.user_id;
        bcrypt.hash(new_password, 12).then((passwordHash) => {
            const updateSql = "UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE user_id = ?";
            db.query(updateSql, [passwordHash, userId], (err) => {
            if (err) {
                console.error("Password update error:", err);
                return res.status(500).json({ error: err.message });
            }

                res.json({ message: "Password reset successful! You can now log in with your new password." });
            });
        }).catch((hashErr) => {
            console.error("Password reset hashing error:", hashErr.message);
            res.status(500).json({ message: "Could not reset password." });
        });
    });
});

// Submit Complaint / Maintenance Request API (Student Side)
app.post("/api/complaints", (req, res) => {
    console.log("POST /api/complaints received body:", req.body);
    const { equipment_id, issue_description } = req.body;
    const user_id = req.auth.user_id;

    if (!user_id || !equipment_id || !issue_description) {
        return res.status(400).json({ message: "User ID, Equipment ID, and Issue Description are required." });
    }

    const insertSql = `
        INSERT INTO complaints (user_id, equipment_id, issue_description, status)
        VALUES (?, ?, ?, 'PENDING')
    `;

    db.query(insertSql, [user_id, equipment_id, issue_description.trim()], (err, result) => {
        if (err) {
            console.error("Submit complaint error:", err.message);
            return res.status(500).json({ error: err.message });
        }

        // Update equipment status to MAINTENANCE
        db.query("UPDATE equipment SET status = 'MAINTENANCE' WHERE equipment_id = ?", [equipment_id], (err) => {
            if (err) console.error("Error updating equipment status to MAINTENANCE:", err.message);
        });

        res.status(201).json({
            message: "Maintenance complaint submitted successfully! Equipment marked for review."
        });
    });
});

// Get All Complaints API (Admin Side)
app.get("/api/complaints", (req, res) => {
    const sql = `
        SELECT
            c.complaint_id,
            c.issue_description,
            c.status AS complaint_status,
            c.created_at,
            u.name AS student_name,
            u.student_id,
            e.equipment_id,
            e.equipment_code,
            e.name AS equipment_name,
            e.status AS equipment_status
        FROM complaints c
        LEFT JOIN users u ON c.user_id = u.user_id
        LEFT JOIN equipment e ON c.equipment_id = e.equipment_id
        ORDER BY c.complaint_id DESC
    `;

    db.query(sql, (err, results) => {
        if (err) {
            console.error("Get complaints warning:", err.message);
            // Return empty list safely if table doesn't exist yet
            return res.json([]);
        }

        res.json(results);
    });
});

// Resolve Complaint API (Admin Side)
app.put("/api/complaints/:id/resolve", (req, res) => {
    const complaintId = req.params.id;
    const { equipment_id, make_available } = req.body;

    const updateSql = "UPDATE complaints SET status = 'RESOLVED' WHERE complaint_id = ?";
    db.query(updateSql, [complaintId], (err, result) => {
        if (err) {
            console.error("Resolve complaint error:", err.message);
            return res.status(500).json({ error: err.message });
        }

        if (make_available !== false && equipment_id) {
            db.query("UPDATE equipment SET status = 'AVAILABLE' WHERE equipment_id = ?", [equipment_id], (err) => {
                if (err) console.error("Error restoring equipment status to AVAILABLE:", err.message);
            });
        }

        res.json({ message: "Complaint resolved and equipment status updated!" });
    });
});

// Checkout equipment API
app.post("/api/checkout", (req, res) => {
    const { equipment_id } = req.body;
    const user_id = req.auth.user_id;

    if (!user_id || !equipment_id) {
        return res.status(400).json({
            message: "User ID and equipment ID are required"
        });
    }

    // Check student exists
    db.query(
        "SELECT user_id FROM users WHERE user_id = ?",
        [user_id],
        (err, users) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            if (users.length === 0) {
                return res.status(404).json({
                    message: "Student not found. Please log in again."
                });
            }

            // Check if user already has an active checkout for this equipment
            db.query(
                "SELECT transaction_id FROM transactions WHERE user_id = ? AND equipment_id = ? AND status = 'ACTIVE'",
                [user_id, equipment_id],
                (err, activeTxs) => {
                    if (err) {
                        return res.status(500).json({ error: err.message });
                    }

                    if (activeTxs.length > 0) {
                        return res.status(400).json({
                            message: "You already have an active checkout for this equipment. You must return it first."
                        });
                    }

                    // Check equipment availability and quantity
                    db.query(
                        "SELECT status, COALESCE(available_quantity, 50) AS available_quantity, COALESCE(total_quantity, 50) AS total_quantity FROM equipment WHERE equipment_id = ?",
                        [equipment_id],
                        (err, equipment) => {
                            if (err) {
                                return res.status(500).json({ error: err.message });
                            }

                            if (equipment.length === 0) {
                                return res.status(404).json({
                                    message: "Equipment not found"
                                });
                            }

                            const eq = equipment[0];
                            if (eq.status === "MAINTENANCE" || eq.status === "LOST" || eq.available_quantity <= 0) {
                                return res.status(400).json({
                                    message: "Equipment is out of stock or under maintenance."
                                });
                            }

                            // Record checkout
                            db.query(
                                `INSERT INTO transactions
                                 (user_id, equipment_id, status)
                                 VALUES (?, ?, 'ACTIVE')`,
                                [user_id, equipment_id],
                                (err, result) => {
                                    if (err) {
                                        return res.status(500).json({ error: err.message });
                                    }

                                    // Decrement available_quantity and set status to OUT_OF_STOCK if 0
                                    db.query(
                                        `UPDATE equipment
                                         SET available_quantity = GREATEST(0, COALESCE(available_quantity, 50) - 1),
                                             status = CASE WHEN (COALESCE(available_quantity, 50) - 1) <= 0 THEN 'OUT_OF_STOCK' ELSE 'AVAILABLE' END
                                         WHERE equipment_id = ?`,
                                        [equipment_id],
                                        (err, updateResult) => {
                                            if (err) {
                                                db.query(
                                                    `DELETE FROM transactions WHERE transaction_id = ?`,
                                                    [result.insertId]
                                                );
                                                return res.status(500).json({ error: err.message });
                                            }

                                            res.json({
                                                message: "Equipment checked out successfully",
                                                transaction_id: result.insertId
                                            });
                                        }
                                    );
                                }
                            );
                        }
                    );
                }
            );
        }
    );
});

// Return equipment API
app.post("/api/return", (req, res) => {
    const { equipment_id } = req.body;

    if (!equipment_id) {
        return res.status(400).json({
            message: "Equipment ID is required"
        });
    }

    const sql = `
        SELECT transaction_id
        FROM transactions
        WHERE equipment_id = ?
          AND user_id = ?
          AND status = 'ACTIVE'
        ORDER BY checkout_time DESC
        LIMIT 1
    `;

    db.query(sql, [equipment_id, req.auth.user_id], (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }

        if (results.length === 0) {
            return res.status(400).json({
                message: "No active checkout found"
            });
        }

        const transactionId = results[0].transaction_id;

        db.query(
            `UPDATE transactions
             SET status = 'RETURNED', return_time = NOW()
             WHERE transaction_id = ? AND status = 'ACTIVE'`,
            [transactionId],
            (err, result) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }

                if (result.affectedRows === 0) {
                    return res.status(409).json({
                        message: "This transaction has already been returned"
                    });
                }

                // Increment available_quantity and set status to AVAILABLE
                db.query(
                    `UPDATE equipment
                     SET available_quantity = LEAST(COALESCE(total_quantity, 50), COALESCE(available_quantity, 0) + 1),
                         status = 'AVAILABLE'
                     WHERE equipment_id = ?`,
                    [equipment_id],
                    (err, updateResult) => {
                        if (err) {
                            return res.status(500).json({ error: err.message });
                        }

                        res.json({
                            message: "Equipment returned successfully"
                        });
                    }
                );
            }
        );
    });
});

// RFID Kiosk Scan API (ESP32 Hardware Integration)
app.post("/api/kiosk/scan", (req, res) => {
    const { student_rfid, equipment_rfid } = req.body;

    if (!student_rfid || !equipment_rfid) {
        return res.status(400).json({ message: "Student RFID and Equipment RFID are required." });
    }

    db.query("SELECT user_id, name, student_id FROM users WHERE rfid_uid = ?", [student_rfid.trim()], (err, users) => {
        if (err) return res.status(500).json({ error: err.message });
        if (users.length === 0) {
            return res.status(404).json({ message: "Student RFID card not registered." });
        }

        const user = users[0];

        db.query("SELECT equipment_id, equipment_code, name, status, available_quantity FROM equipment WHERE rfid_tag = ?", [equipment_rfid.trim()], (err, equipmentList) => {
            if (err) return res.status(500).json({ error: err.message });
            if (equipmentList.length === 0) {
                return res.status(404).json({ message: "Equipment RFID tag not found." });
            }

            const equipment = equipmentList[0];

            db.query("SELECT transaction_id FROM transactions WHERE user_id = ? AND equipment_id = ? AND status = 'ACTIVE'", [user.user_id, equipment.equipment_id], (err, activeTxs) => {
                if (err) return res.status(500).json({ error: err.message });

                if (activeTxs.length > 0) {
                    // PROCESS RETURN
                    const transactionId = activeTxs[0].transaction_id;
                    db.query("UPDATE transactions SET status = 'RETURNED', return_time = NOW() WHERE transaction_id = ?", [transactionId], (err) => {
                        if (err) return res.status(500).json({ error: err.message });

                        db.query("UPDATE equipment SET available_quantity = LEAST(COALESCE(total_quantity, 50), COALESCE(available_quantity, 0) + 1), status = 'AVAILABLE' WHERE equipment_id = ?", [equipment.equipment_id], (err) => {
                            if (err) return res.status(500).json({ error: err.message });

                            res.json({
                                action: "RETURN",
                                message: `Return successful for ${user.name} (${equipment.name})`
                            });
                        });
                    });
                } else {
                    // PROCESS CHECKOUT
                    if (equipment.status === "MAINTENANCE" || equipment.status === "LOST" || (equipment.available_quantity ?? 50) <= 0) {
                        return res.status(400).json({ message: "Equipment is out of stock or under maintenance." });
                    }

                    db.query("INSERT INTO transactions (user_id, equipment_id, status) VALUES (?, ?, 'ACTIVE')", [user.user_id, equipment.equipment_id], (err, result) => {
                        if (err) return res.status(500).json({ error: err.message });

                        db.query(
                            `UPDATE equipment
                             SET available_quantity = GREATEST(0, COALESCE(available_quantity, 50) - 1),
                                 status = CASE WHEN (COALESCE(available_quantity, 50) - 1) <= 0 THEN 'OUT_OF_STOCK' ELSE 'AVAILABLE' END
                             WHERE equipment_id = ?`,
                            [equipment.equipment_id],
                            (err) => {
                                if (err) return res.status(500).json({ error: err.message });

                                res.json({
                                    action: "CHECKOUT",
                                    message: `Checkout successful for ${user.name} (${equipment.name})`
                                });
                            }
                        );
                    });
                }
            });
        });
    });
});

// Get active checkouts for a specific user
app.get("/api/transactions/user/:user_id", (req, res) => {
    const userId = req.params.user_id;
    const sql = `
        SELECT transaction_id, equipment_id, checkout_time, status
        FROM transactions
        WHERE user_id = ? AND status = 'ACTIVE'
    `;
    db.query(sql, [userId], (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(results);
    });
});

// Transaction history API
app.get("/api/transactions", (req, res) => {
    console.log("API /api/transactions requested");
    const sql = `
        SELECT
            t.transaction_id,
            u.name AS student_name,
            u.student_id,
            e.equipment_code,
            e.name AS equipment_name,
            t.checkout_time,
            t.return_time,
            t.status
        FROM transactions t
        LEFT JOIN users u ON t.user_id = u.user_id
        LEFT JOIN equipment e ON t.equipment_id = e.equipment_id
        ORDER BY t.transaction_id DESC
    `;

    db.query(sql, (err, results) => {
        if (err) {
            console.error("Database error in /api/transactions:", err.message);
            return res.status(500).json({ error: err.message });
        }

        console.log(`Found ${results.length} transactions`);
        res.json(results);
    });
});

// Admin API: Get student account details & transaction history by student_id
app.get("/api/admin/student/:student_id", (req, res) => {
    const studentId = req.params.student_id;

    const userSql = "SELECT user_id, name, student_id, email, role FROM users WHERE student_id = ?";

    db.query(userSql, [studentId], (err, users) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }

        if (users.length === 0) {
            return res.status(404).json({ message: "Student not found with ID: " + studentId });
        }

        const user = users[0];

        const txSql = `
            SELECT
                t.transaction_id,
                e.equipment_id,
                e.equipment_code,
                e.name AS equipment_name,
                t.checkout_time,
                t.return_time,
                t.status
            FROM transactions t
            LEFT JOIN equipment e ON t.equipment_id = e.equipment_id
            WHERE t.user_id = ?
            ORDER BY t.transaction_id DESC
        `;

        db.query(txSql, [user.user_id], (err, transactions) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            res.json({
                student: user,
                transactions: transactions
            });
        });
    });
});

// Start server — keep this at the bottom
const PORT = Number(process.env.PORT) || 3000;

app.post("/api/equipment", (req, res) => {
    const {
        equipment_code,
        name,
        category,
        rfid_tag,
        calibration_limit
    } = req.body;

    if (
        !equipment_code ||
        !name ||
        !category ||
        !rfid_tag
    ) {
        return res.status(400).json({
            message: "Please fill in all required fields."
        });
    }

    const sql = `
        INSERT INTO equipment
        (equipment_code, name, category, rfid_tag,
         status, runtime_hours, calibration_limit)
        VALUES (?, ?, ?, ?, 'AVAILABLE', 0, ?)
    `;

    const values = [
        equipment_code,
        name,
        category,
        rfid_tag,
        calibration_limit || 500
    ];

    db.query(sql, values, (error, result) => {
        if (error) {
            console.error("Add equipment error:", error);

            if (error.code === "ER_DUP_ENTRY") {
                return res.status(409).json({
                    message:
                        "Equipment code or RFID tag already exists."
                });
            }

            return res.status(500).json({
                message: "Could not add equipment."
            });
        }

        res.status(201).json({
            message: "Equipment added successfully!",
            equipment_id: result.insertId
        });
    });
});
app.listen(PORT, () => {
    console.log(`LEMS API running on port ${PORT}`);
});