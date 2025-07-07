const express = require("express");
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const base64url = require("base64url");
const cron = require("node-cron");
const path = require("path");
const fs = require("fs").promises;
const multer = require("multer");
const XLSX = require("xlsx");
const router = express.Router();
const app = express();
const port = 3005;
const SALT_ROUNDS = 10;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = "1h";

// app.use(cors({ origin: "*" })); // Allow all origins for testing

app.use(cors({
 origin: "*",
 exposedHeaders: ['Content-Disposition']
}));

app.use(express.json());

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied, no token provided" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ error: "Invalid token" });
  }
};

const adminauthenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  console.log("Auth Header:", authHeader);
  console.log("Token:", token);
  if (!token) {
    return res.status(401).json({ error: "Token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, admin) => {
    console.log("JWT Verify Error:", err);
    console.log("Decoded Admin:", admin);
    if (err) {
      return res.status(403).json({ error: "Invalid or expired token" });
    }
    if (!admin || !admin.id) {
      return res.status(403).json({ error: "Invalid token payload" });
    }
    req.admin = admin;
    next();
  });
};

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: "sssdemo6@gmail.com",
    pass: "qhxc jbqc kami owim",
  },
});

// Serve uploads directory statically from public_html/uploads
app.use(
  "/uploads",
  express.static(path.join(__dirname, "../../public_html/uploads"))
);
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Multer storage configuration
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const uploadDir = path.join(__dirname, "../../public_html/uploads");
    try {
      await fs.mkdir(uploadDir, { recursive: true });
      cb(null, uploadDir);
    } catch (err) {
      console.error("Multer destination error:", err);
      cb(err);
    }
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(
      null,
      `${Date.now()}-${Math.random().toString(36).substring(2, 9)}${ext}`
    );
  },
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|mp4/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(
      path.extname(file.originalname).toLowerCase()
    );
    if (mimetype && extname) return cb(null, true);
    cb(new Error("Invalid file type. Only JPEG, PNG, and MP4 allowed."));
  },
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB limit
});

// Generate invoice number
const generateInvoiceNumber = async () => {
  const [rows] = await pool.query("SELECT COUNT(*) as count FROM invoices");
  const count = rows[0].count + 1;
  return `INV-${String(count).padStart(4, "0")}`;
};

//---------------------------------Customer ApI---------------------------------

//Signup API

app.post("/api/signup", async (req, res) => {
  const {
    userType,
    fullName,
    email,
    password,
    confirmPassword,
    businessName,
    taxId,
    phone,
    address,
    agreeTerms,
  } = req.body;

  // Validation
  if (!userType || !["customer", "vendor"].includes(userType)) {
    return res.status(400).json({ error: "Invalid user type" });
  }
  if (!fullName || !email || !password || !confirmPassword) {
    return res.status(400).json({ error: "Missing required fields" });
  }
  if (password !== confirmPassword) {
    return res.status(400).json({ error: "Passwords do not match" });
  }
  if (!agreeTerms) {
    return res.status(400).json({ error: "You must agree to the terms" });
  }
  if (userType === "vendor" && (!businessName || !taxId)) {
    return res
      .status(400)
      .json({ error: "Business name and tax ID are required for vendors" });
  }

  try {
    // Check if email already exists
    const [existingUsers] = await pool.query(
      "SELECT id FROM users WHERE email = ?",
      [email]
    );
    if (existingUsers.length > 0) {
      return res.status(400).json({ error: "Email already exists" });
    }

    // Check if email already exists for the same userType
    // const [existingUsers] = await pool.query(
    //   "SELECT id FROM users WHERE email = ? AND user_type = ?",
    //   [email, userType]
    // );

    // if (existingUsers.length > 0) {
    //   return res
    //     .status(400)
    //     .json({ error: `An account with this email already exists as a ${userType}.` });
    // }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Insert user into database
    const [result] = await pool.query(
      `INSERT INTO users (user_type, full_name, email, password, company_name, tax_id, phone, address, is_active, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
      [
        userType,
        fullName,
        email,
        hashedPassword,
        businessName || null,
        taxId || null,
        phone || null,
        address || null,
        0, // is_active = 0 (pending approval)
      ]
    );

    // Get the inserted user's ID
    const userId = result.insertId;

    // Send confirmation email to the user
    const userMailOptions = {
      from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
      to: email,
      subject: "Thank You for Signing Up with Studio Signature Cabinets!",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2>Hello, ${fullName}!</h2>
          <p>Thank you for signing up as a <strong>${userType}</strong> with Studio Signature Cabinets. Your account is currently <strong>pending approval</strong> by our admin team.</p>
          <p><strong>What happens next?</strong></p>
          <ul>
            <li>Our team will review your signup details within the next 1-2 business days.</li>
            <li>Once approved, you will receive a confirmation email with instructions to log in and access your account.</li>
            <li>If you have any urgent questions, please contact our support team at <a href="mailto:info@studiosignaturecabinets.com">info@studiosignaturecabinets.com</a>.</li>
          </ul>
          <h3>Your Signup Details:</h3>
          <ul style="list-style: none; padding: 0;">
            <li><strong>Full Name:</strong> ${fullName}</li>
            <li><strong>Email:</strong> ${email}</li>
            <li><strong>Phone:</strong> ${phone || "N/A"}</li>
            <li><strong>Address:</strong> ${address || "N/A"}</li>
            ${
              userType === "vendor"
                ? `
              <li><strong>Business Name:</strong> ${businessName}</li>
              <li><strong>Tax ID:</strong> ${taxId}</li>
            `
                : ""
            }
          </ul>
          <p>We’re excited to have you join our community! You’ll hear from us soon.</p>
          <p>Best regards,<br>Team Studio Signature Cabinets</p>
        </div>
      `,
    };

    // Send notification email to admin
    const adminMailOptions = {
      from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
      to: "aashish.shroff@zeta-v.com",
      subject: `New ${
        userType.charAt(0).toUpperCase() + userType.slice(1)
      } Signup Request - ${fullName}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2>New ${
            userType.charAt(0).toUpperCase() + userType.slice(1)
          } Signup Request</h2>
          <p>A new ${userType} has submitted a signup request on ${new Date().toLocaleDateString()}. Please review and approve or reject this user in the admin panel.</p>
          <h3>User Details:</h3>
          <ul style="list-style: none; padding: 0;">
            <li><strong>User ID:</strong> ${userId}</li>
            <li><strong>User Type:</strong> ${
              userType.charAt(0).toUpperCase() + userType.slice(1)
            }</li>
            <li><strong>Full Name:</strong> ${fullName}</li>
            <li><strong>Email:</strong> ${email}</li>
            <li><strong>Phone:</strong> ${phone || "N/A"}</li>
            <li><strong>Address:</strong> ${address || "N/A"}</li>
            ${
              userType === "vendor"
                ? `
              <li><strong>Business Name:</strong> ${businessName}</li>
              <li><strong>Tax ID:</strong> ${taxId}</li>
            `
                : ""
            }
            <li><strong>Signup Date:</strong> ${new Date().toLocaleDateString()}</li>
            <li><strong>Status:</strong> Pending Approval</li>
          </ul>
          <p><strong>Action Required:</strong> Please review this user and update their status in the admin panel.</p>
          <p style="text-align: center;">
            <a href="https://studiosignaturecabinets.com/admin/login" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Review User</a>
          </p>
          <p>For further details, check the admin panel or contact the user directly at ${email}.</p>
        </div>
      `,
    };

    // Send emails with error handling
    try {
      await Promise.all([
        transporter.sendMail(userMailOptions),
        transporter.sendMail(adminMailOptions),
      ]);
    } catch (emailErr) {
      console.error("Email sending failed:", emailErr);
      // Log error but don't fail signup
      res.status(201).json({
        message:
          "Account created successfully, but email sending failed. Please contact support.",
      });
      return;
    }

    // Respond success
    res.status(201).json({
      message:
        "Signup request submitted successfully. You will receive a confirmation email once your account is approved.",
    });
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Login API

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const [users] = await pool.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);

    if (users.length === 0) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const user = users[0];

    // Check if user is active
    if (!user.is_active) {
      return res.status(403).json({ error: "Account is inactive" });
    }
    if (!user.account_status || user.account_status !== "Active") {
      return res.status(403).json({ error: "Account is inactive" });
    }

    // Check if user is a customer
    if (user.user_type !== "customer") {
      return res.status(403).json({ error: "Only customers can log in" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    // Update last login
    await pool.query("UPDATE users SET last_login = NOW() WHERE id = ?", [
      user.id,
    ]);

    // Create JWT with token_version
    const token = jwt.sign(
      { id: user.id, email: user.email, token_version: user.token_version },
      JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        user_type: user.user_type,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/customer/logout
app.post("/api/customer/logout", authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    // Verify user is a customer
    const [users] = await pool.query(
      "SELECT user_type, token_version FROM users WHERE id = ?",
      [userId]
    );
    if (users.length === 0 || users[0].user_type !== "customer") {
      console.log(`Logout attempt failed: User ID ${userId} is not a vendor`);
      return res
        .status(403)
        .json({ error: "Only vendors can log out from this endpoint" });
    }

    // Increment token_version to invalidate existing tokens
    await pool.query(
      "UPDATE users SET token_version = token_version + 1 WHERE id = ?",
      [userId]
    );
    console.log(`User ID ${userId} logged out, token_version incremented`);

    // Add cache-control headers
    res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
    res.status(200).json({ message: "Logged out successfully" });
  } catch (err) {
    console.error("Logout error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// customer Token Verification API
app.get("/api/customer/verify", authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const tokenVersion = req.user.token_version;

  try {
    const [users] = await pool.query(
      "SELECT token_version, user_type FROM users WHERE id = ?",
      [userId]
    );
    if (users.length === 0 || users[0].user_type !== "customer") {
      return res.status(403).json({ error: "Invalid user" });
    }
    if (users[0].token_version !== tokenVersion) {
      return res.status(401).json({ error: "Token is invalid" });
    }
    res.status(200).json({ valid: true });
  } catch (err) {
    console.error("Token verification error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/logout
app.post("/api/logout", authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    // Increment token_version to invalidate existing tokens
    await pool.query(
      "UPDATE users SET token_version = token_version + 1 WHERE id = ?",
      [userId]
    );

    // Add cache-control headers
    res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
    res.status(200).json({ message: "Logged out successfully" });
  } catch (err) {
    console.error("Logout error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/verify-token", authenticateToken, async (req, res) => {
  res.json({ user: { id: req.user.id, email: req.user.email } });
});

// Get User Profile API

// app.get("/api/profile", authenticateToken, async (req, res) => {
//   try {
//     const userId = req.user.id;
//     const [users] = await pool.query(
//       "SELECT id, user_type, full_name, company_name, email, phone, address, account_status, last_login, admin_discount,created_at FROM users WHERE id = ?",
//       [userId]
//     );

//     if (users.length === 0) {
//       return res.status(404).json({ error: "User not found" });
//     }

//     res.json(users[0]);
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ error: "Server error" });
//   }
// });

app.get("/api/profile", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const [users] = await pool.query(
      "SELECT id, user_type, full_name, company_name, email, phone, address, account_status, last_login, admin_discount, created_at, notes FROM users WHERE id = ?",
      [userId]
    );

    if (users.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(users[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Update User Profile API
app.put("/api/profile", authenticateToken, async (req, res) => {
  const { full_name, email, phone, company_name, address } = req.body;
  const userId = req.user.id;

  try {
    // Validate input
    if (!full_name || !email) {
      return res
        .status(400)
        .json({ error: "Full name and email are required" });
    }

    // Check if email is already in use by another user
    const [existingUsers] = await pool.query(
      "SELECT id FROM users WHERE email = ? AND id != ?",
      [email, userId]
    );
    if (existingUsers.length > 0) {
      return res.status(400).json({ error: "Email is already in use" });
    }

    // Update user details
    await pool.query(
      `UPDATE users 
       SET full_name = ?, email = ?, phone = ?, company_name = ?, address = ?
       WHERE id = ?`,
      [
        full_name,
        email,
        phone || null,
        company_name || null,
        address || null,
        userId,
      ]
    );

    // Fetch updated user data
    const [updatedUsers] = await pool.query(
      "SELECT id, user_type, full_name, company_name, email, phone, address, account_status, last_login, created_at FROM users WHERE id = ?",
      [userId]
    );

    if (updatedUsers.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({
      message: "Profile updated successfully",
      user: updatedUsers[0],
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Change Password API

// PUT /api/password
app.put("/api/password", authenticateToken, async (req, res) => {
  const { currentPassword, newPassword, confirmPassword } = req.body;
  const userId = req.user.id;

  try {
    // Validate input
    if (!currentPassword || !newPassword || !confirmPassword) {
      return res
        .status(400)
        .json({ error: "All password fields are required" });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ error: "New passwords do not match" });
    }

    // Password validation regex
    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]).{8,}$/;
    if (!passwordRegex.test(newPassword) || /\s/.test(newPassword)) {
      return res.status(400).json({
        error:
          "Password must be at least 8 characters, include one uppercase, one lowercase, one number, one special character, and no spaces",
      });
    }

    // Fetch current user
    const [users] = await pool.query(
      "SELECT password, email, full_name FROM users WHERE id = ?",
      [userId]
    );
    if (users.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = users[0];

    // Verify current password
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Current password is incorrect" });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password
    await pool.query("UPDATE users SET password = ? WHERE id = ?", [
      hashedPassword,
      userId,
    ]);

    // Send confirmation email
    const mailOptions = {
      from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
      to: user.email,
      subject: "Password Change Confirmation",
      html: `
        <h3>Password Change Confirmation</h3>
        <p>Dear ${user.full_name || "User"},</p>
        <p>Your password was successfully changed on ${new Date().toLocaleString(
          "en-US",
          {
            timeZone: "Asia/Kolkata",
          }
        )} IST.</p>
        <p>If you did not perform this action, please contact our support team immediately at <a href="mailto:info@studiosignaturecabinets.com">info@studiosignaturecabinets.com</a>.</p>
        <p>Best regards,<br>Studio Signature Cabinets Team</p>
      `,
    };

    await transporter.sendMail(mailOptions);

    res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error("Error updating password:", err);
    res.status(500).json({ error: "Server error" });
  }
});

//place an order

async function generateOrderId(pool) {
  try {
    const [lastOrder] = await pool.query(
      "SELECT order_id FROM orders WHERE order_id LIKE 'S-ORD%' ORDER BY CAST(SUBSTRING(order_id, 7) AS UNSIGNED) DESC LIMIT 1"
    );

    let newOrderNumber = 101002;
    let newOrderId = null;

    if (lastOrder.length > 0) {
      const lastOrderId = lastOrder[0].order_id;
      if (lastOrderId && lastOrderId.startsWith("S-ORD")) {
        const numericPart = lastOrderId.slice(6);
        const parsedNumber = parseInt(numericPart, 10);
        if (!isNaN(parsedNumber) && parsedNumber >= 101002) {
          newOrderNumber = parsedNumber + 1;
        }
      }
    }

    newOrderId = `S-ORD${String(newOrderNumber).padStart(6, "0")}`;

    // Double-check ID does not already exist
    const [existingOrder] = await pool.query(
      "SELECT order_id FROM orders WHERE order_id = ?",
      [newOrderId]
    );
    if (existingOrder.length > 0) {
      newOrderNumber++;
      newOrderId = `S-ORD${String(newOrderNumber).padStart(6, "0")}`;
    }

    return newOrderId;
  } catch (err) {
    console.error("Error generating order ID:", err);
    return `S-ORD${String(101002).padStart(6, "0")}`;
  }
}

app.get("/api/orders/next-id", async (req, res) => {
  try {
    const nextOrderId = await generateOrderId(pool);
    res.status(200).json({ nextOrderId });
  } catch (err) {
    console.error("Error fetching next order ID:", err);
    res.status(500).json({ error: "Failed to fetch next order ID" });
  }
});

app.post("/api/orders", authenticateToken, async (req, res) => {
  const {
    doorStyle,
    finishType,
    stainOption,
    paintOption,
    account,
    billTo,
    items,
    subtotal,
    tax,
    shipping,
    total,
    discount,
  } = req.body;

  try {
    // Validations (same as your original)
    if (!items || !Array.isArray(items) || items.length === 0) {
      return res
        .status(400)
        .json({ error: "Items are required and must be a non-empty array" });
    }
    if (!subtotal || !tax || !total) {
      return res
        .status(400)
        .json({ error: "Subtotal, tax, and total are required" });
    }
    if (!doorStyle || !finishType || !account || !billTo) {
      return res.status(400).json({
        error: "Door style, finish type, account, and bill-to are required",
      });
    }
    if (finishType === "Stain" && !stainOption) {
      return res
        .status(400)
        .json({ error: "Stain option is required for stain finish" });
    }
    if (finishType === "Paint" && !paintOption) {
      return res
        .status(400)
        .json({ error: "Paint option is required for paint finish" });
    }

    const userId = req.user.id;

    // Get user info
    const [userResult] = await pool.query(
      "SELECT full_name, email, phone, admin_discount FROM users WHERE id = ?",
      [userId]
    );
    if (userResult.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const userFullName = userResult[0].full_name;
    const userEmail = userResult[0].email;
    const userPhone = userResult[0].phone || "N/A";
    const adminDiscount = parseFloat(userResult[0].admin_discount) || 0;

    // Validate discount
    const expectedDiscount = parseFloat((subtotal * adminDiscount).toFixed(2));
    if (
      discount === undefined ||
      parseFloat(discount.toFixed(2)) !== expectedDiscount
    ) {
      return res.status(400).json({
        error: `Invalid discount amount. Expected: ${expectedDiscount}, Received: ${discount}`,
      });
    }

    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // Insert order (without order_id)
      const [orderResult] = await connection.query(
        `INSERT INTO orders (
          user_id, door_style, finish_type, stain_option, paint_option, 
          account, bill_to, subtotal, tax, shipping, discount, total, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending', NOW())`,
        [
          userId,
          doorStyle,
          finishType,
          stainOption || null,
          paintOption || null,
          account,
          billTo,
          subtotal,
          tax,
          shipping !== undefined ? shipping : null,
          discount || 0,
          total,
        ]
      );

      const autoId = orderResult.insertId;

      // Generate order_id
      const orderId = `S-ORD${String(autoId + 101001).padStart(6, "0")}`;

      // Update order_id
      await connection.query(`UPDATE orders SET order_id = ? WHERE id = ?`, [
        orderId,
        autoId,
      ]);

      // Insert order items
      for (const item of items) {
        if (!item.sku || !item.name || !item.quantity || item.quantity < 1) {
          throw new Error(
            "Invalid item data: SKU, name, and valid quantity are required"
          );
        }

        await connection.query(
          `INSERT INTO order_items (order_id, sku, name, quantity, price, total_amount, door_style, finish)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            autoId,
            item.sku,
            item.name,
            item.quantity,
            item.price || null,
            item.totalAmount || null,
            doorStyle,
            finishType,
            // finishType === "Stain" ? stainOption : paintOption,
          ]
        );
      }

      await connection.commit();
      connection.release();

      // === Email template with detailed order info ===
      const orderDetailsHtml = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h3>Order Details</h3>
          <ul style="list-style: none; padding: 0;">
            <li><strong>Door Style:</strong> ${doorStyle}</li>
            <li><strong>Finish Type:</strong> ${finishType}</li>
            ${
              stainOption
                ? `<li><strong>Stain Option:</strong> ${stainOption}</li>`
                : ""
            }
            ${
              paintOption
                ? `<li><strong>Paint Option:</strong> ${paintOption}</li>`
                : ""
            }
            <li><strong>Ship To:</strong> ${account}</li>
            <li><strong>Bill To:</strong> ${billTo}</li>
          </ul>
          <h3>Items</h3>
          <table style="border-collapse: collapse; width: 100%;">
            <thead>
              <tr style="background-color: #f2f2f2;">
                <th style="border: 1px solid #ddd; padding: 8px;">SKU</th>
                <th style="border: 1px solid #ddd; padding: 8px;">Name</th>
                <th style="border: 1px solid #ddd; padding: 8px;">Quantity</th>
                <th style="border: 1px solid #ddd; padding: 8px;">Price ($)</th>
                <th style="border: 1px solid #ddd; padding: 8px;">Total ($)</th>
              </tr>
            </thead>
            <tbody>
              ${items
                .map(
                  (item) => `
                <tr>
                  <td style="border: 1px solid #ddd; padding: 8px;">${
                    item.sku
                  }</td>
                  <td style="border: 1px solid #ddd; padding: 8px;">${
                    item.name
                  }</td>
                  <td style="border: 1px solid #ddd; padding: 8px; text-align: center;">${
                    item.quantity
                  }</td>
                  <td style="border: 1px solid #ddd; padding: 8px; text-align: right;">${parseFloat(
                    item.price || 0
                  ).toFixed(2)}</td>
                  <td style="border: 1px solid #ddd; padding: 8px; text-align: right;">${parseFloat(
                    item.totalAmount || 0
                  ).toFixed(2)}</td>
                </tr>
              `
                )
                .join("")}
            </tbody>
          </table>
          <h3>Price Summary</h3>
          <ul style="list-style: none; padding: 0;">
            <li><strong>Subtotal:</strong> $${parseFloat(subtotal).toFixed(
              2
            )}</li>
            ${
              discount > 0
                ? `<li><strong>Discount:</strong> $${parseFloat(
                    discount
                  ).toFixed(2)}</li>`
                : ""
            }
            <li><strong>Tax (7%):</strong> $${parseFloat(tax).toFixed(2)}</li>
            <li><strong>Shipping:</strong> ${
              shipping !== null ? `$${parseFloat(shipping).toFixed(2)}` : "-"
            }</li>
            <li><strong>Total:</strong> $${parseFloat(total).toFixed(2)}</li>
          </ul>
        </div>
      `;

      // Updated mail options with full HTML details
      const userMailOptions = {
        from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
        to: userEmail,
        subject: `Order Submitted - ${orderId} (Pending Approval)`,
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2>Thank You for Your Order, ${userFullName}!</h2>
            <p>Your order <strong>${orderId}</strong> has been submitted on ${new Date().toLocaleDateString()} and is currently <strong>pending admin approval</strong>.</p>
            <p><strong>Important:</strong></p>
            <ul>
              <li>This order cannot be edited or canceled after 24 hours.</li>
              <li>Please note: Your order will be considered accepted after 24 hours of placement.</li>
              <li>Shipping charges will be applied by the admin based on your location's shipping zone. You'll receive an updated order amount via email once finalized.</li>
            </ul>
            ${orderDetailsHtml}
          </div>
        `,
      };

      const adminMailOptions = {
        from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
        to: "aashish.shroff@zeta-v.com",
        subject: `New Order Pending Approval - ${orderId}`,
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2>New Order Pending Approval: ${orderId}</h2>
            <p>A new order has been submitted by <strong>${userFullName}</strong> (${userEmail}) on ${new Date().toLocaleDateString()}.</p>
            <p><strong>Phone:</strong> ${userPhone}</p>
            ${orderDetailsHtml}
          </div>
        `,
      };

      try {
        await Promise.all([
          transporter.sendMail(userMailOptions),
          transporter.sendMail(adminMailOptions),
        ]);
      } catch (emailErr) {
        console.error("Email sending failed:", emailErr);
      }

      res.status(201).json({
        message: "Order submitted successfully and is pending admin approval",
        order_id: orderId,
      });
    } catch (err) {
      await connection.rollback();
      connection.release();
      console.error("Transaction failed:", err);
      res.status(500).json({ error: "Error placing order" });
    }
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/orders", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    const [orders] = await pool.query(
      `SELECT 
          o.order_id AS id,
          o.created_at AS created_at,
          o.door_style,
          o.finish_type,
          o.stain_option,
          o.paint_option,
          o.account,
          o.bill_to,
          o.subtotal,
          o.tax,
          o.shipping,
          o.total,
          o.discount,
          o.additional_discount,
          o.status,
          GROUP_CONCAT(
            JSON_OBJECT(
              'sku', oi.sku,
              'name', oi.name,
              'quantity', oi.quantity,
              'price', oi.price,
              'totalAmount', oi.total_amount
            )
          ) AS items
          FROM orders o
          LEFT JOIN order_items oi ON o.id = oi.order_id
          WHERE o.user_id = ?
          GROUP BY o.id
          ORDER BY o.created_at DESC`,
      [userId]
    );

    const formattedOrders = orders.map((order) => {
      console.log(`Order ${order.id}: created_at = ${order.created_at}`); // Debug log
      const additionalDiscountPercent =
        order.subtotal && order.additional_discount
          ? ((order.additional_discount / order.subtotal) * 100).toFixed(2)
          : "0.00";
      return {
        id: order.id,
        created_at: order.created_at
          ? new Date(order.created_at).toISOString()
          : null,
        date: order.created_at
          ? new Date(order.created_at).toISOString().split("T")[0]
          : null,
        productLine: order.door_style.includes("Shaker")
          ? "Kitchen Shaker"
          : "Bath Shaker",
        status: order.status,
        total: `$${parseFloat(order.total || 0).toFixed(2)}`,
        subtotal: parseFloat(order.subtotal || 0).toFixed(2),
        discount: parseFloat(order.discount || 0).toFixed(2),
        additional_discount: parseFloat(order.additional_discount || 0).toFixed(
          2
        ),
        additional_discount_percent: parseFloat(additionalDiscountPercent),
        tax: parseFloat(order.tax || 0).toFixed(2),
        shipping:
          order.shipping !== null
            ? parseFloat(order.shipping).toFixed(2)
            : null,
        account: order.account,
        bill_to: order.bill_to,
        items: order.items ? JSON.parse(`[${order.items}]`) : [],
        door_style: order.door_style,
        finish_type: order.finish_type,
        stain_option: order.stain_option,
        paint_option: order.paint_option,
      };
    });

    res.json(formattedOrders);
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Edit an order

app.put("/api/orders/:id", authenticateToken, async (req, res) => {
  const orderId = req.params.id;
  const userId = req.user.id;
  const {
    doorStyle,
    finishType,
    stainOption,
    paintOption,
    account,
    billTo,
    items,
    subtotal,
    tax,
    shipping,
    total,
  } = req.body;

  try {
    // Fetch the order from database
    const [orders] = await pool.query(
      `SELECT id, order_id, user_id, created_at, status, 
              door_style, finish_type, stain_option, paint_option, 
              account, bill_to, subtotal, tax, shipping, total
       FROM orders 
       WHERE order_id = ? AND user_id = ?`,
      [orderId, userId]
    );

    if (orders.length === 0) {
      return res
        .status(404)
        .json({ error: "Order not found or you do not have permission" });
    }

    const order = orders[0];

    // Check if order is canceled or completed
    if (order.status === "Cancelled") {
      return res.status(400).json({ error: "Cannot edit a canceled order" });
    }
    if (order.status === "Completed") {
      return res.status(400).json({ error: "Cannot edit a completed order" });
    }

    // Check if within 24 hours
    const now = new Date();
    const orderDate = new Date(order.created_at);
    const hoursDiff = (now - orderDate) / (1000 * 60 * 60);
    if (hoursDiff > 24) {
      return res
        .status(400)
        .json({ error: "Order cannot be edited after 24 hours" });
    }

    // Validate required fields
    if (!items || !Array.isArray(items) || items.length === 0) {
      return res
        .status(400)
        .json({ error: "Items are required and must be a non-empty array" });
    }
    if (!subtotal || !tax || !total) {
      return res
        .status(400)
        .json({ error: "Subtotal, tax, and total are required" });
    }
    if (!doorStyle || !finishType || !account || !billTo) {
      return res.status(400).json({
        error: "Door style, finish type, account, and bill-to are required",
      });
    }
    if (finishType === "Stain" && !stainOption) {
      return res
        .status(400)
        .json({ error: "Stain option is required for stain finish" });
    }
    if (finishType === "Paint" && !paintOption) {
      return res
        .status(400)
        .json({ error: "Paint option is required for paint finish" });
    }

    // Fetch user info, including phone
    const [userResult] = await pool.query(
      "SELECT full_name, email, phone FROM users WHERE id = ?",
      [userId]
    );
    if (userResult.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    const userFullName = userResult[0].full_name;
    const userEmail = userResult[0].email;
    const userPhone = userResult[0].phone || "N/A";

    // Start transaction
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // Update order in orders table
      await connection.query(
        `UPDATE orders 
         SET door_style = ?, finish_type = ?, stain_option = ?, paint_option = ?, 
             account = ?, bill_to = ?, subtotal = ?, tax = ?, shipping = ?, total = ?
         WHERE order_id = ? AND user_id = ?`,
        [
          doorStyle,
          finishType,
          stainOption || null,
          paintOption || null,
          account,
          billTo,
          subtotal,
          tax,
          shipping !== undefined ? shipping : null,
          total,
          orderId,
          userId,
        ]
      );

      // Delete existing order items
      await connection.query("DELETE FROM order_items WHERE order_id = ?", [
        order.id,
      ]);

      // Insert updated items
      for (const item of items) {
        if (!item.sku || !item.name || !item.quantity || item.quantity < 1) {
          throw new Error(
            "Invalid item data: SKU, name, and valid quantity are required"
          );
        }
        await connection.query(
          `INSERT INTO order_items (order_id, sku, name, quantity, price, total_amount, door_style, finish)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            order.id,
            item.sku,
            item.name,
            item.quantity,
            item.price || null,
            item.totalAmount || null,
            doorStyle,
            finishType === "Stain" ? stainOption : paintOption,
          ]
        );
      }

      await connection.commit();
      connection.release();

      // Fetch updated order
      const [updatedOrders] = await pool.query(
        `SELECT 
          o.order_id AS id,
          o.created_at AS date,
          o.door_style,
          o.finish_type,
          o.stain_option,
          o.paint_option,
          o.account,
          o.bill_to,
          o.subtotal,
          o.tax,
          o.shipping,
          o.total,
          o.status,
          GROUP_CONCAT(
            JSON_OBJECT(
              'sku', oi.sku,
              'name', oi.name,
              'quantity', oi.quantity,
              'price', oi.price,
              'totalAmount', oi.total_amount
            )
          ) AS items
         FROM orders o
         LEFT JOIN order_items oi ON o.id = oi.order_id
         WHERE o.order_id = ? AND o.user_id = ?
         GROUP BY o.id`,
        [orderId, userId]
      );

      const formattedOrder = updatedOrders[0]
        ? {
            id: updatedOrders[0].id,
            date: new Date(updatedOrders[0].date).toISOString().split("T")[0],
            productLine: updatedOrders[0].door_style.includes("Shaker")
              ? "Kitchen"
              : "Bath",
            status: updatedOrders[0].status,
            total: `$${parseFloat(updatedOrders[0].total || 0).toFixed(2)}`,
            subtotal: parseFloat(updatedOrders[0].subtotal || 0).toFixed(2),
            tax: parseFloat(updatedOrders[0].tax || 0).toFixed(2),
            shipping:
              updatedOrders[0].shipping !== null
                ? parseFloat(updatedOrders[0].shipping).toFixed(2)
                : null,
            account: updatedOrders[0].account,
            bill_to: updatedOrders[0].bill_to,
            items: updatedOrders[0].items
              ? JSON.parse(`[${updatedOrders[0].items}]`)
              : [],
            door_style: updatedOrders[0].door_style,
            finish_type: updatedOrders[0].finish_type,
            stain_option: updatedOrders[0].stain_option,
            paint_option: updatedOrders[0].paint_option,
          }
        : null;

      // Shared email template for order details
      const orderDetailsHtml = `
        <h3>Order Details</h3>
        <ul>
          <li><strong>Door Style:</strong> ${doorStyle}</li>
          <li><strong>Finish Type:</strong> ${finishType}</li>
          ${
            stainOption
              ? `<li><strong>Stain Option:</strong> ${stainOption}</li>`
              : ""
          }
          ${
            paintOption
              ? `<li><strong>Paint Option:</strong> ${paintOption}</li>`
              : ""
          }
          <li><strong>Account:</strong> ${account}</li>
          <li><strong>Bill To:</strong> ${billTo}</li>
        </ul>
        <h3>Items</h3>
        <table style="border-collapse: collapse; width: 100%;">
          <thead>
            <tr style="background-color: #f2f2f2;">
              <th style="border: 1px solid #ddd; padding: 8px;">SKU</th>
              <th style="border: 1px solid #ddd; padding: 8px;">Name</th>
              <th style="border: 1px solid #ddd; padding: 8px;">Quantity</th>
              <th style="border: 1px solid #ddd; padding: 8px;">Price ($)</th>
              <th style="border: 1px solid #ddd; padding: 8px;">Total ($)</th>
            </tr>
          </thead>
          <tbody>
            ${items
              .map(
                (item) => `
              <tr>
                <td style="border: 1px solid #ddd; padding: 8px;">${
                  item.sku
                }</td>
                <td style="border: 1px solid #ddd; padding: 8px;">${
                  item.name
                }</td>
                <td style="border: 1px solid #ddd; padding: 8px; text-align: center;">${
                  item.quantity
                }</td>
                <td style="border: 1px solid #ddd; padding: 8px; text-align: right;">${parseFloat(
                  item.price || 0
                ).toFixed(2)}</td>
                <td style="border: 1px solid #ddd; padding: 8px; text-align: right;">${parseFloat(
                  item.totalAmount || 0
                ).toFixed(2)}</td>
              </tr>
            `
              )
              .join("")}
          </tbody>
        </table>
        <h3>Price Summary</h3>
        <ul>
          <li><strong>Subtotal:</strong> $${parseFloat(subtotal).toFixed(
            2
          )}</li>
          <li><strong>Tax (7%):</strong> $${parseFloat(tax).toFixed(2)}</li>
          <li><strong>Shipping:</strong> ${
            shipping !== null ? `$${parseFloat(shipping).toFixed(2)}` : "-"
          }</li>
          <li><strong>Total:</strong> $${parseFloat(total).toFixed(2)}</li>
        </ul>
      `;

      // Send email to user
      const userEmailOptions = {
        from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
        to: userEmail,
        subject: `Order Updated - ${orderId}`,
        html: `
          <h2>Your Order Has Been Updated, ${userFullName}!</h2>
          <p>Your order <strong>${orderId}</strong> has been successfully updated on ${new Date().toLocaleDateString()}.</p>
          ${orderDetailsHtml}
          <p>We appreciate your business! You'll receive further updates on your order status soon.</p>
          <p>If you have any questions, please contact our support team.</p>
          <p>Best regards,<br>Studio Signature Cabinets</p>
        `,
      };

      // Admin email
      const adminMailOptions = {
        from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
        to: "aashish.shroff@zeta-v.com",
        subject: `Order Updated - ${orderId}`,
        html: `
          <h2>Order ID: ${orderId}</h2>
          <p><strong>Updated by:</strong> ${userFullName} (${userEmail})</p>
          <p><strong>Phone:</strong> ${userPhone}</p>
          <p><strong>Update Date:</strong> ${new Date().toLocaleDateString()}</p>
          <p><strong>Status:</strong> ${order.status}</p>
          ${orderDetailsHtml}
          <p>Please check the admin panel for further details or to manage this order.</p>
        `,
      };

      await transporter.sendMail(userEmailOptions);
      await transporter.sendMail(adminMailOptions);

      res.json({
        message: "Order updated successfully",
        order: formattedOrder,
      });
    } catch (err) {
      await connection.rollback();
      connection.release();
      console.error("Transaction failed:", err);
      res.status(500).json({ error: "Error updating order" });
    }
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.put("/api/orders/:id/cancel", authenticateToken, async (req, res) => {
  const orderId = req.params.id;
  const userId = req.user.id;

  try {
    // Fetch the order from database with all necessary details
    const [orders] = await pool.query(
      `SELECT id, order_id, created_at, status, door_style, finish_type, stain_option, 
              paint_option, account, bill_to, subtotal, tax, shipping, total
       FROM orders 
       WHERE order_id = ? AND user_id = ?`,
      [orderId, userId]
    );

    if (orders.length === 0) {
      return res
        .status(404)
        .json({ error: "Order not found or you do not have permission" });
    }

    const order = orders[0];

    // Check if already canceled or completed
    if (order.status === "Cancelled") {
      return res.status(400).json({ error: "Order is already canceled" });
    }
    if (order.status === "Completed") {
      return res.status(400).json({ error: "Cannot cancel a completed order" });
    }

    // Check if within 24 hours
    const now = new Date();
    const orderDate = new Date(order.created_at);
    const hoursDiff = (now - orderDate) / (1000 * 60 * 60);
    if (hoursDiff > 24) {
      return res
        .status(400)
        .json({ error: "Order cannot be canceled after 24 hours" });
    }

    // Fetch user info, including phone
    const [userResult] = await pool.query(
      "SELECT full_name, email, phone FROM users WHERE id = ?",
      [userId]
    );
    if (userResult.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    const userFullName = userResult[0].full_name;
    const userEmail = userResult[0].email;
    const userPhone = userResult[0].phone || "N/A";

    // Fetch order items
    const [orderItems] = await pool.query(
      `SELECT sku, name, quantity, price, total_amount
       FROM order_items
       WHERE order_id = ?`,
      [order.id]
    );

    // Update order status to Cancelled
    await pool.query(
      `UPDATE orders 
       SET status = 'Cancelled'
       WHERE order_id = ? AND user_id = ?`,
      [orderId, userId]
    );

    // Fetch updated order
    const [updatedOrders] = await pool.query(
      `SELECT 
        o.order_id AS id,
        o.created_at AS date,
        o.door_style,
        o.finish_type,
        o.stain_option,
        o.paint_option,
        o.account,
        o.bill_to,
        o.subtotal,
        o.tax,
        o.shipping,
        o.total,
        o.status,
        GROUP_CONCAT(
          JSON_OBJECT(
            'sku', oi.sku,
            'name', oi.name,
            'quantity', oi.quantity,
            'price', oi.price,
            'totalAmount', oi.total_amount
          )
        ) AS items
       FROM orders o
       LEFT JOIN order_items oi ON o.id = oi.order_id
       WHERE o.order_id = ? AND o.user_id = ?
       GROUP BY o.id`,
      [orderId, userId]
    );

    const formattedOrder = updatedOrders[0]
      ? {
          id: updatedOrders[0].id,
          date: new Date(updatedOrders[0].date).toISOString().split("T")[0],
          productLine: updatedOrders[0].door_style.includes("Shaker")
            ? "Kitchen"
            : "Bath",
          status: updatedOrders[0].status,
          total: `$${parseFloat(updatedOrders[0].total || 0).toFixed(2)}`,
          subtotal: parseFloat(updatedOrders[0].subtotal || 0).toFixed(2),
          tax: parseFloat(updatedOrders[0].tax || 0).toFixed(2),
          shipping:
            updatedOrders[0].shipping !== null
              ? parseFloat(updatedOrders[0].shipping).toFixed(2)
              : null,
          account: updatedOrders[0].account,
          bill_to: updatedOrders[0].bill_to,
          items: updatedOrders[0].items
            ? JSON.parse(`[${updatedOrders[0].items}]`)
            : [],
          door_style: updatedOrders[0].door_style,
          finish_type: updatedOrders[0].finish_type,
          stain_option: updatedOrders[0].stain_option,
          paint_option: updatedOrders[0].paint_option,
        }
      : null;

    // Shared email template for order details
    const orderDetailsHtml = `
      <h3>Order Details</h3>
      <ul>
        <li><strong>Door Style:</strong> ${order.door_style || "N/A"}</li>
        <li><strong>Finish Type:</strong> ${order.finish_type || "N/A"}</li>
        ${
          order.stain_option
            ? `<li><strong>Stain Option:</strong> ${order.stain_option}</li>`
            : ""
        }
        ${
          order.paint_option
            ? `<li><strong>Paint Option:</strong> ${order.paint_option}</li>`
            : ""
        }
        <li><strong>Account:</strong> ${order.account || "N/A"}</li>
        <li><strong>Bill To:</strong> ${order.bill_to || "N/A"}</li>
      </ul>
      <h3>Items</h3>
      <table style="border-collapse: collapse; width: 100%;">
        <thead>
          <tr style="background-color: #f2f2f2;">
            <th style="border: 1px solid #ddd; padding: 8px;">SKU</th>
            <th style="border: 1px solid #ddd; padding: 8px;">Name</th>
            <th style="border: 1px solid #ddd; padding: 8px;">Quantity</th>
            <th style="border: 1px solid #ddd; padding: 8px;">Price ($)</th>
            <th style="border: 1px solid #ddd; padding: 8px;">Total ($)</th>
          </tr>
        </thead>
        <tbody>
          ${
            orderItems.length > 0
              ? orderItems
                  .map(
                    (item) => `
                <tr>
                  <td style="border: 1px solid #ddd; padding: 8px;">${
                    item.sku
                  }</td>
                  <td style="border: 1px solid #ddd; padding: 8px;">${
                    item.name
                  }</td>
                  <td style="border: 1px solid #ddd; padding: 8px; text-align: center;">${
                    item.quantity
                  }</td>
                  <td style="border: 1px solid #ddd; padding: 8px; text-align: right;">${parseFloat(
                    item.price || 0
                  ).toFixed(2)}</td>
                  <td style="border: 1px solid #ddd; padding: 8px; text-align: right;">${parseFloat(
                    item.total_amount || 0
                  ).toFixed(2)}</td>
                </tr>
              `
                  )
                  .join("")
              : '<tr><td colspan="5" style="text-align: center;">No items found</td></tr>'
          }
        </tbody>
      </table>
      <h3>Price Summary</h3>
      <ul>
        <li><strong>Subtotal:</strong> $${parseFloat(
          order.subtotal || 0
        ).toFixed(2)}</li>
        <li><strong>Tax (7%):</strong> $${parseFloat(order.tax || 0).toFixed(
          2
        )}</li>
        <li><strong>Shipping:</strong> ${
          order.shipping !== null
            ? `$${parseFloat(order.shipping).toFixed(2)}`
            : "-"
        }</li>
        <li><strong>Total:</strong> $${parseFloat(order.total || 0).toFixed(
          2
        )}</li>
      </ul>
    `;

    // User Email
    const userEmailOptions = {
      from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
      to: userEmail,
      subject: `Order Canceled - ${orderId}`,
      html: `
        <h2>Your Order Has Been Canceled, ${userFullName}!</h2>
        <p>Your order <strong>${orderId}</strong> was canceled on ${new Date().toLocaleDateString()}.</p>
        ${orderDetailsHtml}
        <p>We're sorry to see this change. If you need assistance or wish to place a new order, please contact our support team.</p>
        <p>Thank you,<br>Studio Signature Cabinets</p>
      `,
    };

    // Admin Email
    const adminMailOptions = {
      from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
      to: "aashish.shroff@zeta-v.com",
      subject: `Order Canceled - ${orderId}`,
      html: `
        <h2>Order ID: ${orderId}</h2>
        <p><strong>Canceled by:</strong> ${userFullName} (${userEmail})</p>
        <p><strong>Phone:</strong> ${userPhone}</p>
        <p><strong>Cancellation Date:</strong> ${new Date().toLocaleDateString()}</p>
        <p><strong>Status:</strong> ${formattedOrder.status}</p>
        ${orderDetailsHtml}
        <p>Please check the admin panel for further details or to manage this order.</p>
      `,
    };

    await transporter.sendMail(userEmailOptions);
    await transporter.sendMail(adminMailOptions);

    res.json({ message: "Order canceled successfully", order: formattedOrder });
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/items", authenticateToken, async (req, res) => {
  try {
    const { item_type, color, sku_prefix, sku } = req.query;
    let query = "SELECT * FROM items WHERE 1=1";
    const params = [];

    if (item_type) {
      query += " AND item_type = ?";
      params.push(item_type.toUpperCase());
    }

    if (color) {
      query += " AND color = ?";
      params.push(color);
    }

    if (sku_prefix) {
      query += " AND sku LIKE ?";
      params.push(`${sku_prefix}%`);
    }

    if (sku) {
      query += " AND sku = ?";
      params.push(sku);
    }

    const [rows] = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    console.error("Error fetching items:", err);
    res.status(500).json({ error: "Failed to fetch items" });
  }
});

app.get("/api/user-stats", authenticateToken, async (req, res) => {
  try {
    const [stats] = await pool.query(
      `SELECT 
        u.id,
        u.full_name,
        u.email,
        COUNT(o.id) AS total_orders,
        SUM(CASE WHEN o.status = 'Pending' THEN 1 ELSE 0 END) AS pending_orders,
        SUM(CASE WHEN o.status = 'Completed' THEN 1 ELSE 0 END) AS completed_orders,
        SUM(CASE WHEN o.status = 'Cancelled' THEN 1 ELSE 0 END) AS cancelled_orders
       FROM users u
       LEFT JOIN orders o ON u.id = o.user_id
       GROUP BY u.id, u.full_name, u.email
       ORDER BY u.full_name`
    );

    res.json(stats);
  } catch (err) {
    console.error("Error in GET /api/user-stats:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/addresses - Create a new billing or shipping address

// POST /api/addresses
app.post("/api/addresses", authenticateToken, async (req, res) => {
  const { type, address } = req.body;
  const userId = req.user.id;

  try {
    // Validate inputs
    if (!["Billing", "Shipping"].includes(type)) {
      return res.status(400).json({
        error: 'Invalid address type. Must be "Billing" or "Shipping".',
      });
    }
    if (!address || !address.trim()) {
      return res.status(400).json({ error: "Address is required." });
    }

    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      if (type === "Billing") {
        // Check for existing billing address
        const [existingBilling] = await connection.query(
          "SELECT id FROM user_addresses WHERE user_id = ? AND type = ?",
          [userId, "Billing"]
        );

        if (existingBilling.length > 0) {
          // Update existing billing address
          await connection.query(
            "UPDATE user_addresses SET address = ?, updated_at = NOW() WHERE id = ?",
            [address.trim(), existingBilling[0].id]
          );
        } else {
          // Insert new billing address
          await connection.query(
            "INSERT INTO user_addresses (user_id, type, address) VALUES (?, ?, ?)",
            [userId, "Billing", address.trim()]
          );
        }
      } else {
        // Check for duplicate shipping address (case-insensitive)
        const [existingShipping] = await connection.query(
          "SELECT id FROM user_addresses WHERE user_id = ? AND type = ? AND LOWER(address) = LOWER(?)",
          [userId, "Shipping", address.trim()]
        );

        if (existingShipping.length > 0) {
          await connection.rollback();
          connection.release();
          return res
            .status(400)
            .json({ error: "Duplicate shipping address not allowed." });
        }

        // Insert new shipping address
        await connection.query(
          "INSERT INTO user_addresses (user_id, type, address) VALUES (?, ?, ?)",
          [userId, "Shipping", address.trim()]
        );
      }

      await connection.commit();
      connection.release();

      res.status(201).json({ message: "Address saved successfully." });
    } catch (err) {
      await connection.rollback();
      connection.release();
      console.error("Transaction error:", err);
      res.status(500).json({ error: "Failed to save address." });
    }
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Server error." });
  }
});

// GET /api/addresses - Retrieve all addresses for the user
app.get("/api/addresses", authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const [addresses] = await pool.query(
      "SELECT id, type, address, created_at, updated_at FROM user_addresses WHERE user_id = ? ORDER BY type ASC, created_at DESC",
      [userId]
    );

    const formattedAddresses = addresses.map((addr) => ({
      id: addr.id,
      type: addr.type,
      address: addr.address,
      created_at: addr.created_at
        ? new Date(addr.created_at).toISOString()
        : null,
      updated_at: addr.updated_at
        ? new Date(addr.updated_at).toISOString()
        : null,
    }));

    res.json(formattedAddresses);
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Failed to fetch addresses." });
  }
});

// GET /api/addresses/:id - Retrieve a single address by ID
app.get("/api/addresses/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  try {
    const [addresses] = await pool.query(
      "SELECT id, type, address, created_at, updated_at FROM user_addresses WHERE id = ? AND user_id = ?",
      [id, userId]
    );

    if (addresses.length === 0) {
      return res
        .status(404)
        .json({ error: "Address not found or not authorized." });
    }

    const addr = addresses[0];
    res.json({
      id: addr.id,
      type: addr.type,
      address: addr.address,
      created_at: addr.created_at
        ? new Date(addr.created_at).toISOString()
        : null,
      updated_at: addr.updated_at
        ? new Date(addr.updated_at).toISOString()
        : null,
    });
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Failed to fetch address." });
  }
});

// PUT /api/addresses/:id - Update an existing address
app.put("/api/addresses/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { type, address } = req.body;
  const userId = req.user.id;

  try {
    // Validate inputs
    if (!["Billing", "Shipping"].includes(type)) {
      return res.status(400).json({
        error: 'Invalid address type. Must be "Billing" or "Shipping".',
      });
    }
    if (!address || !address.trim()) {
      return res.status(400).json({ error: "Address is required." });
    }

    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // Verify address exists and belongs to user
      const [existing] = await connection.query(
        "SELECT id, type FROM user_addresses WHERE id = ? AND user_id = ?",
        [id, userId]
      );

      if (existing.length === 0) {
        await connection.rollback();
        connection.release();
        return res
          .status(404)
          .json({ error: "Address not found or not authorized." });
      }

      // If changing to Billing, ensure no other billing address exists
      if (type === "Billing") {
        const [otherBilling] = await connection.query(
          "SELECT id FROM user_addresses WHERE user_id = ? AND type = ? AND id != ?",
          [userId, "Billing", id]
        );
        if (otherBilling.length > 0) {
          await connection.rollback();
          connection.release();
          return res
            .status(400)
            .json({ error: "User already has a billing address." });
        }
      }

      // Update address
      await connection.query(
        "UPDATE user_addresses SET type = ?, address = ?, updated_at = NOW() WHERE id = ?",
        [type, address.trim(), id]
      );

      await connection.commit();
      connection.release();

      res.json({ message: "Address updated successfully." });
    } catch (err) {
      await connection.rollback();
      connection.release();
      console.error("Transaction error:", err);
      res.status(500).json({ error: "Failed to update address." });
    }
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Server error." });
  }
});

// DELETE /api/addresses/:id - Delete an address
app.delete("/api/addresses/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  try {
    const [result] = await pool.query(
      "DELETE FROM user_addresses WHERE id = ? AND user_id = ?",
      [id, userId]
    );

    if (result.affectedRows === 0) {
      return res
        .status(404)
        .json({ error: "Address not found or not authorized." });
    }

    res.json({ message: "Address deleted successfully." });
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Failed to delete address." });
  }
});

// POST /api/contact
app.post("/api/contact", authenticateToken, async (req, res) => {
  const { name, email, subject, message } = req.body;
  const userId = req.user.id; // Extracted from JWT

  // Validate input
  if (!name || !email || !subject || !message) {
    return res.status(400).json({ error: "All fields are required" });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Invalid email format" });
  }

  let messageId;
  try {
    // Insert into database (MySQL-compatible)
    const query = `
      INSERT INTO contact_messages (user_id, name, email, subject, message, status)
      VALUES (?, ?, ?, ?, ?, 'pending')
    `;
    const values = [userId || null, name, email, subject, message];
    const [result] = await pool.query(query, values);
    messageId = result.insertId; // Get the inserted ID

    // Send email to admin
    const mailOptions = {
      from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
      to: "aashish.shroff@zeta-v.com", // Admin email
      subject: `New Contact Form Submission: ${subject}`,
      html: `
        <h3>New Contact Message</h3>
        <p><strong>User ID:</strong> ${userId || "Guest"}</p>
        <p><strong>Name:</strong> ${name}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Subject:</strong> ${subject}</p>
        <p><strong>Message:</strong> ${message}</p>
        <p><strong>Message ID:</strong> ${messageId}</p>
      `,
    };

    await transporter.sendMail(mailOptions);

    // Update status
    await pool.query(
      "UPDATE contact_messages SET status = 'processed' WHERE id = ?",
      [messageId]
    );

    res.status(200).json({ message: "Message sent successfully" });
  } catch (error) {
    console.error("Error processing contact form:", error);
    if (messageId) {
      await pool.query(
        "UPDATE contact_messages SET status = 'failed' WHERE id = ?",
        [messageId]
      );
    }
    res.status(500).json({ error: "Failed to send message" });
  }
});

app.post("/api/forgot-password", async (req, res) => {
  const { email } = req.body;

  if (!email) return res.status(400).json({ error: "Email is required" });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: "Invalid email format" });

  try {
    const [users] = await pool.query(
      "SELECT id, full_name FROM users WHERE email = ?",
      [email]
    );
    if (users.length === 0)
      return res.status(404).json({ error: "User not found" });

    const resetToken = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour from now

    // Delete previous token
    await pool.query("DELETE FROM password_resets WHERE email = ?", [email]);

    // Insert new token
    await pool.query(
      "INSERT INTO password_resets (email, token, expires_at) VALUES (?, ?, ?)",
      [email, resetToken, expiresAt]
    );

    const data = { token: resetToken, email };
    const encodedData = base64url.encode(JSON.stringify(data));
    const resetLink = `https://studiosignaturecabinets.com/customer/reset-password?data=${encodedData}`;

    const mailOptions = {
      from: `"Studio Signature Cabinets" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Password Reset Request",
      html: `
        <h3>Password Reset Request</h3>
        <p>Dear ${users[0].full_name || "User"},</p>
        <p>We received a request to reset your password. Click the link below to set a new password:</p>
        <a href="${resetLink}" style="display:inline-block;padding:10px 20px;background-color:#007bff;color:#fff;text-decoration:none;border-radius:5px;">Reset Password</a>
        <p>This link will expire in 1 hour. If you didn’t request this, please ignore this email.</p>
        <p>Best regards,<br>Studio Signature Cabinets Team</p>
      `,
    };

    await transporter.sendMail(mailOptions);

    res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
    res.status(200).json({ message: "Password reset email sent successfully" });
  } catch (error) {
    console.error("Error processing forgot password:", error);
    res.status(500).json({ error: "Failed to send password reset email" });
  }
});

// POST /api/reset-password

app.post("/api/reset-password", async (req, res) => {
  const { email, token, newPassword, confirmPassword } = req.body;

  if (!email || !token || !newPassword || !confirmPassword) {
    return res.status(400).json({ error: "All fields are required" });
  }

  if (newPassword !== confirmPassword) {
    return res.status(400).json({ error: "New passwords do not match" });
  }

  const passwordRegex =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]).{8,}$/;
  if (!passwordRegex.test(newPassword) || /\s/.test(newPassword)) {
    return res.status(400).json({
      error:
        "Password must be at least 8 characters, include one uppercase, one lowercase, one number, one special character, and no spaces",
    });
  }

  try {
    // Log inputs
    console.log("Reset Password Payload:", { email, token });

    const [resets] = await pool.query(
      `SELECT * FROM password_resets WHERE email = ? AND token = ? AND expires_at > CONVERT_TZ(NOW(), 'SYSTEM', '+00:00')`,
      [email, token]
    );

    if (resets.length === 0) {
      return res.status(400).json({ error: "Invalid or expired reset token" });
    }

    const [users] = await pool.query(
      "SELECT id, full_name FROM users WHERE email = ?",
      [email]
    );
    if (users.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = users[0];
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await pool.query("UPDATE users SET password = ? WHERE id = ?", [
      hashedPassword,
      user.id,
    ]);
    await pool.query(
      "DELETE FROM password_resets WHERE email = ? AND token = ?",
      [email, token]
    );

    const mailOptions = {
      from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
      to: email,
      subject: "Password Reset Confirmation",
      html: `
        <h3>Password Reset Confirmation</h3>
        <p>Dear ${user.full_name || "User"},</p>
        <p>Your password has been successfully reset on ${new Date().toLocaleString(
          "en-US",
          { timeZone: "Asia/Kolkata" }
        )} IST.</p>
        <p>If you did not perform this action, please contact our support team immediately at <a href="mailto:info@studiosignaturecabinets.com">info@studiosignaturecabinets.com</a>.</p>
        <p>Best regards,<br>Studio Signature Cabinets Team</p>
      `,
    };

    await transporter.sendMail(mailOptions);

    res.status(200).json({ message: "Password reset successfully" });
  } catch (error) {
    console.error("Error resetting password:", error);
    res.status(500).json({ error: "Failed to reset password" });
  }
});

// Fetch visible media for customers
app.get("/api/elearning", async (req, res) => {
  try {
    const [media] = await pool.query(
      "SELECT id, media_type, file_path, description, created_at FROM elearning_media WHERE is_visible = 1"
    );
    // Return absolute URLs
    const updatedMedia = media.map((item) => ({
      ...item,
      file_path: `${req.protocol}://${req.get("host")}${item.file_path}`,
    }));
    res.json({ media: updatedMedia });
  } catch (err) {
    console.error("Customer fetch error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/customer/invoices", authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const [invoices] = await pool.query(
      `SELECT i.*, o.id AS order_internal_id, o.order_id, o.bill_to, o.account
       FROM invoices i
       LEFT JOIN orders o ON i.order_id = o.id
       WHERE i.user_id = ?`,
      [userId]
    );

    // Fetch all order items for each invoice using the internal order_id (o.id)
    const orderIds = invoices.map((invoice) => invoice.order_internal_id);
    const [items] = await pool.query(
      `SELECT oi.order_id, oi.sku, oi.name, oi.quantity, oi.door_style, oi.finish, oi.price, oi.total_amount
       FROM order_items oi
       WHERE oi.order_id IN (?)`,
      [orderIds]
    );

    // Associate items with their respective invoices
    const invoicesWithItems = invoices.map((invoice) => ({
      ...invoice,
      items: items.filter(
        (item) => item.order_id === invoice.order_internal_id
      ),
    }));

    // Format the response to match the expected structure
    const formattedResponse = invoicesWithItems.map((invoice) => ({
      id: invoice.id,
      invoice_number: invoice.invoice_number,
      order_id: invoice.order_id, // Use the string order_id (e.g., "S-ORD101127")
      user_id: invoice.user_id,
      issue_date: invoice.issue_date,
      subtotal: invoice.subtotal,
      tax: invoice.tax,
      shipping: invoice.shipping,
      discount: invoice.discount,
      additional_discount: invoice.additional_discount,
      total: invoice.total,
      items: invoice.items,
      finish_type: invoice.finish_type,
      door_style: invoice.door_style,
      bill_to: invoice.bill_to,
      account: invoice.account,
    }));

    res.json(formattedResponse);
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/customer/products - Fetch products for customer portal (is_visible = 1)
app.get("/api/customer/products", authenticateToken, async (req, res) => {
  try {
    const [products] = await pool.query(
      `SELECT id, name, item_type, color, photo_path
       FROM products
       WHERE is_visible = 1`
    );
    res.json(
      products.map((product) => ({
        id: product.id,
        name: product.name,
        item_type: product.item_type,
        color: product.color,
        photo_path: product.photo_path
          ? `${req.protocol}://${req.get("host")}${product.photo_path}`
          : null,
      }))
    );
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

//-------------------------------------------Admin Apis ------------------------------------------------------------

// Admin Registration API

app.post("/api/admin/register", async (req, res) => {
  const { fullName, email, password, confirmPassword } = req.body;

  // Validation
  if (!fullName || !email || !password || !confirmPassword) {
    return res.status(400).json({ error: "Missing required fields" });
  }
  if (password !== confirmPassword) {
    return res.status(400).json({ error: "Passwords do not match" });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Invalid email format" });
  }
  if (password.length < 8) {
    return res
      .status(400)
      .json({ error: "Password must be at least 8 characters" });
  }

  try {
    // Check if email already exists
    const [existingAdmins] = await pool.query(
      "SELECT id FROM admins WHERE email = ?",
      [email]
    );
    if (existingAdmins.length > 0) {
      return res.status(400).json({ error: "Email already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Insert admin into database
    const [result] = await pool.query(
      `INSERT INTO admins (full_name, email, password, role, is_active, created_at)
       VALUES (?, ?, ?, 'Administrator', 1, NOW())`,
      [fullName, email, hashedPassword]
    );

    const adminId = result.insertId;

    // Send confirmation email to admin
    const adminMailOptions = {
      from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
      to: email,
      subject: "Welcome to Studio Signature Cabinets Admin Panel!",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2>Welcome, ${fullName}!</h2>
          <p>Your admin account has been successfully created with Studio Signature Cabinets.</p>
          <h3>Account Details:</h3>
          <ul style="list-style: none; padding: 0;">
            <li><strong>Full Name:</strong> ${fullName}</li>
            <li><strong>Email:</strong> ${email}</li>
            <li><strong>Role:</strong> Administrator</li>
          </ul>
          <p>You can now log in to the admin panel:</p>
          <p style="text-align: center;">
            <a href="https://studiosignaturecabinets.com/admin/login" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Log In Now</a>
          </p>
          <p>For support, contact us at <a href="mailto:info@studiosignaturecabinets.com">info@studiosignaturecabinets.com</a>.</p>
          <p>Best regards,<br>Team Studio Signature Cabinets</p>
        </div>
      `,
    };

    // Send notification email to super admin
    const superAdminMailOptions = {
      from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
      to: "aashish.shroff@zeta-v.com",
      subject: `New Admin Registration - ${fullName}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2>New Admin Registered</h2>
          <p>A new admin has registered on ${new Date().toLocaleDateString()}.</p>
          <h3>Admin Details:</h3>
          <ul style="list-style: none; padding: 0;">
            <li><strong>Admin ID:</strong> ${adminId}</li>
            <li><strong>Full Name:</strong> ${fullName}</li>
            <li><strong>Email:</strong> ${email}</li>
            <li><strong>Role:</strong> Administrator</li>
            <li><strong>Registration Date:</strong> ${new Date().toLocaleDateString()}</li>
          </ul>
          <p>Review this admin in the admin panel:</p>
          <p style="text-align: center;">
            <a href="https://studiosignaturecabinets.com/admin/login" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">View Admin</a>
          </p>
        </div>
      `,
    };

    // Send emails with error handling
    try {
      await Promise.all([
        transporter.sendMail(adminMailOptions),
        transporter.sendMail(superAdminMailOptions),
      ]);
    } catch (emailErr) {
      console.error("Email sending failed:", emailErr);
      return res.status(201).json({
        message:
          "Admin account created successfully. Email sending failed, please contact support.",
      });
    }

    res.status(201).json({
      message: "Admin account created successfully. Confirmation email sent.",
    });
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Admin Login API
app.post("/api/admin/login", async (req, res) => {
  const { email, password } = req.body;

  // Validation
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Invalid email format" });
  }

  try {
    // Fetch admin
    const [admins] = await pool.query(
      "SELECT id, full_name, email, password, role, is_active FROM admins WHERE email = ?",
      [email]
    );

    if (admins.length === 0) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const admin = admins[0];

    // Check if admin is active
    if (!admin.is_active) {
      return res.status(403).json({ error: "Account is deactivated" });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, admin.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    // Update last_login
    await pool.query("UPDATE admins SET last_login = NOW() WHERE id = ?", [
      admin.id,
    ]);

    // Generate JWT
    const token = jwt.sign(
      { id: admin.id, email: admin.email, role: admin.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    // Respond with token and admin details
    res.json({
      message: "Login successful",
      token,
      admin: {
        id: admin.id,
        fullName: admin.full_name,
        email: admin.email,
        role: admin.role,
      },
    });
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Get Admin Profile
app.get("/api/admin/profile", adminauthenticateToken, async (req, res) => {
  try {
    console.log("Fetching profile for admin ID:", req.admin.id);
    const [admins] = await pool.query(
      "SELECT id, full_name, email, phone, role, bio FROM admins WHERE id = ? AND is_active = 1",
      [req.admin.id]
    );

    if (admins.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const admin = admins[0];
    res.json({
      fullName: admin.full_name,
      email: admin.email,
      phone: admin.phone || "",
      role: admin.role,
      bio: admin.bio || "",
    });
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Update Admin Profile
app.put("/api/admin/profile", adminauthenticateToken, async (req, res) => {
  const { fullName, email, phone, bio } = req.body;

  // Validation
  if (!fullName || !email) {
    return res.status(400).json({ error: "Full name and email are required" });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Invalid email format" });
  }
  if (phone && !/^\(\d{3}\) \d{3}-\d{4}$/.test(phone)) {
    return res
      .status(400)
      .json({ error: "Phone format should be (XXX) XXX-XXXX" });
  }

  try {
    // Check if email is taken by another admin
    const [existingAdmins] = await pool.query(
      "SELECT id FROM admins WHERE email = ? AND id != ?",
      [email, req.admin.id]
    );
    if (existingAdmins.length > 0) {
      return res.status(400).json({ error: "Email already in use" });
    }

    // Update profile
    await pool.query(
      "UPDATE admins SET full_name = ?, email = ?, phone = ?, bio = ?, updated_at = NOW() WHERE id = ?",
      [fullName, email, phone || null, bio || null, req.admin.id]
    );

    res.json({ message: "Profile updated successfully" });
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Update Admin Password

app.put("/api/admin/password", adminauthenticateToken, async (req, res) => {
  const { currentPassword, newPassword, confirmPassword } = req.body;

  // Validation
  if (!currentPassword || !newPassword || !confirmPassword) {
    return res.status(400).json({ error: "All password fields are required" });
  }

  const passwordRegex =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]).{8,}$/;
  if (!passwordRegex.test(newPassword) || /\s/.test(newPassword)) {
    return res.status(400).json({
      error:
        "Password must be at least 8 characters, include one uppercase, one lowercase, one number, one special character, and no spaces",
    });
  }

  if (newPassword !== confirmPassword) {
    return res
      .status(400)
      .json({ error: "New password and confirm password do not match" });
  }

  try {
    // Fetch current password and email
    const [admins] = await pool.query(
      "SELECT id, password, email FROM admins WHERE id = ?",
      [req.admin.id]
    );

    if (admins.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    // Verify current password
    const isPasswordValid = await bcrypt.compare(
      currentPassword,
      admins[0].password
    );
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Current password is incorrect" });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);

    // Update password
    await pool.query(
      "UPDATE admins SET password = ?, updated_at = NOW() WHERE id = ?",
      [hashedPassword, req.admin.id]
    );

    // Send confirmation email
    await transporter.sendMail({
      from: `"Studio Signature Cabinets" <sssdemo6@gmail.com>`,
      to: admins[0].email,
      subject: "Admin Password Update Confirmation",
      html: `
        <p>Your admin account password has been successfully updated.</p>
        <p>If you did not perform this action, please contact support immediately.</p>
      `,
    });

    res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
    res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/admin/forgot-password", async (req, res) => {
  const { email } = req.body;

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Valid email is required" });
  }

  try {
    const [admins] = await pool.query(
      "SELECT id, email FROM admins WHERE email = ?",
      [email]
    );
    if (admins.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const token = crypto.randomBytes(32).toString("hex");
    const expires = new Date(Date.now() + 3600000); // 1 hour

    await pool.query(
      "INSERT INTO admin_password_resets (email, token, created_at) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE token = ?, created_at = ?",
      [email, token, new Date(), token, new Date()]
    );

    const resetData = { token, email };
    const encodedData = base64url.encode(JSON.stringify(resetData));
    const resetLink = `https://studiosignaturecabinets.com/admin/reset-password?data=${encodedData}`;

    await transporter.sendMail({
      from: `"Studio Signature Cabinets" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Admin Password Reset Request",
      html: `
        <p>You requested a password reset for your admin account.</p>
        <p>Click <a href="${resetLink}">here</a> to reset your password.</p>
        <p>This link will expire in 1 hour.</p>
        <p>If you did not request this, please ignore this email.</p>
      `,
    });

    res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
    res.json({ message: "Password reset email sent successfully" });
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Failed to send password reset email" });
  }
});

// POST /api/admin/reset-password
app.post("/api/admin/reset-password", async (req, res) => {
  const { email, token, newPassword, confirmPassword } = req.body;

  if (!email || !token || !newPassword || !confirmPassword) {
    return res.status(400).json({ error: "All fields are required" });
  }

  if (newPassword !== confirmPassword) {
    return res
      .status(400)
      .json({ error: "New password and confirm password do not match" });
  }

  const passwordRegex =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]).{8,}$/;
  if (!passwordRegex.test(newPassword) || /\s/.test(newPassword)) {
    return res.status(400).json({
      error:
        "Password must be at least 8 characters, include one uppercase, one lowercase, one number, one special character, and no spaces",
    });
  }

  try {
    const [resetRequests] = await pool.query(
      "SELECT created_at FROM admin_password_resets WHERE email = ? AND token = ?",
      [email, token]
    );

    if (resetRequests.length === 0) {
      return res.status(400).json({ error: "Invalid or expired reset token" });
    }

    const createdAt = new Date(resetRequests[0].created_at);
    if (Date.now() - createdAt.getTime() > 3600000) {
      // 1 hour
      await pool.query("DELETE FROM admin_password_resets WHERE email = ?", [
        email,
      ]);
      return res.status(400).json({ error: "Reset token has expired" });
    }

    const [admins] = await pool.query("SELECT id FROM admins WHERE email = ?", [
      email,
    ]);
    if (admins.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);

    await pool.query(
      "UPDATE admins SET password = ?, updated_at = NOW() WHERE id = ?",
      [hashedPassword, admins[0].id]
    );

    await pool.query("DELETE FROM admin_password_resets WHERE email = ?", [
      email,
    ]);

    await transporter.sendMail({
      from: `"Studio Signature Cabinets" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Admin Password Reset Confirmation",
      html: `
        <p>Your admin account password has been successfully reset.</p>
        <p>If you did not perform this action, please contact support immediately.</p>
      `,
    });

    res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
    res.json({ message: "Password reset successfully" });
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Failed to reset password" });
  }
});

// Fetch All Users

app.get("/api/admin/users", adminauthenticateToken, async (req, res) => {
  try {
    const [users] = await pool.query(
      "SELECT id, full_name, email, phone, created_at, last_login, account_status, is_active, company_name, address, admin_discount, updated_at,notes FROM users WHERE user_type = 'customer'"
    );

    res.json({
      users: users.map((user) => ({
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        phone: user.phone,
        joinDate: user.created_at,
        lastLogin: user.last_login || null,
        account_status: user.account_status,
        is_active: user.is_active,
        company_name: user.company_name,
        address: user.address,
        admin_discount: user.admin_discount,
        updated_at: user.updated_at,
        notes: user.notes,
      })),
    });
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// fetch all vendors

// app.get("/api/admin/vendors", adminauthenticateToken, async (req, res) => {
//   try {
//     const [vendors] = await pool.query(
//       "SELECT id, full_name, email, phone, created_at, last_login, account_status, is_active, company_name, address, updated_at,notes FROM users WHERE user_type = 'vendor'"
//     );
//     res.json({
//       vendors: vendors.map((vendor) => ({
//         id: vendor.id,
//         fullName: vendor.full_name,
//         email: vendor.email,
//         phone: vendor.phone,
//         joinDate: vendor.created_at,
//         lastLogin: vendor.last_login || null,
//         account_status: vendor.account_status,
//         is_active: vendor.is_active,
//         company_name: vendor.company_name,
//         address: vendor.address,
//         updated_at: vendor.updated_at,
//       })),
//     });
//   } catch (err) {
//     console.error("Server error:", err);
//     res.status(500).json({ error: "Server error" });
//   }
// });

app.get("/api/admin/vendors", adminauthenticateToken, async (req, res) => {
  try {
    const [vendors] = await pool.query(
      "SELECT id, full_name, email, phone, created_at, last_login, account_status, is_active, company_name, address, updated_at, notes FROM users WHERE user_type = 'vendor'"
    );
    res.json({
      vendors: vendors.map((vendor) => ({
        id: vendor.id,
        fullName: vendor.full_name,
        email: vendor.email,
        phone: vendor.phone,
        joinDate: vendor.created_at,
        lastLogin: vendor.last_login || null,
        account_status: vendor.account_status,
        is_active: vendor.is_active,
        company_name: vendor.company_name,
        address: vendor.address,
        updated_at: vendor.updated_at,
        notes: vendor.notes || null, // Include notes
      })),
    });
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.put("/api/admin/vendor/:id", adminauthenticateToken, async (req, res) => {
  const { id } = req.params;
  const { notes } = req.body;

  // Validate notes (optional, can be null or string)
  if (notes !== undefined && notes !== null && typeof notes !== "string") {
    return res.status(400).json({ error: "Notes must be a string or null" });
  }

  try {
    // Check if vendor exists
    const [vendors] = await pool.query(
      "SELECT id FROM users WHERE id = ? AND user_type = 'vendor'",
      [id]
    );
    if (vendors.length === 0) {
      return res.status(404).json({ error: "Vendor not found" });
    }

    // Update notes
    await pool.query(
      "UPDATE users SET notes = ?, updated_at = NOW() WHERE id = ? AND user_type = 'vendor'",
      [notes || null, id]
    );

    // Fetch updated vendor data
    const [updatedVendors] = await pool.query(
      "SELECT id, full_name, email, phone, created_at, last_login, account_status, is_active, company_name, address, updated_at, notes FROM users WHERE id = ? AND user_type = 'vendor'",
      [id]
    );

    if (updatedVendors.length === 0) {
      return res.status(404).json({ error: "Vendor not found after update" });
    }

    res.json({
      vendor: {
        id: updatedVendors[0].id,
        fullName: updatedVendors[0].full_name,
        email: updatedVendors[0].email,
        phone: updatedVendors[0].phone,
        joinDate: updatedVendors[0].created_at,
        lastLogin: updatedVendors[0].last_login || null,
        account_status: updatedVendors[0].account_status,
        is_active: updatedVendors[0].is_active,
        company_name: updatedVendors[0].company_name,
        address: updatedVendors[0].address,
        updated_at: updatedVendors[0].updated_at,
        notes: updatedVendors[0].notes || null,
      },
      message: "Vendor notes updated successfully",
    });
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.put("/api/admin/vendor/:id/status",adminauthenticateToken,
  async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;

    // Validate status
    if (!["Active", "Inactive", "Suspended"].includes(status)) {
      return res.status(400).json({
        error: "Invalid status. Must be Active, Inactive, or Suspended",
      });
    }

    try {
      // Check if vendor exists
      const [vendors] = await pool.query(
        "SELECT id, full_name, email, user_type FROM users WHERE id = ? AND user_type = 'vendor'",
        [id]
      );
      if (vendors.length === 0) {
        return res.status(404).json({ error: "Vendor not found" });
      }

      const vendor = vendors[0];
      // Determine is_active based on status
      const isActive = status === "Active" ? 1 : 0;

      // Update status and is_active
      await pool.query(
        "UPDATE users SET account_status = ?, is_active = ? WHERE id = ? AND user_type = 'vendor'",
        [status, isActive, id]
      );

      // Send email if status is Active
      if (status === "Active") {
        const mailOptions = {
          from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
          to: vendor.email,
          subject:
            "Your Studio Signature Cabinets Vendor Account Has Been Approved!",
          html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2>Welcome, ${vendor.full_name}!</h2>
            <p>Great news! Your <strong>${
              vendor.user_type.charAt(0).toUpperCase() +
              vendor.user_type.slice(1)
            }</strong> account with Studio Signature Cabinets has been approved.</p>
            <p>You can now log in to your account and start exploring our platform:</p>
            <p style="text-align: center;">
              <a href="https://studiosignaturecabinets.com/vendor" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Log In Now</a>
            </p>
            <h3>Your Account Details:</h3>
            <ul style="list-style: none; padding: 0;">
              <li><strong>Full Name:</strong> ${vendor.full_name}</li>
              <li><strong>Email:</strong> ${vendor.email}</li>
              <li><strong>User Type:</strong> ${
                vendor.user_type.charAt(0).toUpperCase() +
                vendor.user_type.slice(1)
              }</li>
            </ul>
            <p>If you have any questions, please contact our support team at <a href="mailto:info@studiosignaturecabinets.com">info@studiosignaturecabinets.com</a>.</p>
            <p>Best regards,<br>Team Studio Signature Cabinets</p>
          </div>
        `,
        };

        try {
          await transporter.sendMail(mailOptions);
        } catch (emailErr) {
          console.error("Failed to send approval email:", emailErr);
          // Log error but don't fail the status update
        }
      }

      res.json({ message: "Vendor status updated successfully" });
    } catch (err) {
      console.error("Server error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Update Customer Discount
// app.put("/api/admin/user/:id/discount", adminauthenticateToken,
//   async (req, res) => {
//     const { id } = req.params;
//     const { admin_discount } = req.body;

//     // Validate discount
//     if (
//       typeof admin_discount !== "number" ||
//       admin_discount < 0 ||
//       admin_discount > 100
//     ) {
//       return res
//         .status(400)
//         .json({ error: "Discount must be a number between 0 and 100" });
//     }

//     try {
//       // Check if user exists
//       const [users] = await pool.query("SELECT id FROM users WHERE id = ?", [
//         id,
//       ]);
//       if (users.length === 0) {
//         return res.status(404).json({ error: "User not found" });
//       }

//       // Update discount
//       await pool.query(
//         "UPDATE users SET admin_discount = ?, updated_at = NOW() WHERE id = ?",
//         [admin_discount, id]
//       );

//       res.json({ message: "Customer discount updated successfully" });
//     } catch (err) {
//       console.error("Server error:", err);
//       res.status(500).json({ error: "Server error" });
//     }
//   }
// );

app.put("/api/admin/user/:id/discount",adminauthenticateToken,
  async (req, res) => {
    const { id } = req.params;
    const { admin_discount, notes } = req.body;

    // Validate discount
    if (
      typeof admin_discount !== "number" ||
      admin_discount < 0 ||
      admin_discount > 100
    ) {
      return res
        .status(400)
        .json({ error: "Discount must be a number between 0 and 100" });
    }

    // Validate notes (optional, can be null or string)
    if (notes !== undefined && notes !== null && typeof notes !== "string") {
      return res.status(400).json({ error: "Notes must be a string or null" });
    }

    try {
      // Check if user exists
      const [users] = await pool.query("SELECT id FROM users WHERE id = ?", [
        id,
      ]);
      if (users.length === 0) {
        return res.status(404).json({ error: "User not found" });
      }

      // Update discount and notes
      await pool.query(
        "UPDATE users SET admin_discount = ?, notes = ?, updated_at = NOW() WHERE id = ?",
        [admin_discount, notes || null, id]
      );

      res.json({ message: "Customer discount and notes updated successfully" });
    } catch (err) {
      console.error("Server error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Update User Status

app.put("/api/admin/user/:id/status",adminauthenticateToken,
  async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;

    // Validate status
    if (!["Active", "Inactive", "Suspended"].includes(status)) {
      return res.status(400).json({
        error: "Invalid status. Must be Active, Inactive, or Suspended",
      });
    }

    try {
      // Check if user exists
      const [users] = await pool.query(
        "SELECT id, full_name, email, user_type FROM users WHERE id = ?",
        [id]
      );
      if (users.length === 0) {
        return res.status(404).json({ error: "User not found" });
      }

      const user = users[0];
      // Determine is_active based on status
      const isActive = status === "Active" ? 1 : 0;

      // Update status and is_active
      await pool.query(
        "UPDATE users SET account_status = ?, is_active = ? WHERE id = ?",
        [status, isActive, id]
      );

      // Send email if status is Active
      if (status === "Active") {
        const mailOptions = {
          from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
          to: user.email,
          subject: "Your Studio Signature Cabinets Account Has Been Approved!",
          html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2>Welcome, ${user.full_name}!</h2>
            <p>Great news! Your <strong>${
              user.user_type
            }</strong> account with Studio Signature Cabinets has been approved.</p>
            <p>You can now log in to your account and start exploring our platform:</p>
            <p style="text-align: center;">
              <a href="https://studiosignaturecabinets.com/customer/login" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Log In Now</a>
            </p>
            <h3>Your Account Details:</h3>
            <ul style="list-style: none; padding: 0;">
              <li><strong>Full Name:</strong> ${user.full_name}</li>
              <li><strong>Email:</strong> ${user.email}</li>
              <li><strong>User Type:</strong> ${
                user.user_type.charAt(0).toUpperCase() + user.user_type.slice(1)
              }</li>
            </ul>
            <p>If you have any questions, please contact our support team at <a href="mailto:info@studiosignaturecabinets.com">info@studiosignaturecabinets.com</a>.</p>
            <p>Best regards,<br>Team Studio Signature Cabinets</p>
          </div>
        `,
        };

        try {
          await transporter.sendMail(mailOptions);
        } catch (emailErr) {
          console.error("Failed to send approval email:", emailErr);
          // Log error but don't fail the status update
        }
      }

      res.json({ message: "User status updated successfully" });
    } catch (err) {
      console.error("Server error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

app.get("/api/admin/orders", adminauthenticateToken, async (req, res) => {
  try {
    const [orders] = await pool.query(`
      SELECT 
        o.id AS id,
        o.order_id AS orderId,
        o.user_id,
        u.full_name AS userName,
        u.email AS userEmail,
        o.created_at AS created_at,
        o.door_style AS door_style,
        o.finish_type AS finish_type,
        o.stain_option AS stain_option,
        o.paint_option AS paint_option,
        o.account,
        o.bill_to,
        o.subtotal,
        o.tax,
        o.shipping,
        o.discount,
        o.additional_discount,
        o.total,
        o.status,
        GROUP_CONCAT(
          JSON_OBJECT(
            'sku', oi.sku,
            'name', oi.name,
            'quantity', oi.quantity,
            'price', oi.price,
            'totalAmount', oi.total_amount
          )
        ) AS items
      FROM orders o
      LEFT JOIN users u ON o.user_id = u.id
      LEFT JOIN order_items oi ON o.id = oi.order_id
      GROUP BY o.id
      ORDER BY o.created_at DESC
    `);

    const formattedOrders = orders.map((order) => ({
      id: order.id,
      orderId: order.orderId,
      userId: order.user_id,
      userName: order.userName || "Unknown User",
      userEmail: order.userEmail || "N/A",
      created_at: order.created_at
        ? new Date(order.created_at).toISOString()
        : null,
      date: order.created_at
        ? new Date(order.created_at).toISOString().split("T")[0]
        : null,
      productLine: order.door_style.includes("Shaker")
        ? "Kitchen Shaker"
        : "Bath Shaker",
      status: order.status,
      total: `$${parseFloat(order.total || 0).toFixed(2)}`,
      subtotal: parseFloat(order.subtotal || 0).toFixed(2),
      discount: parseFloat(order.discount || 0).toFixed(2),
      additional_discount: parseFloat(order.additional_discount || 0).toFixed(
        2
      ),
      tax: parseFloat(order.tax || 0).toFixed(2),
      shipping:
        order.shipping !== null ? parseFloat(order.shipping).toFixed(2) : null,
      account: order.account,
      bill_to: order.bill_to,
      items: order.items ? JSON.parse(`[${order.items}]`) : [],
      door_style: order.door_style,
      finish_type: order.finish_type,
      stain_option: order.stain_option,
      paint_option: order.paint_option,
    }));

    res.json(formattedOrders);
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/admin/orders/:id", adminauthenticateToken, async (req, res) => {
  const orderId = req.params.id;
  try {
    const [orders] = await pool.query(
      `
      SELECT 
        o.id,
        o.order_id AS orderId,
        o.user_id,
        u.full_name AS userName,
        u.email AS userEmail,
        o.door_style AS doorStyle,
        o.finish_type AS finishType,
        o.stain_option AS stainOption,
        o.paint_option AS paintOption,
        o.account,
        o.bill_to AS billTo,
        o.subtotal,
        o.tax,
        o.shipping,
        o.discount,
        o.additional_discount,
        o.total,
        o.status,
        o.created_at AS createdAt,
        GROUP_CONCAT(
          JSON_OBJECT(
            'sku', oi.sku,
            'name', oi.name,
            'quantity', oi.quantity,
            'price', oi.price,
            'totalAmount', oi.total_amount
          )
        ) AS items
      FROM orders o
      LEFT JOIN users u ON o.user_id = u.id
      LEFT JOIN order_items oi ON o.id = oi.order_id
      WHERE o.id = ?
      GROUP BY o.id
    `,
      [orderId]
    );

    if (orders.length === 0) {
      return res.status(404).json({ error: "Order not found" });
    }

    const order = orders[0];
    const additionalDiscountPercent =
      order.subtotal && order.additional_discount
        ? ((order.additional_discount / order.subtotal) * 100).toFixed(2)
        : "0.00";

    res.json({
      order: {
        id: order.id,
        orderId: order.orderId,
        userId: order.user_id,
        userName: order.userName || "Unknown User",
        userEmail: order.userEmail || "N/A",
        door_style: order.doorStyle,
        finish_type: order.finishType,
        stain_option: order.stainOption || "None",
        paint_option: order.paintOption || "None",
        account: order.account,
        bill_to: order.billTo,
        subtotal: parseFloat(order.subtotal || 0).toFixed(2),
        tax: parseFloat(order.tax || 0).toFixed(2),
        shipping: order.shipping ? parseFloat(order.shipping).toFixed(2) : null,
        discount: parseFloat(order.discount || 0).toFixed(2),
        additional_discount: parseFloat(order.additional_discount || 0).toFixed(
          2
        ),
        additional_discount_percent: parseFloat(additionalDiscountPercent),
        total: parseFloat(order.total || 0).toFixed(2),
        status: order.status,
        created_at: order.createdAt
          ? new Date(order.createdAt).toISOString()
          : null,
        date: order.createdAt
          ? new Date(order.createdAt).toISOString().split("T")[0]
          : null,
        productLine: order.doorStyle.includes("Shaker")
          ? "Kitchen Shaker"
          : "Bath Shaker",
        items: order.items ? JSON.parse(`[${order.items}]`) : [],
      },
    });
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/admin/orders/:id", adminauthenticateToken, async (req, res) => {
  const { id } = req.params;
  const { shipping, additional_discount } = req.body;

  console.log(
    `POST /api/admin/orders/${id} called with shipping: ${shipping}, additional_discount: ${additional_discount}`
  );

  // Validate inputs if provided
  if (
    (shipping !== undefined &&
      (typeof shipping !== "number" || shipping < 0)) ||
    (additional_discount !== undefined &&
      (typeof additional_discount !== "number" ||
        additional_discount < 0 ||
        additional_discount > 100))
  ) {
    console.log(
      `Invalid input: shipping=${shipping}, additional_discount=${additional_discount}`
    );
    return res
      .status(400)
      .json({ error: "Invalid shipping or additional discount (0-100%)" });
  }

  try {
    // Fetch order details
    const [orders] = await pool.query(
      `SELECT o.id, o.order_id, o.subtotal, o.tax, o.discount, o.additional_discount AS current_additional_discount, 
                o.shipping AS current_shipping, o.total, o.user_id, u.full_name, u.email 
         FROM orders o 
         LEFT JOIN users u ON o.user_id = u.id 
         WHERE o.id = ?`,
      [id]
    );
    if (orders.length === 0) {
      console.log(`Order ${id} not found`);
      return res.status(404).json({ error: "Order not found" });
    }

    const order = orders[0];
    const user = {
      full_name: order.full_name || "Customer",
      email: order.email || "N/A",
    };

    // Use provided values or keep current
    const newShipping =
      shipping !== undefined
        ? parseFloat(shipping)
        : parseFloat(order.current_shipping || 0);
    const newAdditionalDiscountPercent =
      additional_discount !== undefined
        ? parseFloat(additional_discount)
        : undefined;
    const subtotal = parseFloat(order.subtotal) || 0;
    const newAdditionalDiscountAmount =
      newAdditionalDiscountPercent !== undefined
        ? (newAdditionalDiscountPercent / 100) * subtotal
        : parseFloat(order.current_additional_discount || 0);

    // Calculate new total
    const tax = parseFloat(order.tax) || 0;
    const discount = parseFloat(order.discount) || 0;
    let newTotal;
    if (discount > 0) {
      newTotal =
        subtotal - newAdditionalDiscountAmount - discount + tax + newShipping;
    } else {
      newTotal = subtotal - newAdditionalDiscountAmount + tax + newShipping;
    }

    // Ensure total is non-negative
    if (newTotal < 0) {
      console.log(`Invalid total calculated: ${newTotal}`);
      return res.status(400).json({ error: "Total cannot be negative" });
    }

    // Update database
    await pool.query(
      "UPDATE orders SET shipping = ?, additional_discount = ?, total = ? WHERE id = ?",
      [newShipping, newAdditionalDiscountAmount, newTotal, id]
    );

    // Send email if changes were made
    if (shipping !== undefined || additional_discount !== undefined) {
      const mailOptions = {
        from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
        to: user.email,
        subject: `Updated Order #${order.order_id}: Final Amount`,
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
              <h2>Hello, ${user.full_name}!</h2>
              <p>We’ve updated your order <strong>#${
                order.order_id
              }</strong>. Below is the final amount including any shipping charges and additional discounts.</p>
              <h3>Order Summary:</h3>
              <ul style="list-style: none; padding: 0;">
                <li><strong>Order ID:</strong> ${order.order_id}</li>
                <li><strong>Subtotal:</strong> $${subtotal.toFixed(2)}</li>
                <li><strong>Tax:</strong> $${tax.toFixed(2)}</li>
                <li><strong>Discount:</strong> $${discount.toFixed(2)}</li>
                <li><strong>Additional Discount:</strong> ${
                  newAdditionalDiscountPercent !== undefined
                    ? `${newAdditionalDiscountPercent.toFixed(
                        2
                      )}% ($${newAdditionalDiscountAmount.toFixed(2)})`
                    : `0.00% ($${newAdditionalDiscountAmount.toFixed(2)})`
                }</li>
                <li><strong>Shipping Charges:</strong> $${newShipping.toFixed(
                  2
                )}</li>
                <li><strong>Final Total:</strong> $${newTotal.toFixed(2)}</li>
              </ul>
              <p><strong>Next Steps:</strong></p>
              <ul>
                <li>You can view your updated order details at <a href="https://studiosignaturecabinets.com/customer/orders">My Orders</a>.</li>
                <li>Contact us at <a href="mailto:info@studiosignaturecabinets.com">info@studiosignaturecabinets.com</a> for questions.</li>
              </ul>
              <p>Thank you for choosing Studio Signature Cabinets!</p>
              <p>Best regards,<br>Team Studio Signature Cabinets</p>
            </div>
          `,
      };

      try {
        await transporter.sendMail(mailOptions);
        console.log(`Update email sent to ${user.email}`);
      } catch (emailErr) {
        console.error("Failed to send update email:", emailErr);
      }
    }

    console.log(
      `Order ${id} updated: shipping=${newShipping}, additional_discount_amount=${newAdditionalDiscountAmount}, total=${newTotal}`
    );
    res.json({
      message: "Changes updated successfully",
      shipping: newShipping,
      additional_discount_amount: newAdditionalDiscountAmount,
      additional_discount_percent:
        newAdditionalDiscountPercent !== undefined
          ? newAdditionalDiscountPercent
          : (order.current_additional_discount / subtotal) * 100 || 0,
      total: newTotal,
    });
  } catch (err) {
    console.error("Server error updating order:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// PUT /api/admin/orders/:id/shipping (fallback)
app.put("/api/admin/orders/:id/shipping",adminauthenticateToken,
  async (req, res) => {
    const { id } = req.params;
    const { shipping, additional_discount } = req.body;

    console.log(
      `PUT /api/admin/orders/${id}/shipping called with shipping: ${shipping}, additional_discount: ${additional_discount}`
    );

    // Validate inputs if provided
    if (
      (shipping !== undefined &&
        (typeof shipping !== "number" || shipping < 0)) ||
      (additional_discount !== undefined &&
        (typeof additional_discount !== "number" ||
          additional_discount < 0 ||
          additional_discount > 100))
    ) {
      console.log(
        `Invalid input: shipping=${shipping}, additional_discount=${additional_discount}`
      );
      return res
        .status(400)
        .json({ error: "Invalid shipping or additional discount (0-100%)" });
    }

    try {
      // Fetch order details
      const [orders] = await pool.query(
        `SELECT o.id, o.order_id, o.subtotal, o.tax, o.discount, o.additional_discount AS current_additional_discount, 
                o.shipping AS current_shipping, o.total, o.user_id, u.full_name, u.email 
         FROM orders o 
         LEFT JOIN users u ON o.user_id = u.id 
         WHERE o.id = ?`,
        [id]
      );
      if (orders.length === 0) {
        console.log(`Order ${id} not found`);
        return res.status(404).json({ error: "Order not found" });
      }

      const order = orders[0];
      const user = {
        full_name: order.full_name || "Customer",
        email: order.email || "N/A",
      };

      // Use provided values or keep current
      const newShipping =
        shipping !== undefined
          ? parseFloat(shipping)
          : parseFloat(order.current_shipping || 0);
      const newAdditionalDiscountPercent =
        additional_discount !== undefined
          ? parseFloat(additional_discount)
          : undefined;
      const subtotal = parseFloat(order.subtotal) || 0;
      const newAdditionalDiscountAmount =
        newAdditionalDiscountPercent !== undefined
          ? (newAdditionalDiscountPercent / 100) * subtotal
          : parseFloat(order.current_additional_discount || 0);

      // Calculate new total
      const tax = parseFloat(order.tax) || 0;
      const discount = parseFloat(order.discount) || 0;
      let newTotal;
      if (discount > 0) {
        newTotal =
          subtotal - newAdditionalDiscountAmount - discount + tax + newShipping;
      } else {
        newTotal = subtotal - newAdditionalDiscountAmount + tax + newShipping;
      }

      // Ensure total is non-negative
      if (newTotal < 0) {
        console.log(`Invalid total calculated: ${newTotal}`);
        return res.status(400).json({ error: "Total cannot be negative" });
      }

      // Update database
      await pool.query(
        "UPDATE orders SET shipping = ?, additional_discount = ?, total = ? WHERE id = ?",
        [newShipping, newAdditionalDiscountAmount, newTotal, id]
      );

      // Send email if changes were made
      if (shipping !== undefined || additional_discount !== undefined) {
        const mailOptions = {
          from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
          to: user.email,
          subject: `Updated Order #${order.order_id}: Final Amount`,
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
              <h2>Hello, ${user.full_name}!</h2>
              <p>We’ve updated your order <strong>#${
                order.order_id
              }</strong>. Below is the final amount including any shipping charges and additional discounts.</p>
              <h3>Order Summary:</h3>
              <ul style="list-style: none; padding: 0;">
                <li><strong>Order ID:</strong> ${order.order_id}</li>
                <li><strong>Subtotal:</strong> $${subtotal.toFixed(2)}</li>
                <li><strong>Tax:</strong> $${tax.toFixed(2)}</li>
                <li><strong>Discount:</strong> $${discount.toFixed(2)}</li>
                <li><strong>Additional Discount:</strong> ${
                  newAdditionalDiscountPercent !== undefined
                    ? `${newAdditionalDiscountPercent.toFixed(
                        2
                      )}% ($${newAdditionalDiscountAmount.toFixed(2)})`
                    : `0.00% ($${newAdditionalDiscountAmount.toFixed(2)})`
                }</li>
                <li><strong>Shipping Charges:</strong> $${newShipping.toFixed(
                  2
                )}</li>
                <li><strong>Final Total:</strong> $${newTotal.toFixed(2)}</li>
              </ul>
              <p><strong>Next Steps:</strong></p>
              <ul>
                <li>You can view your updated order details at <a href="https://studiosignaturecabinets.com/customer/orders">My Orders</a>.</li>
                <li>Contact us at <a href="mailto:info@studiosignaturecabinets.com">info@studiosignaturecabinets.com</a> for questions.</li>
              </ul>
              <p>Thank you for choosing Studio Signature Cabinets!</p>
              <p>Best regards,<br>Team Studio Signature Cabinets</p>
            </div>
          `,
        };

        try {
          await transporter.sendMail(mailOptions);
          console.log(`Update email sent to ${user.email}`);
        } catch (emailErr) {
          console.error("Failed to send update email:", emailErr);
        }
      }

      console.log(
        `Order ${id} updated: shipping=${newShipping}, additional_discount_amount=${newAdditionalDiscountAmount}, total=${newTotal}`
      );
      res.json({
        message: "Changes updated successfully",
        shipping: newShipping,
        additional_discount_amount: newAdditionalDiscountAmount,
        additional_discount_percent:
          newAdditionalDiscountPercent !== undefined
            ? newAdditionalDiscountPercent
            : (order.current_additional_discount / subtotal) * 100 || 0,
        total: newTotal,
      });
    } catch (err) {
      console.error("Server error updating order:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

app.put("/api/admin/orders/:id/status",adminauthenticateToken,
  async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;

    if (
      !["Pending", "Accepted", "Processing", "Completed", "Cancelled"].includes(
        status
      )
    ) {
      return res.status(400).json({
        error:
          "Invalid status. Must be Pending, Accepted, Processing, Completed, or Cancelled",
      });
    }

    try {
      const [orders] = await pool.query(
        `SELECT o.id, o.order_id, o.user_id, o.door_style, o.finish_type, o.stain_option, o.paint_option, 
              o.subtotal, o.tax, o.shipping, o.discount, o.additional_discount, o.total, o.status, 
              u.full_name, u.email 
       FROM orders o 
       LEFT JOIN users u ON o.user_id = u.id 
       WHERE o.id = ?`,
        [id]
      );

      if (orders.length === 0) {
        return res.status(404).json({ error: "Order not found" });
      }

      const order = orders[0];

      if (order.status === "Cancelled") {
        return res.status(400).json({
          error: "Cannot update status of a cancelled order",
        });
      }

      const user = {
        full_name: order.full_name || "Customer",
        email: order.email || "N/A",
      };
      const additionalDiscountPercent =
        order.subtotal && order.additional_discount
          ? ((order.additional_discount / order.subtotal) * 100).toFixed(2)
          : "0.00";

      // Update order status
      await pool.query("UPDATE orders SET status = ? WHERE id = ?", [
        status,
        id,
      ]);

      // Generate invoice if status is Completed
      let invoiceNumber = null;
      if (status === "Completed") {
        invoiceNumber = `INV-${order.order_id}-${Date.now()}`;
        await pool.query(
          `INSERT INTO invoices (invoice_number, order_id, user_id, subtotal, tax, shipping, discount, additional_discount, total)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            invoiceNumber,
            order.id,
            order.user_id,
            order.subtotal,
            order.tax,
            order.shipping,
            order.discount,
            order.additional_discount,
            order.total,
          ]
        );
      }

      // Fetch order items for email
      const [orderItems] = await pool.query(
        `SELECT sku, name, quantity, door_style, finish, price, total_amount 
       FROM order_items 
       WHERE order_id = ?`,
        [order.id]
      );

      // Send email for status updates
      if (
        ["Accepted", "Processing", "Completed", "Cancelled"].includes(status) &&
        user.email !== "N/A"
      ) {
        let mailOptions;
        switch (status) {
          case "Completed":
            mailOptions = {
              from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
              to: user.email,
              subject: `Your Order #${order.order_id} Has Been Completed! Invoice #${invoiceNumber}`,
              html: `
              <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2>Hello, ${user.full_name}!</h2>
                <p>Fantastic news! Your order <strong>#${
                  order.order_id
                }</strong> has been completed and shipped.</p>
                <p>Your invoice <strong>#${invoiceNumber}</strong> is now available in your customer portal.</p>
                <h3>Invoice Details:</h3>
                <table style="width: 100%; border-collapse: collapse;">
                  <thead>
                    <tr style="background-color: #f2f2f2;">
                      <th style="border: 1px solid #ddd; padding: 8px;">SKU</th>
                      <th style="border: 1px solid #ddd; padding: 8px;">Name</th>
                      <th style="border: 1px solid #ddd; padding: 8px;">Quantity</th>
                      <th style="border: 1px solid #ddd; padding: 8px;">Price</th>
                      <th style="border: 1px solid #ddd; padding: 8px;">Total</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${orderItems
                      .map(
                        (item) => `
                      <tr>
                        <td style="border: 1px solid #ddd; padding: 8px;">${
                          item.sku
                        }</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">${
                          item.name
                        }</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">${
                          item.quantity
                        }</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">$${parseFloat(
                          item.price || 0
                        ).toFixed(2)}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">$${parseFloat(
                          item.total_amount || 0
                        ).toFixed(2)}</td>
                      </tr>
                    `
                      )
                      .join("")}
                  </tbody>
                </table>
                <h3 style="margin-top: 20px;">Summary:</h3>
                <ul style="list-style: none; padding: 0;">
                  <li><strong>Subtotal:</strong> $${parseFloat(
                    order.subtotal
                  ).toFixed(2)}</li>
                  <li><strong>Special Discount:</strong> $${parseFloat(
                    order.discount || 0
                  ).toFixed(2)}</li>
                  <li><strong>Additional Discount:</strong> ${additionalDiscountPercent}% ($${parseFloat(
                order.additional_discount || 0
              ).toFixed(2)})</li>
                  <li><strong>Tax:</strong> $${parseFloat(order.tax).toFixed(
                    2
                  )}</li>
                  <li><strong>Shipping:</strong> ${
                    order.shipping !== null
                      ? `$${parseFloat(order.shipping).toFixed(2)}`
                      : "-"
                  }</li>
                  <li><strong>Total:</strong> $${parseFloat(
                    order.total
                  ).toFixed(2)}</li>
                </ul>
                <p><strong>Next Steps:</strong></p>
                <ul>
                  <li>Your order has been shipped. Check your email for tracking information.</li>
                  <li>View your invoice at <a href="https://studiosignaturecabinets.com/customer/invoices">My Invoices</a>.</li>
                </ul>
                <p>If you have any issues, contact us at <a href="mailto:info@studiosignaturecabinets.com">info@studiosignaturecabinets.com</a>.</p>
                <p>Enjoy your new cabinets!</p>
                <p>Best regards,<br>Team Studio Signature Cabinets</p>
              </div>
            `,
            };
            break;
          // Other cases (Accepted, Processing, Cancelled) remain unchanged from your original code
          case "Accepted":
            mailOptions = {
              from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
              to: user.email,
              subject: `Your Order #${order.order_id} Has Been Accepted!`,
              html: `
              <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2>Hello, ${user.full_name}!</h2>
                <p>Great news! Your order <strong>#${
                  order.order_id
                }</strong> has been accepted and is now being processed.</p>
                <h3>Order Details:</h3>
                <ul style="list-style: none; padding: 0;">
                  <li><strong>Order ID:</strong> ${order.order_id}</li>
                  <li><strong>Door Style:</strong> ${order.door_style}</li>
                  <li><strong>Finish Type:</strong> ${order.finish_type}</li>
                  ${
                    order.stain_option
                      ? `<li><strong>Stain Option:</strong> ${order.stain_option}</li>`
                      : ""
                  }
                  ${
                    order.paint_option
                      ? `<li><strong>Paint Option:</strong> ${order.paint_option}</li>`
                      : ""
                  }
                  <li><strong>Subtotal:</strong> $${parseFloat(
                    order.subtotal
                  ).toFixed(2)}</li>
                  <li><strong>Special Discount:</strong> $${parseFloat(
                    order.discount || 0
                  ).toFixed(2)}</li>
                  <li><strong>Additional Discount:</strong> ${additionalDiscountPercent}% ($${parseFloat(
                order.additional_discount || 0
              ).toFixed(2)})</li>
                  <li><strong>Tax:</strong> $${parseFloat(order.tax).toFixed(
                    2
                  )}</li>
                  <li><strong>Shipping:</strong> ${
                    order.shipping !== null
                      ? `$${parseFloat(order.shipping).toFixed(2)}`
                      : "-"
                  }</li>
                  <li><strong>Total:</strong> $${parseFloat(
                    order.total
                  ).toFixed(2)}</li>
                </ul>
                <p><strong>Next Steps:</strong></p>
                <ul>
                  <li>Your order is now in the processing stage. We’ll notify you with updates on its progress.</li>
                  <li>You can track your order status in your account at <a href="https://studiosignaturecabinets.com/customer/orders">My Orders</a>.</li>
                </ul>
                <p>If you have any questions, please contact our support team at <a href="mailto:info@studiosignaturecabinets.com">info@studiosignaturecabinets.com</a>.</p>
                <p>Thank you for choosing Studio Signature Cabinets!</p>
                <p>Best regards,<br>Team Studio Signature Cabinets</p>
              </div>
            `,
            };
            break;
          case "Processing":
            mailOptions = {
              from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
              to: user.email,
              subject: `Your Order #${order.order_id} is Being Processed!`,
              html: `
              <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2>Hello, ${user.full_name}!</h2>
                <p>Your order <strong>#${
                  order.order_id
                }</strong> is now being processed. We're preparing your items for shipment.</p>
                <h3>Order Details:</h3>
                <ul style="list-style: none; padding: 0;">
                  <li><strong>Order ID:</strong> ${order.order_id}</li>
                  <li><strong>Door Style:</strong> ${order.door_style}</li>
                  <li><strong>Finish Type:</strong> ${order.finish_type}</li>
                  ${
                    order.stain_option
                      ? `<li><strong>Stain Option:</strong> ${order.stain_option}</li>`
                      : ""
                  }
                  ${
                    order.paint_option
                      ? `<li><strong>Paint Option:</strong> ${order.paint_option}</li>`
                      : ""
                  }
                  <li><strong>Subtotal:</strong> $${parseFloat(
                    order.subtotal
                  ).toFixed(2)}</li>
                  <li><strong>Special Discount:</strong> $${parseFloat(
                    order.discount || 0
                  ).toFixed(2)}</li>
                  <li><strong>Additional Discount:</strong> ${additionalDiscountPercent}% ($${parseFloat(
                order.additional_discount || 0
              ).toFixed(2)})</li>
                  <li><strong>Tax:</strong> $${parseFloat(order.tax).toFixed(
                    2
                  )}</li>
                  <li><strong>Shipping:</strong> ${
                    order.shipping !== null
                      ? `$${parseFloat(order.shipping).toFixed(2)}`
                      : "-"
                  }</li>
                  <li><strong>Total:</strong> $${parseFloat(
                    order.total
                  ).toFixed(2)}</li>
                </ul>
                <p><strong>Next Steps:</strong></p>
                <ul>
                  <li>We are preparing your order for shipment. You’ll receive a shipping confirmation soon.</li>
                  <li>Track your order status at <a href="https://studiosignaturecabinets.com/customer/orders">My Orders</a>.</li>
                </ul>
                <p>For inquiries, contact us at <a href="mailto:info@studiosignaturecabinets.com">info@studiosignaturecabinets.com</a>.</p>
                <p>Thank you for your patience!</p>
                <p>Best regards,<br>Team Studio Signature Cabinets</p>
              </div>
            `,
            };
            break;
          case "Cancelled":
            mailOptions = {
              from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
              to: user.email,
              subject: `Your Order #${order.order_id} Has Been Cancelled`,
              html: `
              <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2>Hello, ${user.full_name}!</h2>
                <p>We’re sorry to inform you that your order <strong>#${
                  order.order_id
                }</strong> has been cancelled.</p>
                <p><strong>Note:</strong> This order cannot be reinstated or modified once cancelled.</p>
                <h3>Order Details:</h3>
                <ul style="list-style: none; padding: 0;">
                  <li><strong>Order ID:</strong> ${order.order_id}</li>
                  <li><strong>Door Style:</strong> ${order.door_style}</li>
                  <li><strong>Finish Type:</strong> ${order.finish_type}</li>
                  ${
                    order.stain_option
                      ? `<li><strong>Stain Option:</strong> ${order.stain_option}</li>`
                      : ""
                  }
                  ${
                    order.paint_option
                      ? `<li><strong>Paint Option:</strong> ${order.paint_option}</li>`
                      : ""
                  }
                  <li><strong>Subtotal:</strong> $${parseFloat(
                    order.subtotal
                  ).toFixed(2)}</li>
                  <li><strong>Special Discount:</strong> $${parseFloat(
                    order.discount || 0
                  ).toFixed(2)}</li>
                  <li><strong>Additional Discount:</strong> ${additionalDiscountPercent}% ($${parseFloat(
                order.additional_discount || 0
              ).toFixed(2)})</li>
                  <li><strong>Tax:</strong> $${parseFloat(order.tax).toFixed(
                    2
                  )}</li>
                  <li><strong>Shipping:</strong> ${
                    order.shipping !== null
                      ? `$${parseFloat(order.shipping).toFixed(2)}`
                      : "-"
                  }</li>
                  <li><strong>Total:</strong> $${parseFloat(
                    order.total
                  ).toFixed(2)}</li>
                </ul>
                <p><strong>Next Steps:</strong></p>
                <ul>
                  <li>If this was unexpected, please contact us immediately at <a href="mailto:info@studiosignaturecabinets.com">info@studiosignaturecabinets.com</a>.</li>
                  <li>Explore our products to place a new order at <a href="https://studiosignaturecabinets.com">Studio Signature Cabinets</a>.</li>
                </ul>
                <p>We apologize for any inconvenience. Let us know how we can assist you further.</p>
                <p>Best regards,<br>Team Studio Signature Cabinets</p>
              </div>
            `,
            };
            break;
        }

        try {
          await transporter.sendMail(mailOptions);
          console.log(
            `Email sent for order ${order.order_id} status: ${status}`
          );
        } catch (emailErr) {
          console.error(`Failed to send email for ${status} status:`, emailErr);
        }
      }

      res.json({ message: "Order status updated successfully" });
    } catch (err) {
      console.error("Server error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

cron.schedule("* * * * *", async () => {
  console.log(
    "Running auto-accept orders task at",
    new Date().toLocaleString("en-IN", { timeZone: "Asia/Kolkata" })
  );

  try {
    // Query for Pending orders older than 24 hours (adjusted for IST)
    const [pendingOrders] = await pool.query(
      `SELECT o.id, o.order_id, o.user_id, o.door_style, o.finish_type, o.stain_option, o.paint_option, 
              o.subtotal, o.tax, o.shipping, o.discount, o.additional_discount, o.total, o.status, 
              u.full_name, u.email 
       FROM orders o 
       LEFT JOIN users u ON o.user_id = u.id 
       WHERE o.status = 'Pending' 
       AND o.created_at <= CONVERT_TZ(DATE_SUB(NOW(), INTERVAL 24 HOUR), '+00:00', '+05:30')`
    );

    if (pendingOrders.length === 0) {
      console.log("No pending orders older than 24 hours found.");
      return;
    }

    for (const order of pendingOrders) {
      const user = {
        full_name: order.full_name || "Customer",
        email: order.email || "N/A",
      };
      const additionalDiscountPercent =
        order.subtotal && order.additional_discount
          ? ((order.additional_discount / order.subtotal) * 100).toFixed(2)
          : "0.00";

      // Update order status to Accepted
      await pool.query("UPDATE orders SET status = 'Accepted' WHERE id = ?", [
        order.id,
      ]);
      console.log(`Order ${order.order_id} auto-accepted after 24 hours.`);

      // Send email if email is available
      if (user.email !== "N/A") {
        const mailOptions = {
          from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
          to: user.email,
          subject: `Your Order #${order.order_id} Has Been Accepted!`,
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
              <h2>Hello, ${user.full_name}!</h2>
              <p>Great news! Your order <strong>#${
                order.order_id
              }</strong> has been accepted and is now being processed.</p>
              <h3>Order Details:</h3>
              <ul style="list-style: none; padding: 0;">
                <li><strong>Order ID:</strong> ${order.order_id}</li>
                <li><strong>Door Style:</strong> ${order.door_style}</li>
                <li><strong>Finish Type:</strong> ${order.finish_type}</li>
                ${
                  order.stain_option
                    ? `<li><strong>Stain Option:</strong> ${order.stain_option}</li>`
                    : ""
                }
                ${
                  order.paint_option
                    ? `<li><strong>Paint Option:</strong> ${order.paint_option}</li>`
                    : ""
                }
                <li><strong>Subtotal:</strong> $${parseFloat(
                  order.subtotal
                ).toFixed(2)}</li>
                <li><strong>Special Discount:</strong> $${parseFloat(
                  order.discount || 0
                ).toFixed(2)}</li>
                <li><strong>Additional Discount:</strong> ${additionalDiscountPercent}% ($${parseFloat(
            order.additional_discount || 0
          ).toFixed(2)})</li>
                <li><strong>Tax:</strong> $${parseFloat(order.tax).toFixed(
                  2
                )}</li>
                <li><strong>Shipping:</strong> ${
                  order.shipping !== null
                    ? `$${parseFloat(order.shipping).toFixed(2)}`
                    : "-"
                }</li>
                <li><strong>Total:</strong> $${parseFloat(order.total).toFixed(
                  2
                )}</li>
              </ul>
              <p><strong>Next Steps:</strong></p>
              <ul>
                <li>Your order is now in the processing stage. We’ll notify you with updates on its progress.</li>
                <li>You can track your order status in your account at <a href="https://studiosignaturecabinets.com/customer/orders">My Orders</a>.</li>
              </ul>
              <p>If you have any questions, please contact our support team at <a href="mailto:info@studiosignaturecabinets.com">info@studiosignaturecabinets.com</a>.</p>
              <p>Thank you for choosing Studio Signature Cabinets!</p>
              <p>Best regards,<br>Team Studio Signature Cabinets</p>
            </div>
          `,
        };

        try {
          await transporter.sendMail(mailOptions);
          console.log(
            `Email sent for order ${order.order_id} status: Accepted`
          );
        } catch (emailErr) {
          console.error(
            `Failed to send email for order ${order.order_id}:`,
            emailErr
          );
        }
      }
    }
  } catch (err) {
    console.error("Error in auto-accept orders task:", err);
  }
});

app.delete("/api/admin/orders/:id",adminauthenticateToken,
  async (req, res) => {
    const { id } = req.params;

    try {
      // Check if order exists
      const [orders] = await pool.query("SELECT id FROM orders WHERE id = ?", [
        id,
      ]);
      if (orders.length === 0) {
        return res.status(404).json({ error: "Order not found" });
      }

      // Delete order
      await pool.query("DELETE FROM orders WHERE id = ?", [id]);

      res.json({ message: "Order deleted successfully" });
    } catch (err) {
      console.error("Server error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// GET /api/contact/messages
app.get( "/api/admin/contact/messages",adminauthenticateToken,
  async (req, res) => {
    try {
      const query = `
      SELECT id, user_id, name, email, subject, message, status, created_at
      FROM contact_messages
      ORDER BY created_at DESC
    `;
      const [messages] = await pool.query(query);
      res.status(200).json(messages);
    } catch (error) {
      console.error("Error fetching contact messages:", error);
      res.status(500).json({ error: "Failed to fetch messages" });
    }
  }
);

// Upload media
app.post("/api/admin/elearning/upload",
  adminauthenticateToken,
  upload.single("media"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: "No file uploaded" });
      }
      const { description, media_type } = req.body;
      if (!["image", "video"].includes(media_type)) {
        return res.status(400).json({ error: "Invalid media type" });
      }

      const filePath = `/uploads/${req.file.filename}`;
      const [result] = await pool.query(
        "INSERT INTO elearning_media (media_type, file_path, description, is_visible) VALUES (?, ?, ?, 1)",
        [media_type, filePath, description || null]
      );

      res.json({
        media: {
          id: result.insertId,
          media_type,
          file_path: `${req.protocol}://${req.get("host")}${filePath}`,
          description: description || null,
          is_visible: 1,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        },
      });
    } catch (err) {
      console.error("Upload error:", err);
      res.status(500).json({ error: err.message || "Server error" });
    }
  }
);

// Fetch all media for admin
app.get("/api/admin/elearning", adminauthenticateToken, async (req, res) => {
  try {
    const [media] = await pool.query(
      "SELECT id, media_type, file_path, description, is_visible, created_at, updated_at FROM elearning_media"
    );
    // Return absolute URLs
    const updatedMedia = media.map((item) => ({
      ...item,
      file_path: `${req.protocol}://${req.get("host")}${item.file_path}`,
    }));
    res.json({ media: updatedMedia });
  } catch (err) {
    console.error("Fetch error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Toggle visibility
app.put(
  "/api/admin/elearning/:id/toggle",
  adminauthenticateToken,
  async (req, res) => {
    const { id } = req.params;
    const { is_visible } = req.body;

    if (![0, 1].includes(Number(is_visible))) {
      return res.status(400).json({ error: "Invalid visibility value" });
    }

    try {
      const [result] = await pool.query(
        "UPDATE elearning_media SET is_visible = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        [is_visible, id]
      );
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: "Media not found" });
      }
      res.json({ message: "Visibility updated successfully" });
    } catch (err) {
      console.error("Toggle error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Delete media
app.delete(
  "/api/admin/elearning/:id",
  adminauthenticateToken,
  async (req, res) => {
    const { id } = req.params;

    try {
      // Fetch file_path to delete the file
      const [rows] = await pool.query(
        "SELECT file_path FROM elearning_media WHERE id = ?",
        [id]
      );
      if (rows.length === 0) {
        return res.status(404).json({ error: "Media not found" });
      }

      const filePath = path.join(
        __dirname,
        "../../public_html",
        rows[0].file_path
      );
      try {
        await fs.unlink(filePath); // Delete file from server
      } catch (err) {
        console.warn(`Failed to delete file ${filePath}:`, err.message);
        // Continue with database deletion even if file deletion fails
      }

      const [result] = await pool.query(
        "DELETE FROM elearning_media WHERE id = ?",
        [id]
      );
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: "Media not found" });
      }

      res.json({ message: "Media deleted successfully" });
    } catch (err) {
      console.error("Delete error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Validation functions
const validateEmail = (email) => {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email) && !/\s/.test(email);
};

const validatePassword = (password) => {
  const re =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return re.test(password) && !/\s/.test(password);
};

const validatePhone = (phone) => {
  const re = /^\d{10}$/;
  return re.test(phone);
};

// Fetch all admins
app.get(
  "/api/adminuserpanel/admins",
  adminauthenticateToken,
  async (req, res) => {
    try {
      const [adminUsers] = await pool.query(
        "SELECT id, full_name AS fullName, email, role AS userType, created_at, updated_at FROM admins"
      );
      console.log("Fetched admins:", adminUsers); // Debug log
      res.json({ admins: adminUsers });
    } catch (err) {
      console.error("Fetch admins error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Fetch all users (customers/vendors)
// app.get(
//   "/api/adminuserpanel/users",
//   adminauthenticateToken,
//   async (req, res) => {
//     try {
//       const [customerVendorUsers] = await pool.query(
//         "SELECT id, full_name AS fullName, email, user_type AS userType, created_at, updated_at FROM users "
//       );
//       console.log("Fetched users:", customerVendorUsers); // Debug log
//       res.json({ users: customerVendorUsers });
//     } catch (err) {
//       console.error("Fetch users error:", err);
//       res.status(500).json({ error: "Server error" });
//     }
//   }
// );

app.get(
  "/api/adminuserpanel/users",
  adminauthenticateToken,
  async (req, res) => {
    try {
      const [customerVendorUsers] = await pool.query(
        "SELECT id,account_status, is_active,full_name AS fullName, email, user_type AS userType, created_at, updated_at FROM users "
      );
      console.log("Fetched users:", customerVendorUsers); // Debug log
      res.json({ users: customerVendorUsers });
    } catch (err) {
      console.error("Fetch users error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Admin registration
// app.post( "/api/adminuserpanel/register",adminauthenticateToken,
//   async (req, res) => {
//     const { fullName, email, password, confirmPassword, phone, bio } = req.body;

//     // Validate input
//     if (!fullName || !email || !password || !confirmPassword) {
//       return res
//         .status(400)
//         .json({ error: "All required fields must be provided" });
//     }
//     if (!validateEmail(email)) {
//       return res.status(400).json({ error: "Invalid email address" });
//     }
//     if (!validatePassword(password)) {
//       return res.status(400).json({
//         error:
//           "Password must be at least 8 characters long and include uppercase, lowercase, number, and special character",
//       });
//     }
//     if (password !== confirmPassword) {
//       return res.status(400).json({ error: "Passwords do not match" });
//     }
//     if (phone && !validatePhone(phone)) {
//       return res
//         .status(400)
//         .json({ error: "Phone number must be exactly 10 digits" });
//     }

//     try {
//       // Check if email exists in admins or users table
//       const [adminEmail] = await pool.query(
//         "SELECT id FROM admins WHERE email = ?",
//         [email]
//       );
//       const [userEmail] = await pool.query(
//         "SELECT id FROM users WHERE email = ?",
//         [email]
//       );
//       if (adminEmail.length > 0 || userEmail.length > 0) {
//         return res.status(400).json({ error: "Email already exists" });
//       }

//       // Hash password
//       const hashedPassword = await bcrypt.hash(password, 10);

//       // Insert admin
//       const [result] = await pool.query(
//         "INSERT INTO admins (full_name, email, password, role, phone, bio, is_active) VALUES (?, ?, ?, 'Administrator', ?, ?, 1)",
//         [fullName, email, hashedPassword, phone || null, bio || null]
//       );

//       res.json({
//         user: {
//           id: result.insertId,
//           fullName,
//           email,
//           userType: "Administrator",
//           created_at: new Date().toISOString(),
//           updated_at: new Date().toISOString(),
//         },
//         message: "Admin registered successfully",
//       });
//     } catch (err) {
//       console.error("Admin register error:", err);
//       res.status(500).json({ error: "Server error" });
//     }
//   }
// );

app.post(
  "/api/adminuserpanel/register",
  adminauthenticateToken,
  async (req, res) => {
    const { fullName, email, password, confirmPassword, phone, bio } = req.body;

    // Validate input
    if (!fullName || !email || !password || !confirmPassword) {
      return res
        .status(400)
        .json({ error: "All required fields must be provided" });
    }
    if (!validateEmail(email)) {
      return res.status(400).json({ error: "Invalid email address" });
    }
    if (!validatePassword(password)) {
      return res.status(400).json({
        error:
          "Password must be at least 8 characters long and include uppercase, lowercase, number, and special character",
      });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ error: "Passwords do not match" });
    }
    if (phone && !validatePhone(phone)) {
      return res
        .status(400)
        .json({ error: "Phone number must be exactly 10 digits" });
    }

    try {
      // Check if email exists in admins or users table
      const [adminEmail] = await pool.query(
        "SELECT id FROM admins WHERE email = ?",
        [email]
      );
      const [userEmail] = await pool.query(
        "SELECT id FROM users WHERE email = ?",
        [email]
      );
      if (adminEmail.length > 0 || userEmail.length > 0) {
        return res.status(400).json({ error: "Email already exists" });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Insert admin
      const [result] = await pool.query(
        "INSERT INTO admins (full_name, email, password, role, phone, bio, is_active, created_at, updated_at) VALUES (?, ?, ?, 'Administrator', ?, ?, 1, NOW(), NOW())",
        [fullName, email, hashedPassword, phone || null, bio || null]
      );

      // Send welcome email
      try {
        const mailOptions = {
          from: `"Admin Panel" < "sssdemo6@gmail.com"}>`,
          to: email,
          subject:
            "Welcome to Studio Signature Cabinets - Your Admin Account Details",
          html: `
            <h2>Welcome, ${fullName}!</h2>
            <p>Your Administrator account has been successfully created.</p>
            <p><strong>Login Details:</strong></p>
            <ul>
              <li><strong>Email:</strong> ${email}</li>
              <li><strong>Temporary Password:</strong> ${password}</li>
            </ul>
            <p>Please log in to the admin panel at <a href="https://studiosignaturecabinets.com/admin/login">https://studiosignaturecabinets.com/admin/login</a> using these credentials.</p>
            <p>For security, we recommend changing your password immediately after logging in. You can do this in your profile settings .</p>
            <p>If you have any questions, contact our support team at support@studiosignaturecabinets.com.</p>
            <p>Best regards,<br>The Studio Signature Cabinets Team</p>
          `,
        };

        await transporter.sendMail(mailOptions);
        console.log(`Welcome email sent to ${email}`);
      } catch (emailErr) {
        console.error("Email sending error:", emailErr);
        // Continue with response even if email fails
      }

      res.json({
        user: {
          id: result.insertId,
          fullName,
          email,
          userType: "Administrator",
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        },
        message: "Admin registered successfully",
      });
    } catch (err) {
      console.error("Admin register error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Customer/Vendor signup

// Email sending function with dynamic login URL
const sendWelcomeEmail = async (email, fullName, userType, password) => {
  try {
    const role = userType.charAt(0).toUpperCase() + userType.slice(1);
    const loginUrl =
      userType === "customer"
        ? "https://studiosignaturecabinets.com/customer/login"
        : "https://studiosignaturecabinets.com/vendor/";
    const mailOptions = {
      from: `"Admin Panel" < "sssdemo6@gmail.com"}>`,
      to: email,
      subject: `Welcome to Studio Signature Cabinets - Your ${role} Account Details`,
      html: `
        <h2>Welcome, ${fullName}!</h2>
        <p>Your ${role} account has been successfully created by the admin.</p>
        <p><strong>Login Details:</strong></p>
        <ul>
          <li><strong>Email:</strong> ${email}</li>
          <li><strong>Temporary Password:</strong> ${password}</li>
        </ul>
        <p>Please log in to our platform at <a href="${loginUrl}">${loginUrl}</a> using these credentials.</p>
        <p>For security, we recommend changing your password immediately after logging in. You can do this in your profile settings .</p>
        <p>If you have any questions, contact our support team at info@studiosignaturecabinets.com.</p>
        <p>Best regards,<br>The Studio Signature Cabinets Team</p>
      `,
    };

    await transporter.sendMail(mailOptions);
    console.log(`Welcome email sent to ${email}`);
  } catch (err) {
    console.error("Email sending error:", err);
    // Do not throw error to avoid affecting signup response
  }
};

app.post(
  "/api/adminuserpanel/signup",
  adminauthenticateToken,
  async (req, res) => {
    const {
      userType,
      fullName,
      email,
      password,
      confirmPassword,
      companyName,
      taxId,
      phone,
      address,
      agreeTerms,
    } = req.body;

    // Validate input
    if (
      !userType ||
      !fullName ||
      !email ||
      !password ||
      !confirmPassword ||
      (userType === "vendor" && (!companyName || !taxId || !phone || !address))
    ) {
      return res
        .status(400)
        .json({ error: "All required fields must be provided" });
    }
    if (!["customer", "vendor"].includes(userType)) {
      return res.status(400).json({ error: "Invalid user type" });
    }
    if (!validateEmail(email)) {
      return res.status(400).json({ error: "Invalid email address" });
    }
    if (!validatePassword(password)) {
      return res.status(400).json({
        error:
          "Password must be at least 8 characters long and include uppercase, lowercase, number, and special character",
      });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ error: "Passwords do not match" });
    }
    if (phone && !validatePhone(phone)) {
      return res
        .status(400)
        .json({ error: "Phone number must be exactly 10 digits" });
    }

    try {
      // Check if email exists in users or admin table
      const [userEmail] = await pool.query(
        "SELECT id FROM users WHERE email = ?",
        [email]
      );

      if (userEmail.length > 0) {
        return res.status(400).json({ error: "Email already exists" });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Insert user
      const [result] = await pool.query(
        `INSERT INTO users 
        (user_type, full_name, email, password, company_name, tax_id, phone, address, account_status, is_active, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Active', 1, NOW(), NOW())`,
        [
          userType,
          fullName,
          email,
          hashedPassword,
          companyName || null,
          taxId || null,
          phone || null,
          address || null,
        ]
      );

      // Send welcome email with dynamic login URL
      await sendWelcomeEmail(email, fullName, userType, password);

      res.json({
        user: {
          id: result.insertId,
          fullName,
          email,
          userType,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        },
        message: `${
          userType.charAt(0).toUpperCase() + userType.slice(1)
        } registered successfully`,
      });
    } catch (err) {
      console.error("Signup error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// app.post(
//   "/api/adminuserpanel/signup",
//   adminauthenticateToken,
//   async (req, res) => {
//     const {
//       userType,
//       fullName,
//       email,
//       password,
//       confirmPassword,
//       companyName,
//       taxId,
//       phone,
//       address,
//       agreeTerms,
//     } = req.body;

//     // Validate input
//     if (
//       !userType ||
//       !fullName ||
//       !email ||
//       !password ||
//       !confirmPassword ||
//       (userType === "vendor" && (!companyName || !taxId || !phone || !address))
//     ) {
//       return res
//         .status(400)
//         .json({ error: "All required fields must be provided" });
//     }
//     if (!["customer", "vendor"].includes(userType)) {
//       return res.status(400).json({ error: "Invalid user type" });
//     }
//     if (!validateEmail(email)) {
//       return res.status(400).json({ error: "Invalid email address" });
//     }
//     if (!validatePassword(password)) {
//       return res.status(400).json({
//         error:
//           "Password must be at least 8 characters long and include uppercase, lowercase, number, and special character",
//       });
//     }
//     if (password !== confirmPassword) {
//       return res.status(400).json({ error: "Passwords do not match" });
//     }
//     if (phone && !validatePhone(phone)) {
//       return res
//         .status(400)
//         .json({ error: "Phone number must be exactly 10 digits" });
//     }

//     try {
//       // Check if email exists in users or admin table
//       const [userEmail] = await pool.query(
//         "SELECT id FROM users WHERE email = ?",
//         [email]
//       );

//       if (userEmail.length > 0) {
//         return res.status(400).json({ error: "Email already exists" });
//       }

//       // Hash password
//       const hashedPassword = await bcrypt.hash(password, 10);

//       // Insert user
//       const [result] = await pool.query(
//         `INSERT INTO users
//       (user_type, full_name, email, password, company_name, tax_id, phone, address, account_status, is_active, created_at, updated_at)
//       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Active', 1, NOW(), NOW())`,
//         [
//           userType,
//           fullName,
//           email,
//           hashedPassword,
//           companyName || null,
//           taxId || null,
//           phone || null,
//           address || null,
//         ]
//       );

//       res.json({
//         user: {
//           id: result.insertId,
//           fullName,
//           email,
//           userType,
//           created_at: new Date().toISOString(),
//           updated_at: new Date().toISOString(),
//         },
//         message: `${
//           userType.charAt(0).toUpperCase() + userType.slice(1)
//         } registered successfully`,
//       });
//     } catch (err) {
//       console.error("Signup error:", err);
//       res.status(500).json({ error: "Server error" });
//     }
//   }
// );

// Delete a user from users table

app.delete(
  "/api/adminuserpanel/users/:id",
  adminauthenticateToken,
  async (req, res) => {
    const { id } = req.params;
    console.log(`Attempting to delete user ID ${id} from users table`); // Debug log

    try {
      const [result] = await pool.query("DELETE FROM users WHERE id = ?", [id]);
      console.log(`Delete user result:`, result); // Debug log
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: "User not found" });
      }
      res.json({ message: "User deleted successfully" });
    } catch (err) {
      console.error("Delete user error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Delete an admin from admin table
app.delete(
  "/api/adminuserpanel/admins/:id",
  adminauthenticateToken,
  async (req, res) => {
    const { id } = req.params;
    const adminId = req.admin.id; // From decoded token
    console.log(`Attempting to delete admin ID ${id} by admin ID ${adminId}`); // Debug log

    try {
      // Prevent self-deletion
      if (parseInt(id) === adminId) {
        return res
          .status(403)
          .json({ error: "Cannot delete your own account" });
      }

      const [result] = await pool.query("DELETE FROM admins WHERE id = ?", [
        id,
      ]);
      console.log(`Delete admin result:`, result); // Debug log
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: "Admin not found" });
      }
      res.json({ message: "Admin deleted successfully" });
    } catch (err) {
      console.error("Delete admin error:", err);
      res.status(500).json({ error: err.message || "Server error" });
    }
  }
);

// app.get("/api/admin/vendorproducts",adminauthenticateToken,
//   async (req, res) => {
//     try {
//       const { vendor_id } = req.query;
//       let query =
//         "SELECT product_id, vendor_id, name, category, sku, price, currency, in_stock, lead_time, image_url, description, created_at, updated_at FROM vendorproducts WHERE 1=1";
//       const params = [];

//       if (vendor_id) {
//         query += " AND vendor_id = ?";
//         params.push(vendor_id);
//       }

//       const [rows] = await pool.query(query, params);
//       res.json(rows);
//     } catch (err) {
//       console.error("Error fetching vendor products:", err);
//       res.status(500).json({ error: "Failed to fetch vendor products" });
//     }
//   }
// );

// GET /api/items?sku=<sku>&item_type=<item_type>&color=<color>


app.get(
  "/api/admin/vendorproducts",
  adminauthenticateToken,
  async (req, res) => {
    try {
      const { vendor_id } = req.query;
      let query =
        "SELECT product_id, vendor_id, name, category, sku, price, currency, in_stock, lead_time, image_url, description, created_at, updated_at FROM vendorproducts WHERE 1=1";
      const params = [];

      if (vendor_id) {
        query += " AND vendor_id = ?";
        params.push(vendor_id);
      }

      const [rows] = await pool.query(query, params);

      // Transform image_url to absolute URLs
      const updatedRows = rows.map((product) => ({
        ...product,
        image_url: product.image_url?.startsWith("http")
          ? product.image_url
          : `${req.protocol}://${req.get("host")}${product.image_url}`,
      }));

      res.json(updatedRows);
    } catch (err) {
      console.error("Error fetching vendor products:", err);
      res.status(500).json({ error: "Failed to fetch vendor products" });
    }
  }
);


app.get("/api/admin/items", adminauthenticateToken, async (req, res) => {
  try {
    const { sku, item_type, color } = req.query;
    let query =
      "SELECT id, sku, description, item_type, search_description, unit_of_measure, price, weight, cube, cw, gr, se, sw, created_at, updated_at, color FROM items WHERE 1=1";
    const params = [];

    if (sku) {
      query += " AND sku LIKE ?";
      params.push(`%${sku}%`);
    }
    if (item_type) {
      query += " AND item_type = ?";
      params.push(item_type.toUpperCase());
    }
    if (color) {
      query += " AND color = ?";
      params.push(color);
    }

    const [rows] = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    console.error("Error fetching items:", err);
    res.status(500).json({ error: "Failed to fetch items" });
  }
});

// POST /api/admin/items
app.post("/api/admin/items", adminauthenticateToken, async (req, res) => {
  try {
    const {
      sku,
      description,
      item_type,
      unit_of_measure,
      color,
      price,
      search_description,
      weight,
      cube,
      cw,
      gr,
      se,
      sw,
    } = req.body;

    if (
      !sku ||
      !description ||
      !item_type ||
      !unit_of_measure ||
      !color ||
      price == null
    ) {
      return res.status(400).json({
        error:
          "Missing required fields: sku, description, item_type, unit_of_measure, color, price",
      });
    }

    const [result] = await pool.query(
      "INSERT INTO items (sku, description, item_type, search_description, unit_of_measure, color, price, weight, cube, cw, gr, se, sw) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      [
        sku,
        description,
        item_type.toUpperCase(),
        search_description || null,
        unit_of_measure,
        color,
        price,
        weight || null,
        cube || null,
        cw || null,
        gr || null,
        se || null,
        sw || null,
      ]
    );

    const [newItem] = await pool.query("SELECT * FROM items WHERE id = ?", [
      result.insertId,
    ]);
    res.status(201).json(newItem[0]);
  } catch (err) {
    console.error("Error creating item:", err);
    res.status(500).json({ error: "Failed to create item" });
  }
});

// PUT /api/items/:id
app.put("/api/admin/items/:id", adminauthenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { sku, description, item_type, unit_of_measure, color, price } =
      req.body;

    if (
      !sku ||
      !description ||
      !item_type ||
      !unit_of_measure ||
      !color ||
      price == null
    ) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const [result] = await pool.query(
      "UPDATE items SET sku = ?, description = ?, item_type = ?, unit_of_measure = ?, color = ?, price = ?, updated_at = NOW() WHERE id = ?",
      [
        sku,
        description,
        item_type.toUpperCase(),
        unit_of_measure,
        color,
        price,
        id,
      ]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Item not found" });
    }

    res.json({ message: "Item updated successfully" });
  } catch (err) {
    console.error("Error updating item:", err);
    res.status(500).json({ error: "Failed to update item" });
  }
});

// DELETE /api/items/:id
app.delete("/api/admin/items/:id", adminauthenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const [result] = await pool.query("DELETE FROM items WHERE id = ?", [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Item not found" });
    }

    res.json({ message: "Item deleted successfully" });
  } catch (err) {
    console.error("Error deleting item:", err);
    res.status(500).json({ error: "Failed to delete item" });
  }
});

app.post("/api/admin/import-items", async (req, res) => {
  let connection;

  try {
    // Get a connection from the pool
    connection = await pool.getConnection();

    // Read Excel file (adjust file path as needed)
    const filePath = "SSC MASTER LIST.xlsx";
    const workbook = XLSX.readFile(filePath);
    const sheet = workbook.Sheets[workbook.SheetNames[0]];
    const data = XLSX.utils.sheet_to_json(sheet);

    if (data.length === 0) {
      throw new Error("Excel file is empty or has no data rows");
    }

    console.log("Excel headers:", Object.keys(data[0]));

    let skippedRows = [];

    await connection.beginTransaction();

    for (const [index, item] of data.entries()) {
      // Normalize keys
      const itemKeys = Object.keys(item).reduce((acc, key) => {
        acc[key.toLowerCase().trim()] = item[key];
        return acc;
      }, {});

      // Map fields
      const sku = itemKeys["no"] ? String(itemKeys["no"]).trim() : null;
      const description = itemKeys["description"]
        ? String(itemKeys["description"]).trim()
        : null;
      const color = itemKeys["color"] ? String(itemKeys["color"]).trim() : null;
      const item_type = itemKeys["description 2"]
        ? String(itemKeys["description 2"]).trim()
        : "STAINED PLYWOOD";
      const search_description = itemKeys["search description"]
        ? String(itemKeys["search description"]).trim()
        : null;
      const unit_of_measure = itemKeys["base unit of measure"]
        ? String(itemKeys["base unit of measure"]).trim()
        : "NOS";
      const price =
        itemKeys["unit price"] !== undefined
          ? parseFloat(itemKeys["unit price"])
          : null;

      console.log(
        `Row ${index + 2}: SKU = ${sku}, Description = ${description}`
      );

      if (!sku || !description) {
        skippedRows.push({
          row: index + 2,
          item,
          reason: `Missing SKU or Description`,
        });
        continue;
      }

      await connection.query(
        `INSERT INTO items (
          sku, description, item_type, search_description, unit_of_measure, price, color,
          weight, cube, cw, gr, se, sw
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          sku,
          description,
          item_type,
          search_description,
          unit_of_measure,
          price,
          color,
          null,
          null,
          null,
          null,
          null,
          null,
        ]
      );
    }

    await connection.commit();

    res.json({
      message: "Data imported successfully",
      skippedRows,
    });
  } catch (err) {
    console.error("Error importing data:", err);
    if (connection) {
      await connection.rollback();
    }
    res
      .status(500)
      .json({ error: "Failed to import data", details: err.message });
  } finally {
    if (connection) {
      connection.release(); // Return connection to the pool
    }
  }
});

app.get("/api/invoice/profile", adminauthenticateToken, async (req, res) => {
  try {
    const customerId = req.query.customer_id;
    if (!customerId) {
      return res.status(400).json({ error: "customer_id is required" });
    }

    const [users] = await pool.query(
      "SELECT id, full_name, email, phone, created_at, last_login, account_status, is_active, company_name, address, admin_discount, updated_at FROM users WHERE user_type = 'customer' AND id = ?",
      [customerId]
    );

    if (users.length === 0) {
      return res.status(404).json({ error: "Customer not found" });
    }

    const user = users[0];
    res.json({
      id: user.id,
      fullName: user.full_name,
      email: user.email,
      phone: user.phone,
      joinDate: user.created_at,
      lastLogin: user.last_login || null,
      account_status: user.account_status,
      is_active: user.is_active,
      company_name: user.company_name,
      address: user.address,
      admin_discount: user.admin_discount,
      updated_at: user.updated_at,
    });
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/admin/invoices", adminauthenticateToken, async (req, res) => {
  try {
    // Fetch all invoices with order details
    const [invoices] = await pool.query(
      `SELECT i.*, o.id AS order_internal_id, o.order_id, o.bill_to, o.account
       FROM invoices i
       LEFT JOIN orders o ON i.order_id = o.id`
    );

    // Fetch all order items for the invoices
    const orderIds = invoices
      .map((invoice) => invoice.order_internal_id)
      .filter((id) => id);
    let items = [];
    if (orderIds.length > 0) {
      const [orderItems] = await pool.query(
        `SELECT oi.order_id, oi.sku, oi.name, oi.quantity, oi.door_style, oi.finish, oi.price, oi.total_amount
         FROM order_items oi
         WHERE oi.order_id IN (?)`,
        [orderIds]
      );
      items = orderItems;
    }

    // Associate items with their respective invoices
    const invoicesWithItems = invoices.map((invoice) => ({
      id: invoice.id,
      invoice_number: invoice.invoice_number,
      order_id: invoice.order_id, // String order_id from orders table (e.g., "S-ORD101127")
      customer_id: invoice.user_id, // Map user_id to customer_id for frontend
      issue_date: invoice.issue_date,
      subtotal: parseFloat(invoice.subtotal) || 0,
      tax: parseFloat(invoice.tax) || 0,
      shipping: invoice.shipping !== null ? parseFloat(invoice.shipping) : null,
      discount: parseFloat(invoice.discount) || 0,
      additional_discount: parseFloat(invoice.additional_discount) || 0,
      total: parseFloat(invoice.total) || 0,
      items: items
        .filter((item) => item.order_id === invoice.order_internal_id)
        .map((item) => ({
          sku: item.sku,
          name: item.name,
          quantity: item.quantity,
          door_style: item.door_style || null,
          finish: item.finish || null,
          price: parseFloat(item.price) || 0,
          total_amount: parseFloat(item.total_amount) || 0,
        })),
      bill_to: invoice.bill_to || null,
      account: invoice.account || null,
      finish_type: invoice.finish_type || null,
      door_style: invoice.door_style || null,
    }));

    res.json(invoicesWithItems);
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/admin/products - Fetch all products
app.get("/api/admin/products", adminauthenticateToken, async (req, res) => {
  try {
    const [products] = await pool.query(
      `SELECT id, name, item_type, color, photo_path, is_visible, created_at, updated_at
       FROM products`
    );
    res.json(
      products.map((product) => ({
        id: product.id,
        name: product.name,
        item_type: product.item_type,
        color: product.color,
        photo_path: product.photo_path
          ? `${req.protocol}://${req.get("host")}${product.photo_path}`
          : null,
        is_visible: product.is_visible,
        created_at: product.created_at,
        updated_at: product.updated_at,
      }))
    );
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/admin/products/filters - Fetch unique item_type and color values
app.get(
  "/api/admin/products/filters",
  adminauthenticateToken,
  async (req, res) => {
    try {
      const [itemTypes] = await pool.query(
        `SELECT DISTINCT item_type FROM products`
      );
      const [colors] = await pool.query(`SELECT DISTINCT color FROM products`);
      res.json({
        item_types: itemTypes.map((row) => row.item_type),
        colors: colors.map((row) => row.color),
      });
    } catch (err) {
      console.error("Server error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// POST /api/admin/products - Add a new product
app.post(
  "/api/admin/products",
  adminauthenticateToken,
  upload.single("photo"),
  async (req, res) => {
    try {
      const { name, item_type, color } = req.body;
      if (!name || !item_type || !color) {
        return res
          .status(400)
          .json({ error: "All required fields must be provided" });
      }

      const photo_path = req.file ? `/Uploads/${req.file.filename}` : null;
      const is_visible = req.body.is_visible === "true" ? 1 : 0;

      const [result] = await pool.query(
        `INSERT INTO products (name, item_type, color, photo_path, is_visible)
       VALUES (?, ?, ?, ?, ?)`,
        [name, item_type, color, photo_path, is_visible]
      );

      res.json({
        id: result.insertId,
        name,
        item_type,
        color,
        photo_path: photo_path
          ? `${req.protocol}://${req.get("host")}${photo_path}`
          : null,
        is_visible,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      });
    } catch (err) {
      console.error("Server error:", err);
      res.status(500).json({ error: err.message || "Server error" });
    }
  }
);

// PUT /api/admin/products/:id - Update a product
app.put(
  "/api/admin/products/:id",
  adminauthenticateToken,
  upload.single("photo"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { name, item_type, color, is_visible } = req.body;

      // For toggle visibility, only is_visible may be sent
      if (
        !name &&
        !item_type &&
        !color &&
        !req.file &&
        is_visible === undefined
      ) {
        return res
          .status(400)
          .json({ error: "At least one field must be provided" });
      }

      // Get current product data
      const [currentProduct] = await pool.query(
        `SELECT * FROM products WHERE id = ?`,
        [id]
      );
      if (currentProduct.length === 0) {
        return res.status(404).json({ error: "Product not found" });
      }

      // Use existing values if not provided
      const updatedName = name || currentProduct[0].name;
      const updatedItemType = item_type || currentProduct[0].item_type;
      const updatedColor = color || currentProduct[0].color;
      const updatedPhotoPath = req.file
        ? `/Uploads/${req.file.filename}`
        : currentProduct[0].photo_path;
      const updatedIsVisible =
        is_visible !== undefined
          ? is_visible === "true" || is_visible === 1
            ? 1
            : 0
          : currentProduct[0].is_visible;

      const [result] = await pool.query(
        `UPDATE products
       SET name = ?, item_type = ?, color = ?, photo_path = ?, is_visible = ?
       WHERE id = ?`,
        [
          updatedName,
          updatedItemType,
          updatedColor,
          updatedPhotoPath,
          updatedIsVisible,
          id,
        ]
      );

      if (result.affectedRows === 0) {
        return res.status(404).json({ error: "Product not found" });
      }

      res.json({
        id: parseInt(id),
        name: updatedName,
        item_type: updatedItemType,
        color: updatedColor,
        photo_path: updatedPhotoPath
          ? `${req.protocol}://${req.get("host")}${updatedPhotoPath}`
          : null,
        is_visible: updatedIsVisible,
        updated_at: new Date().toISOString(),
      });
    } catch (err) {
      console.error("Server error:", err);
      res.status(500).json({ error: err.message || "Server error" });
    }
  }
);

// DELETE /api/admin/products/:id - Delete a product
app.delete(
  "/api/admin/products/:id",
  adminauthenticateToken,
  async (req, res) => {
    try {
      const { id } = req.params;
      const [result] = await pool.query(`DELETE FROM products WHERE id = ?`, [
        id,
      ]);
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: "Product not found" });
      }
      res.json({ message: "Product deleted successfully" });
    } catch (err) {
      console.error("Server error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Get all messages for all vendors (admin view)
app.get(
  "/api/admin/vendors/messages",
  adminauthenticateToken,
  async (req, res) => {
    const connection = await pool.getConnection();
    try {
      // Fetch messages joined with vendor details
      const [messages] = await connection.query(
        `select * from vendor_messages`
      );
      res.json(messages);
    } catch (error) {
      console.error("Error fetching admin messages:", error);
      res.status(500).json({ error: "Failed to fetch messages" });
    } finally {
      connection.release();
    }
  }
);

// Send a reply to a specific vendor
app.post(
  "/api/admin/vendors/:vendorId/messages",
  adminauthenticateToken,
  async (req, res) => {
    const { vendorId } = req.params;
    const { content } = req.body;

    if (!content || content.trim() === "") {
      return res.status(400).json({ error: "Message content is required" });
    }

    const connection = await pool.getConnection();
    try {
      // Verify vendor exists
      const [vendor] = await connection.query(
        "SELECT id FROM users WHERE id = ?",
        [vendorId]
      );
      if (!vendor.length) {
        return res.status(404).json({ error: "Vendor not found" });
      }

      // Insert admin reply
      const [result] = await connection.query(
        "INSERT INTO vendor_messages (vendor_id, sender, content, is_user, avatar) VALUES (?, ?, ?, ?, ?)",
        [
          vendorId,
          "SSC Support Team",
          content,
          0,
          "https://static.vecteezy.com/system/resources/previews/022/132/452/large_2x/personal-id-icon-logo-design-vector.jpg",
        ]
      );

      res.status(201).json({
        id: result.insertId,
        vendor_id: vendorId,
        sender: "SSC Support Team",
        content,
        is_user: 0,
        avatar:
          "https://static.vecteezy.com/system/resources/previews/022/132/452/large_2x/personal-id-icon-logo-design-vector.jpg",
        timestamp: new Date(),
      });
    } catch (error) {
      console.error("Error sending admin message:", error);
      res.status(500).json({ error: "Failed to send message" });
    } finally {
      connection.release();
    }
  }
);

app.post("/api/admin/rfqs", adminauthenticateToken, async (req, res) => {
  const { title, description, location, deadline, items, attachments } =
    req.body;
  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    // Validate input
    if (!title || !description || !location || !deadline) {
      await connection.rollback();
      return res.status(400).json({
        error: "Title, description, location, and deadline are required",
      });
    }

    // Insert RFQ
    const [rfqResult] = await connection.query(
      "INSERT INTO rfqs (title, description, location, deadline, state, created_at, updated_at) VALUES (?, ?, ?, ?, 'Open', NOW(), NOW())",
      [title, description, location, deadline]
    );
    const rfqId = rfqResult.insertId;

    // Insert items
    if (items && items.length > 0) {
      for (const item of items) {
        if (!item.name || !item.quantity || !item.unit) {
          await connection.rollback();
          return res
            .status(400)
            .json({ error: "Item name, quantity, and unit are required" });
        }
        await connection.query(
          "INSERT INTO rfq_items (rfq_id, name, quantity, unit) VALUES (?, ?, ?, ?)",
          [rfqId, item.name, item.quantity, item.unit]
        );
      }
    }

    // Insert attachments
    if (attachments && attachments.length > 0) {
      for (const attachment of attachments) {
        await connection.query(
          "INSERT INTO rfq_attachments (rfq_id, file_name) VALUES (?, ?)",
          [rfqId, attachment]
        );
      }
    }

    // Notify all vendors
    const [vendors] = await connection.query(
      "SELECT id, full_name, email FROM users WHERE user_type = 'vendor' AND is_active = 1"
    );
    for (const vendor of vendors) {
      try {
        const mailOptions = {
          from: `"Admin Panel" <${
            process.env.EMAIL_USER || "your-email@gmail.com"
          }>`,
          to: vendor.email,
          subject: `New RFQ Available: RFQ #${rfqId}`,
          html: `
              <h2>Hello, ${vendor.full_name}!</h2>
              <p>A new Request for Quote (RFQ #${rfqId}) is available.</p>
              <p><strong>RFQ Details:</strong></p>
              <ul>
                <li><strong>Title:</strong> ${title}</li>
                <li><strong>Deadline:</strong> ${formatDateForDisplay(
                  deadline
                )}</li>
              </ul>
              <p>View and submit your quote at <a href="https://studiosignaturecabinets.com/vendor/">https://studiosignaturecabinets.com/vendor/</a>.</p>
              <p>Best regards,<br>The Studio Signature Cabinets Team</p>
            `,
        };
        await transporter.sendMail(mailOptions);
        console.log(`RFQ notification sent to ${vendor.email}`);
      } catch (emailErr) {
        console.error(`Email sending error to ${vendor.email}:`, emailErr);
      }
    }

    await connection.commit();
    res.json({ rfq_id: rfqId, message: "RFQ created successfully" });
  } catch (error) {
    await connection.rollback();
    console.error("Error creating RFQ:", error);
    res.status(500).json({ error: "Failed to create RFQ" });
  } finally {
    connection.release();
  }
});

app.get("/api/admin/rfqs", adminauthenticateToken, async (req, res) => {
  const { search, state } = req.query;
  const connection = await pool.getConnection();

  try {
    let query = "SELECT * FROM rfqs";
    const queryParams = [];

    if (search || state) {
      query += " WHERE ";
      const conditions = [];

      if (search) {
        conditions.push("(rfq_id LIKE ? OR title LIKE ? OR location LIKE ?)");
        queryParams.push(`%${search}%`, `%${search}%`, `%${search}%`);
      }

      if (state) {
        conditions.push("state = ?");
        queryParams.push(state);
      }

      query += conditions.join(" AND ");
    }

    const [rfqs] = await connection.query(query, queryParams);

    for (let rfq of rfqs) {
      const [items] = await connection.query(
        "SELECT * FROM rfq_items WHERE rfq_id = ?",
        [rfq.rfq_id]
      );
      const [attachments] = await connection.query(
        "SELECT * FROM rfq_attachments WHERE rfq_id = ?",
        [rfq.rfq_id]
      );
      const [quoteCount] = await connection.query(
        "SELECT COUNT(*) as count FROM quotes WHERE rfq_id = ?",
        [rfq.rfq_id]
      );
      rfq.items = items;
      rfq.attachments = attachments.map((a) => a.file_name);
      rfq.quote_count = quoteCount[0].count;
    }

    res.json(rfqs);
  } catch (error) {
    console.error("Error fetching RFQs:", error);
    res.status(500).json({ error: "Failed to fetch RFQs" });
  } finally {
    connection.release();
  }
});

app.get("/api/admin/rfqs/:id", adminauthenticateToken, async (req, res) => {
  const connection = await pool.getConnection();

  try {
    const [rfq] = await connection.query(
      "SELECT * FROM rfqs WHERE rfq_id = ?",
      [req.params.id]
    );
    if (!rfq[0]) return res.status(404).json({ error: "RFQ not found" });

    const [items] = await connection.query(
      "SELECT * FROM rfq_items WHERE rfq_id = ?",
      [req.params.id]
    );
    const [attachments] = await connection.query(
      "SELECT * FROM rfq_attachments WHERE rfq_id = ?",
      [req.params.id]
    );
    const [quotes] = await connection.query(
      "SELECT q.*, u.full_name, u.company_name as vendor_name FROM quotes q JOIN users u ON q.vendor_id = u.id WHERE q.rfq_id = ?",
      [req.params.id]
    );

    rfq[0].items = items;
    rfq[0].attachments = attachments.map((a) => a.file_name);
    rfq[0].quotes = quotes;

    res.json(rfq[0]);
  } catch (error) {
    console.error("Error fetching RFQ:", error);
    res.status(500).json({ error: "Failed to fetch RFQ" });
  } finally {
    connection.release();
  }
});

app.put(
  "/api/admin/rfqs/:id/quote/:quote_id/accept",
  adminauthenticateToken,
  async (req, res) => {
    const connection = await pool.getConnection();

    try {
      await connection.beginTransaction();

      const [rfq] = await connection.query(
        "SELECT * FROM rfqs WHERE rfq_id = ?",
        [req.params.id]
      );
      if (!rfq[0]) {
        await connection.rollback();
        return res.status(404).json({ error: "RFQ not found" });
      }

      const [quote] = await connection.query(
        "SELECT * FROM quotes WHERE quote_id = ? AND rfq_id = ?",
        [req.params.quote_id, req.params.id]
      );
      if (!quote[0]) {
        await connection.rollback();
        return res.status(404).json({ error: "Quote not found" });
      }

      await connection.query(
        "UPDATE quotes SET status = 'Accepted' WHERE quote_id = ?",
        [req.params.quote_id]
      );
      await connection.query(
        "UPDATE quotes SET status = 'Rejected', rejection_reason = 'Another quote was accepted' WHERE rfq_id = ? AND quote_id != ?",
        [req.params.id, req.params.quote_id]
      );
      await connection.query(
        "UPDATE rfqs SET state = 'Closed' WHERE rfq_id = ?",
        [req.params.id]
      );

      // Notify vendors
      const [vendors] = await connection.query(
        "SELECT q.*, u.full_name, u.email FROM quotes q JOIN users u ON q.vendor_id = u.id WHERE q.rfq_id = ?",
        [req.params.id]
      );
      for (const vendor of vendors) {
        try {
          const mailOptions = {
            from: `"Admin Panel" <${
              process.env.EMAIL_USER || "your-email@gmail.com"
            }>`,
            to: vendor.email,
            subject: `RFQ #${req.params.id} Quote Update`,
            html: `
              <h2>Hello, ${vendor.full_name}!</h2>
              <p>Your quote for RFQ #${req.params.id} has been ${
              vendor.quote_id == req.params.quote_id ? "accepted" : "rejected"
            }.</p>
              ${
                vendor.quote_id == req.params.quote_id
                  ? `
                  <p><strong>Quote Details:</strong></p>
                  <ul>
                    <li><strong>Total Amount:</strong> ${
                      vendor.currency
                    } ${Number(vendor.total_amount).toFixed(2)}</li>
                    <li><strong>Lead Time:</strong> ${vendor.lead_time}</li>
                  </ul>
                  <p>Please proceed with the next steps via <a href="https://studiosignaturecabinets.com/vendor/">https://studiosignaturecabinets.com/vendor/</a>.</p>
                `
                  : `
                  <p><strong>Reason:</strong> Another quote was accepted.</p>
                  <p>View details at <a href="https://studiosignaturecabinets.com/vendor/">https://studiosignaturecabinets.com/vendor/</a>.</p>
                `
              }
              <p>Best regards,<br>The Studio Signature Cabinets Team</p>
            `,
          };
          await transporter.sendMail(mailOptions);
          console.log(`Notification sent to ${vendor.email}`);
        } catch (emailErr) {
          console.error(`Email sending error to ${vendor.email}:`, emailErr);
        }
      }

      await connection.commit();
      res.json({ message: "Quote accepted, RFQ closed" });
    } catch (error) {
      await connection.rollback();
      console.error("Error accepting quote:", error);
      res.status(500).json({ error: "Failed to accept quote" });
    } finally {
      connection.release();
    }
  }
);

app.put(
  "/api/admin/rfqs/:id/quote/:quote_id/reject",
  adminauthenticateToken,
  async (req, res) => {
    const { rejection_reason } = req.body;
    const connection = await pool.getConnection();

    try {
      await connection.beginTransaction();

      const [quote] = await connection.query(
        "SELECT * FROM quotes WHERE quote_id = ? AND rfq_id = ?",
        [req.params.quote_id, req.params.id]
      );
      if (!quote[0]) {
        await connection.rollback();
        return res.status(404).json({ error: "Quote not found" });
      }

      await connection.query(
        "UPDATE quotes SET status = 'Rejected', rejection_reason = ? WHERE quote_id = ?",
        [rejection_reason, req.params.quote_id]
      );

      const [vendor] = await connection.query(
        "SELECT u.full_name, u.email FROM users u JOIN quotes q ON u.id = q.vendor_id WHERE q.quote_id = ?",
        [req.params.quote_id]
      );

      try {
        const mailOptions = {
          from: `"Admin Panel" <${
            process.env.EMAIL_USER || "your-email@gmail.com"
          }>`,
          to: vendor[0].email,
          subject: `RFQ #${req.params.id} Quote Rejected`,
          html: `
            <h2>Hello, ${vendor[0].full_name}!</h2>
            <p>Your quote for RFQ #${req.params.id} has been rejected.</p>
            <p><strong>Reason:</strong> ${rejection_reason}</p>
            <p>View details at <a href="https://studiosignaturecabinets.com/vendor/">https://studiosignaturecabinets.com/vendor/</a>.</p>
            <p>Best regards,<br>The Studio Signature Cabinets Team</p>
          `,
        };
        await transporter.sendMail(mailOptions);
        console.log(`Rejection notification sent to ${vendor[0].email}`);
      } catch (emailErr) {
        console.error(`Email sending error to ${vendor[0].email}:`, emailErr);
      }

      await connection.commit();
      res.json({ message: "Quote rejected" });
    } catch (error) {
      await connection.rollback();
      console.error("Error rejecting quote:", error);
      res.status(500).json({ error: "Failed to reject quote" });
    } finally {
      connection.release();
    }
  }
);

//-----------------------------------------------------------------------Vendor API Endpoints-----------------------------------------------------------------------

// Multer configuration for image uploads
const imageStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, "uploads");
    require("fs").mkdirSync(uploadDir, { recursive: true });
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});

const imageUpload = multer({
  storage: imageStorage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB limit
  fileFilter: (req, file, cb) => {
    const filetypes = /jpg|jpeg|png/;
    const extname = filetypes.test(
      path.extname(file.originalname).toLowerCase()
    );
    const mimetype = filetypes.test(file.mimetype);
    if (extname && mimetype) {
      cb(null, true);
    } else {
      cb(new Error("Only JPG and PNG files are allowed"));
    }
  },
});

// Vendor Login API
app.post("/api/vendor/login", async (req, res) => {
  const { email, password } = req.body;

  // Validation
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Invalid email format" });
  }

  try {
    // Fetch user with vendor type
    const [users] = await pool.query(
      "SELECT * FROM users WHERE email = ? AND user_type = ?",
      [email, "vendor"]
    );

    if (users.length === 0) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const vendor = users[0];

    // Check if vendor is active
    if (!vendor.is_active) {
      return res.status(403).json({ error: "Account is inactive" });
    }
    if (!vendor.account_status || vendor.account_status !== "Active") {
      return res.status(403).json({ error: "Account is inactive" });
    }

    // Check if user is a vendor
    if (vendor.user_type !== "vendor") {
      return res.status(403).json({ error: "Only vendors can log in" });
    }

    // Verify password
    const isMatch = await bcrypt.compare(password, vendor.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    // Update last login
    await pool.query("UPDATE users SET last_login = NOW() WHERE id = ?", [
      vendor.id,
    ]);

    // Create JWT with token_version
    const token = jwt.sign(
      {
        id: vendor.id,
        email: vendor.email,
        token_version: vendor.token_version,
      },
      JWT_SECRET,
      { expiresIn: "1d" }
    );

    // Respond with token and vendor details
    res.json({
      token,
      vendor: {
        id: vendor.id,
        email: vendor.email,
        full_name: vendor.full_name,
        user_type: vendor.user_type,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/vendor/logout
app.post("/api/vendor/logout", authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    // Verify user is a vendor
    const [users] = await pool.query(
      "SELECT user_type, token_version FROM users WHERE id = ?",
      [userId]
    );
    if (users.length === 0 || users[0].user_type !== "vendor") {
      console.log(`Logout attempt failed: User ID ${userId} is not a vendor`);
      return res
        .status(403)
        .json({ error: "Only vendors can log out from this endpoint" });
    }

    // Increment token_version to invalidate existing tokens
    await pool.query(
      "UPDATE users SET token_version = token_version + 1 WHERE id = ?",
      [userId]
    );
    console.log(`User ID ${userId} logged out, token_version incremented`);

    // Add cache-control headers
    res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
    res.status(200).json({ message: "Logged out successfully" });
  } catch (err) {
    console.error("Logout error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Vendor Token Verification API
app.get("/api/vendor/verify", authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const tokenVersion = req.user.token_version;

  try {
    const [users] = await pool.query(
      "SELECT token_version, user_type FROM users WHERE id = ?",
      [userId]
    );
    if (users.length === 0 || users[0].user_type !== "vendor") {
      return res.status(403).json({ error: "Invalid user" });
    }
    if (users[0].token_version !== tokenVersion) {
      return res.status(401).json({ error: "Token is invalid" });
    }
    res.status(200).json({ valid: true });
  } catch (err) {
    console.error("Token verification error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/profilevendor", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    // Fetch user data
    const [users] = await pool.query(
      `SELECT id, user_type, full_name, email, phone, company_name, tax_id, address, 
              city, state, postal_code, country, account_status ,notes
       FROM users 
       WHERE id = ?`,
      [userId]
    );

    if (users.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    // Fetch banking information
    const [banking] = await pool.query(
      `SELECT bank_name, account_number, routing_number, currency 
       FROM vendor_banking 
       WHERE user_id = ?`,
      [userId]
    );

    // Fetch product categories
    const [categories] = await pool.query(
      `SELECT pc.category_name 
       FROM vendor_product_categories vpc 
       JOIN product_categories pc ON vpc.category_id = pc.category_id 
       WHERE vpc.user_id = ?`,
      [userId]
    );

    // Fetch compliance documents
    const [documents] = await pool.query(
      `SELECT document_id, document_name, document_type, document_size, 
              upload_date, status 
       FROM compliance_documents 
       WHERE user_id = ?`,
      [userId]
    );

    const userData = {
      ...users[0],
      banking: banking[0] || {},
      productCategories: categories.map((cat) => cat.category_name),
      documents,
    };

    res.json(userData);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// PUT /api/profile - Update or insert vendor profile
app.put("/api/profilevendor", authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const {
    full_name,
    email,
    phone,
    company_name,
    tax_id,
    address,
    city,
    state,
    postal_code,
    country,
    bank_name,
    account_number,
    routing_number,
    currency,
    product_categories,
  } = req.body;

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    // Update or insert user data
    const [existingUser] = await connection.query(
      `SELECT id FROM users WHERE id = ?`,
      [userId]
    );

    if (existingUser.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    await connection.query(
      `UPDATE users 
       SET full_name = ?, email = ?, phone = ?, company_name = ?, tax_id = ?, 
           address = ?, city = ?, state = ?, postal_code = ?, country = ? 
       WHERE id = ?`,
      [
        full_name,
        email,
        phone,
        company_name,
        tax_id,
        address,
        city,
        state,
        postal_code,
        country,
        userId,
      ]
    );

    // Update or insert banking information
    const [existingBanking] = await connection.query(
      `SELECT banking_id FROM vendor_banking WHERE user_id = ?`,
      [userId]
    );

    if (existingBanking.length > 0) {
      await connection.query(
        `UPDATE vendor_banking 
         SET bank_name = ?, account_number = ?, routing_number = ?, currency = ? 
         WHERE user_id = ?`,
        [bank_name, account_number, routing_number, currency, userId]
      );
    } else {
      await connection.query(
        `INSERT INTO vendor_banking (user_id, bank_name, account_number, routing_number, currency) 
         VALUES (?, ?, ?, ?, ?)`,
        [userId, bank_name, account_number, routing_number, currency]
      );
    }

    // Update or insert product categories
    if (product_categories && product_categories.length > 0) {
      // Delete existing categories
      await connection.query(
        `DELETE FROM vendor_product_categories WHERE user_id = ?`,
        [userId]
      );

      // Insert new categories
      for (const category of product_categories) {
        let [categoryRow] = await connection.query(
          `SELECT category_id FROM product_categories WHERE category_name = ?`,
          [category]
        );

        if (categoryRow.length === 0) {
          [categoryRow] = await connection.query(
            `INSERT INTO product_categories (category_name) VALUES (?)`,
            [category]
          );
          categoryRow = [{ category_id: categoryRow.insertId }];
        }

        await connection.query(
          `INSERT INTO vendor_product_categories (user_id, category_id) VALUES (?, ?)`,
          [userId, categoryRow[0].category_id]
        );
      }
    }

    await connection.commit();
    res.json({
      message: "Profile updated successfully",
      user: { id: userId, ...req.body },
    });
  } catch (err) {
    await connection.rollback();
    res.status(500).json({ error: "Server error" });
  } finally {
    connection.release();
  }
});

const mystorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const orderDir = path.join(__dirname, "Uploads", "orders"); // Save all files in uploads/orders
    fs.mkdirSync(orderDir, { recursive: true }); // Create directory if it doesn't exist
    cb(null, orderDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${Math.random()
      .toString(36)
      .substring(2, 9)}`; // Unique identifier
    const ext = path.extname(file.originalname); // Preserve original extension
    cb(null, `${uniqueSuffix}${ext}`); // Unique filename to prevent collisions
  },
});

const myupload = multer({
  storage: mystorage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      "application/pdf",
      "image/jpeg",
      "image/png",
      "image/gif",
      "application/msword",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(
        new Error("Only PDF, JPG, PNG, GIF, DOC, and DOCX files are allowed"),
        false
      );
    }
  },
});

// POST /api/profile/documents - Handle document uploads
app.post(
  "/api/profile/documents",
  authenticateToken,
  myupload.array("documents"),
  async (req, res) => {
    const userId = req.user.id;
    const files = req.files; // Files uploaded via multer

    if (!files || files.length === 0) {
      return res.status(400).json({ error: "No files uploaded" });
    }

    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();

      for (const file of files) {
        await connection.query(
          `INSERT INTO compliance_documents 
         (user_id, document_name, document_type, document_size, storage_path, status) 
         VALUES (?, ?, ?, ?, ?, ?)`,
          [
            userId,
            file.originalname,
            file.mimetype,
            file.size,
            file.path,
            "Pending Review",
          ]
        );
      }

      await connection.commit();
      res.json({ message: "Documents uploaded successfully" });
    } catch (err) {
      await connection.rollback();
      res.status(500).json({ error: `Server error: ${err.message}` }); // Include error message for debugging
    } finally {
      connection.release();
    }
  }
);

// DELETE /api/profile/documents/:documentId - Delete a specific document
app.delete(
  "/api/profile/documents/:documentId",
  authenticateToken,
  async (req, res) => {
    const userId = req.user.id;
    const documentId = req.params.documentId;

    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();

      // Delete document only if it belongs to the authenticated user
      const [result] = await connection.query(
        `DELETE FROM compliance_documents WHERE document_id = ? AND user_id = ?`,
        [documentId, userId]
      );

      if (result.affectedRows === 0) {
        await connection.commit();
        return res
          .status(404)
          .json({ error: "Document not found or not authorized" });
      }

      await connection.commit();
      res.json({ message: "Document deleted successfully" });
    } catch (err) {
      await connection.rollback();
      res.status(500).json({ error: `Server error: ${err.message}` });
    } finally {
      connection.release();
    }
  }
);

// Fetch All Product Categories
app.get("/api/all-product-categories", authenticateToken, async (req, res) => {
  try {
    console.log("Fetching all product categories");
    const [categories] = await pool.query(
      "SELECT category_name FROM product_categories ORDER BY category_name"
    );
    res.json(categories.map((c) => c.category_name));
    console.log("Product categories fetched successfully");
  } catch (err) {
    console.error("Error fetching product categories:", err.message);
    res
      .status(500)
      .json({ error: "Cannot fetch product categories", details: err.message });
  }
});

// GET /api/products - Fetch all products for the authenticated vendor
app.get("/api/products", authenticateToken, async (req, res) => {
  const vendorId = req.user.id;
  try {
    const [products] = await pool.query(
      `SELECT product_id AS id, name, category, sku, price, currency, in_stock AS inStock, lead_time AS leadTime, image_url AS image, description 
       FROM vendorproducts 
       WHERE vendor_id = ? 
       ORDER BY created_at DESC`,
      [vendorId]
    );
    // Return absolute URLs for images
    const updatedProducts = products.map((product) => ({
      ...product,
      image: product.image?.startsWith("http")
        ? product.image
        : `${req.protocol}://${req.get("host")}${product.image}`,
    }));

    res.json(updatedProducts);
  } catch (err) {
    console.error("Fetch error:", err.message);
    res
      .status(500)
      .json({ error: "Failed to fetch products", details: err.message });
  }
});

// POST /api/products - Create a new product
app.post("/api/products", authenticateToken, async (req, res) => {
  const vendorId = req.user.id;
  const {
    name,
    category,
    sku,
    price,
    currency,
    inStock,
    leadTime,
    image,
    description,
  } = req.body;

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const [result] = await connection.query(
      `INSERT INTO vendorproducts 
       (vendor_id, name, category, sku, price, currency, in_stock, lead_time, image_url, description) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        vendorId,
        name,
        category,
        sku,
        price,
        currency,
        inStock,
        leadTime,
        image,
        description,
      ]
    );

    await connection.commit();
    res.json({ id: result.insertId, ...req.body });
  } catch (err) {
    await connection.rollback();
    res
      .status(500)
      .json({ error: "Failed to create product", details: err.message });
  } finally {
    connection.release();
  }
});

// PUT /api/products/:id - Update a product
app.put("/api/products/:id", authenticateToken, async (req, res) => {
  const vendorId = req.user.id;
  const productId = req.params.id;
  const {
    name,
    category,
    sku,
    price,
    currency,
    inStock,
    leadTime,
    image,
    description,
  } = req.body;

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const [result] = await connection.query(
      `UPDATE vendorproducts 
       SET name = ?, category = ?, sku = ?, price = ?, currency = ?, in_stock = ?, lead_time = ?, image_url = ?, description = ? 
       WHERE product_id = ? AND vendor_id = ?`,
      [
        name,
        category,
        sku,
        price,
        currency,
        inStock,
        leadTime,
        image,
        description,
        productId,
        vendorId,
      ]
    );

    if (result.affectedRows === 0) {
      await connection.commit();
      return res
        .status(404)
        .json({ error: "Product not found or not authorized" });
    }

    await connection.commit();
    res.json({ id: productId, ...req.body });
  } catch (err) {
    await connection.rollback();
    res
      .status(500)
      .json({ error: "Failed to update product", details: err.message });
  } finally {
    connection.release();
  }
});

// DELETE /api/products/:id - Delete a product
app.delete("/api/products/:id", authenticateToken, async (req, res) => {
  const vendorId = req.user.id;
  const productId = req.params.id;

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const [result] = await connection.query(
      `DELETE FROM vendorproducts WHERE product_id = ? AND vendor_id = ?`,
      [productId, vendorId]
    );

    if (result.affectedRows === 0) {
      await connection.commit();
      return res
        .status(404)
        .json({ error: "Product not found or not authorized" });
    }

    await connection.commit();
    res.json({ message: "Product deleted successfully" });
  } catch (err) {
    await connection.rollback();
    res
      .status(500)
      .json({ error: "Failed to delete product", details: err.message });
  } finally {
    connection.release();
  }
});

app.post(
  "/api/products/upload-image",
  authenticateToken,
  imageUpload.single("image"),
  async (req, res) => {
    const vendorId = req.user.id;
    if (!req.file) {
      return res.status(400).json({ error: "No image file uploaded" });
    }

    const imageUrl = `/Uploads/${req.file.filename}`; // Relative path for frontend access
    try {
      res.json({ imageUrl });
    } catch (err) {
      res
        .status(500)
        .json({ error: "Failed to process image", details: err.message });
    }
  }
);
const { promisify } = require("util");

const AdmZip = require("adm-zip");

// Configure storage for bulk uploads
const bulkUploadStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, "temp_uploads");
    fs.mkdirSync(uploadDir, { recursive: true });
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});

const bulkUpload = multer({
  storage: bulkUploadStorage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
});
const uploadsDir = path.join(__dirname, "Uploads");

async function ensureUploadsDir() {
  try {
    await fs.mkdir(uploadsDir, { recursive: true });
    // No need to check if it exists; recursive:true does it safely
  } catch (err) {
    console.error("Error creating uploads directory:", err);
  }
}

ensureUploadsDir();

app.post(
  "/api/products/bulk-upload",
  authenticateToken,
  bulkUpload.single("file"),
  async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }

    try {
      // 1. Parse Excel data
      const workbook = XLSX.readFile(req.file.path);
      const sheetName = workbook.SheetNames[0];
      const sheet = workbook.Sheets[sheetName];
      const jsonData = XLSX.utils.sheet_to_json(sheet);

      // 2. Extract images from Excel
      const images = await extractImagesFromExcel(req.file.path);
      console.log(`Extracted ${images.length} images from Excel`);

      // 3. Process products
      const connection = await pool.getConnection();
      try {
        await connection.beginTransaction();

        const results = [];
        for (let i = 0; i < jsonData.length; i++) {
          const product = jsonData[i];

          // Validate required fields
          if (!product.name || !product.sku || !product.price) {
            console.warn(`Skipping invalid product at row ${i + 2}`);
            continue;
          }

          // Handle image
          let imageUrl = "";
          const imageForRow = images.find((img) => img.position.row === i + 1);

          if (imageForRow) {
            const imageName = `product-${Date.now()}-${i}.${
              imageForRow.extension
            }`;
            const imagePath = path.join(uploadsDir, imageName);

            await promisify(fs.writeFile)(imagePath, imageForRow.buffer);
            imageUrl = `/Uploads/${imageName}`;
            console.log(`Saved image for product ${i + 1}: ${imageUrl}`);
          }

          // Insert into database
          const [result] = await connection.query(
            `INSERT INTO vendorproducts 
          (vendor_id, name, category, sku, price, currency, in_stock, lead_time, image_url, description)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
              req.user.id,
              product.name,
              product.category || "",
              product.sku,
              parseFloat(product.price) || 0,
              product.currency || "USD",
              product.inStock ? 1 : 0,
              product.leadTime || "",
              imageUrl,
              product.description || "",
            ]
          );

          results.push(result);
        }

        await connection.commit();
        await promisify(fs.unlink)(req.file.path);

        return res.json({
          success: true,
          total: jsonData.length,
          inserted: results.length,
          withImages: images.length,
        });
      } catch (err) {
        await connection.rollback();
        throw err;
      } finally {
        connection.release();
      }
    } catch (error) {
      console.error("Bulk upload error:", error);

      // Clean up temp file if it exists
      if (req.file && fs.existsSync(req.file.path)) {
        await promisify(fs.unlink)(req.file.path).catch(console.error);
      }

      return res.status(500).json({
        error: "Failed to process bulk upload",
        details: error.message,
      });
    }
  }
);

// Improved image extraction
async function extractImagesFromExcel(filePath) {
  try {
    const zip = new AdmZip(filePath);
    const zipEntries = zip.getEntries();
    const images = [];

    // Find all image files in the media directory
    const mediaEntries = zipEntries.filter((entry) =>
      entry.entryName.match(/^xl\/media\/image\d+\.(jpg|jpeg|png)$/i)
    );

    for (const entry of mediaEntries) {
      const buffer = entry.getData();
      const extension = path.extname(entry.entryName).substr(1).toLowerCase();

      // Extract image number to determine row (image1.jpg = row 1)
      const rowMatch = entry.entryName.match(/image(\d+)\./i);
      const row = rowMatch ? parseInt(rowMatch[1]) : null;

      if (row) {
        images.push({
          buffer,
          extension,
          position: { row },
          originalName: entry.entryName,
        });
      }
    }

    return images;
  } catch (error) {
    console.error("Image extraction error:", error);
    return [];
  }
}

// Get all RFQs for a vendor
app.get("/api/rfqs", authenticateToken, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const { search, state } = req.query;
    let query = "SELECT * FROM rfqs";
    const queryParams = [];

    if (search || state) {
      query += " WHERE ";
      const conditions = [];

      if (search) {
        conditions.push("(rfq_id LIKE ? OR title LIKE ? OR location LIKE ?)");
        queryParams.push(`%${search}%`, `%${search}%`, `%${search}%`);
      }

      if (state) {
        conditions.push("state = ?");
        queryParams.push(state);
      }

      query += conditions.join(" AND ");
    }

    const [rfqs] = await connection.query(query, queryParams);

    for (let rfq of rfqs) {
      const [items] = await connection.query(
        "SELECT * FROM rfq_items WHERE rfq_id = ?",
        [rfq.rfq_id]
      );
      const [attachments] = await connection.query(
        "SELECT * FROM rfq_attachments WHERE rfq_id = ?",
        [rfq.rfq_id]
      );
      const [quote] = await connection.query(
        "SELECT * FROM quotes WHERE rfq_id = ? AND vendor_id = ?",
        [rfq.rfq_id, req.user.id]
      );
      rfq.items = items;
      rfq.attachments = attachments.map((a) => a.file_name);
      rfq.quote = quote[0] || null;
      // Set vendor-specific status from the quote, or default to 'Open' if no quote exists
      rfq.vendorStatus = quote[0]?.status || "Open";
    }

    res.json(rfqs);
  } catch (error) {
    console.error("Error fetching RFQs:", error);
    res.status(500).json({ error: "Failed to fetch RFQs" });
  } finally {
    connection.release();
  }
});

// Get single RFQ
app.get("/api/rfqs/:id", authenticateToken, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const [rfq] = await connection.query(
      "SELECT * FROM rfqs WHERE rfq_id = ?",
      [req.params.id]
    );
    if (!rfq[0]) return res.status(404).json({ error: "RFQ not found" });

    const [items] = await connection.query(
      "SELECT * FROM rfq_items WHERE rfq_id = ?",
      [req.params.id]
    );
    const [attachments] = await connection.query(
      "SELECT * FROM rfq_attachments WHERE rfq_id = ?",
      [req.params.id]
    );
    const [quote] = await connection.query(
      "SELECT * FROM quotes WHERE rfq_id = ? AND vendor_id = ?",
      [req.params.id, req.user.id]
    );

    rfq[0].items = items;
    rfq[0].attachments = attachments.map((a) => a.file_name);
    rfq[0].quote = quote[0] || null;
    rfq[0].vendorStatus = quote[0]?.status || "Open";

    res.json(rfq[0]);
  } catch (error) {
    console.error("Error fetching RFQ:", error);
    res.status(500).json({ error: "Failed to fetch RFQ" });
  } finally {
    connection.release();
  }
});

// Submit a quote
app.post("/api/rfqs/:id/quote", authenticateToken, async (req, res) => {
  const vendorId = req.user.id;
  const rfqId = req.params.id;
  const { total_amount, currency, lead_time, valid_until, notes } = req.body;

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const [rfq] = await connection.query(
      "SELECT * FROM rfqs WHERE rfq_id = ?",
      [rfqId]
    );
    if (!rfq[0]) {
      await connection.rollback();
      return res.status(404).json({ error: "RFQ not found" });
    }

    if (rfq[0].state !== "Open") {
      await connection.rollback();
      return res
        .status(400)
        .json({ error: "Cannot submit quote for this RFQ" });
    }

    const [existingQuote] = await connection.query(
      "SELECT * FROM quotes WHERE rfq_id = ? AND vendor_id = ?",
      [rfqId, vendorId]
    );
    if (existingQuote[0]) {
      await connection.rollback();
      return res.status(400).json({ error: "Quote already submitted" });
    }

    const [result] = await connection.query(
      "INSERT INTO quotes (rfq_id, vendor_id, total_amount, currency, lead_time, valid_until, notes, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [
        rfqId,
        vendorId,
        total_amount,
        currency,
        lead_time,
        valid_until,
        notes,
        "Pending Quote",
      ]
    );

    await connection.commit();
    res.json({
      message: "Quote submitted successfully",
      quote_id: result.insertId,
    });
  } catch (error) {
    await connection.rollback();
    console.error("Error submitting quote:", error);
    res.status(500).json({ error: "Failed to submit quote" });
  } finally {
    connection.release();
  }
});

// Edit a quote
app.put("/api/rfqs/:id/quote", authenticateToken, async (req, res) => {
  const vendorId = req.user.id;
  const rfqId = req.params.id;
  const { total_amount, currency, lead_time, valid_until, notes } = req.body;

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const [rfq] = await connection.query(
      "SELECT * FROM rfqs WHERE rfq_id = ?",
      [rfqId]
    );
    if (!rfq[0]) {
      await connection.rollback();
      return res.status(404).json({ error: "RFQ not found" });
    }

    const [existingQuote] = await connection.query(
      "SELECT * FROM quotes WHERE rfq_id = ? AND vendor_id = ?",
      [rfqId, vendorId]
    );
    if (!existingQuote[0]) {
      await connection.rollback();
      return res.status(404).json({ error: "Quote not found" });
    }

    if (existingQuote[0].status !== "Pending Quote") {
      await connection.rollback();
      return res
        .status(400)
        .json({ error: "Can only edit quotes in Pending Quote status" });
    }

    await connection.query(
      "UPDATE quotes SET total_amount = ?, currency = ?, lead_time = ?, valid_until = ?, notes = ? WHERE rfq_id = ? AND vendor_id = ?",
      [total_amount, currency, lead_time, valid_until, notes, rfqId, vendorId]
    );

    await connection.commit();
    res.json({ message: "Quote updated successfully" });
  } catch (error) {
    await connection.rollback();
    console.error("Error updating quote:", error);
    res.status(500).json({ error: "Failed to update quote" });
  } finally {
    connection.release();
  }
});

// Orders routes
app.get("/api/vendororders", authenticateToken, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const { search, status } = req.query;
    let query = "SELECT * FROM vendor_orders WHERE vendor_id = ?";
    const queryParams = [req.user.id];
    if (search || status) {
      const conditions = [];
      if (search) {
        conditions.push(
          "(order_id LIKE ? OR po_number LIKE ? OR client_name LIKE ?)"
        );
        queryParams.push(`%${search}%`, `%${search}%`, `%${search}%`);
      }
      if (status) {
        if (status === "active") {
          conditions.push(
            "status IN ('Processing', 'Ready for Shipment', 'Shipped')"
          );
        } else if (status === "completed") {
          conditions.push("status = 'Delivered'");
        } else if (status === "cancelled") {
          conditions.push("status = 'Cancelled'");
        }
      }
      if (conditions.length) {
        query += " AND " + conditions.join(" AND ");
      }
    }
    const [orders] = await connection.query(query, queryParams);
    for (let order of orders) {
      const [items] = await connection.query(
        "SELECT * FROM vendor_order_items WHERE order_id = ?",
        [order.order_id]
      );
      const [address] = await connection.query(
        "SELECT * FROM vendor_shipping_addresses WHERE order_id = ?",
        [order.order_id]
      );
      const [documents] = await connection.query(
        "SELECT * FROM vendor_order_documents WHERE order_id = ?",
        [order.order_id]
      );
      order.items = items;
      order.shippingAddress = address[0] || null;
      order.documents = documents;
    }
    res.json(orders);
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ error: "Failed to fetch orders" });
  } finally {
    connection.release();
  }
});

app.get("/api/vendororders/:poNumber", authenticateToken, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const { poNumber } = req.params;
    const [orders] = await connection.query(
      "SELECT * FROM vendor_orders WHERE po_number = ? AND vendor_id = ?",
      [poNumber, req.user.id]
    );
    if (orders.length === 0) {
      return res.status(404).json({ error: "Order not found" });
    }
    const order = orders[0];
    const [items] = await connection.query(
      "SELECT * FROM vendor_order_items WHERE order_id = ?",
      [order.order_id]
    );
    const [address] = await connection.query(
      "SELECT * FROM vendor_shipping_addresses WHERE order_id = ?",
      [order.order_id]
    );
    const [documents] = await connection.query(
      "SELECT * FROM vendor_order_documents WHERE order_id = ?",
      [order.order_id]
    );
    order.items = items;
    order.shippingAddress = address[0] || null;
    order.documents = documents;
    res.json(order);
  } catch (error) {
    console.error("Error fetching order:", error);
    res.status(500).json({ error: "Failed to fetch order" });
  } finally {
    connection.release();
  }
});

app.put(
  "/api/vendororders/:poNumber/status",
  authenticateToken,
  async (req, res) => {
    const connection = await pool.getConnection();
    try {
      const { poNumber } = req.params;
      const { status } = req.body;
      const validStatuses = [
        "Processing",
        "Ready for Shipment",
        "Shipped",
        "Delivered",
      ];
      if (!validStatuses.includes(status)) {
        return res.status(400).json({ error: "Invalid status" });
      }

      const [orders] = await connection.query(
        "SELECT * FROM vendor_orders WHERE po_number = ? AND vendor_id = ?",
        [poNumber, req.user.id]
      );
      if (orders.length === 0) {
        return res.status(404).json({ error: "Order not found" });
      }
      const currentOrder = orders[0];

      if (
        currentOrder.status === "Delivered" ||
        currentOrder.status === "Cancelled"
      ) {
        return res.status(400).json({
          error: "Cannot update status of delivered or cancelled order",
        });
      }

      const allowedTransitions = {
        Processing: ["Ready for Shipment"],
        "Ready for Shipment": ["Shipped"],
        Shipped: ["Delivered"],
      };

      if (!allowedTransitions[currentOrder.status]?.includes(status)) {
        return res.status(400).json({
          error: `Cannot transition from ${currentOrder.status} to ${status}`,
        });
      }

      const updates = { status };
      if (status === "Shipped") {
        const trackingNumber = `1Z${Date.now()}`;
        updates.shipped_date = new Date().toISOString().split("T")[0];
        updates.estimated_delivery = new Date(
          Date.now() + 5 * 24 * 60 * 60 * 1000
        )
          .toISOString()
          .split("T")[0];
        updates.tracking_number = trackingNumber;
        updates.tracking_url = `https://www.ups.com/track?tracknum=${trackingNumber}`;
      } else if (status === "Delivered") {
        updates.delivered_date = new Date().toISOString().split("T")[0];
      }

      await connection.query("UPDATE vendor_orders SET ? WHERE order_id = ?", [
        updates,
        currentOrder.order_id,
      ]);
      res.json({ message: "Order status updated successfully" });
    } catch (error) {
      console.error("Error updating order status:", error);
      res.status(500).json({ error: "Failed to update order status" });
    } finally {
      connection.release();
    }
  }
);

app.post(
  "/api/vendororders/:poNumber/documents",
  authenticateToken,
  myupload.array("documents", 5),
  async (req, res) => {
    const connection = await pool.getConnection();
    try {
      const { poNumber } = req.params;
      const files = req.files;

      const [orders] = await connection.query(
        "SELECT * FROM vendor_orders WHERE po_number = ? AND vendor_id = ?",
        [poNumber, req.user.id]
      );
      if (orders.length === 0) {
        return res.status(404).json({ error: "Order not found" });
      }
      const order = orders[0];

      if (
        order.status !== "Processing" &&
        order.status !== "Ready for Shipment"
      ) {
        return res.status(400).json({
          error:
            "Documents can only be uploaded for Processing or Ready for Shipment orders",
        });
      }

      const documents = files.map((file) => ({
        order_id: order.order_id,
        name: file.originalname,
        storage_path: file.path.replace(__dirname, "").replace(/\\/g, "/"), // Normalize path for database
        type:
          file.mimetype === "application/pdf"
            ? "PDF Document"
            : file.mimetype === "image/jpeg" || file.mimetype === "image/png"
            ? "Image File"
            : "Other File",
        size: file.size,
        upload_date: new Date().toISOString().split("T")[0],
      }));

      if (documents.length > 0) {
        await connection.query(
          "INSERT INTO vendor_order_documents (order_id, name, storage_path, type, size, upload_date) VALUES ?",
          [
            documents.map((d) => [
              d.order_id,
              d.name,
              d.storage_path,
              d.type,
              d.size,
              d.upload_date,
            ]),
          ]
        );

        if (order.status === "Processing") {
          await connection.query(
            'UPDATE vendor_orders SET status = "Ready for Shipment" WHERE order_id = ?',
            [order.order_id]
          );
        }
      }

      res.json({ message: "Documents uploaded successfully" });
    } catch (error) {
      console.error("Error uploading documents:", error);
      res
        .status(500)
        .json({ error: `Failed to upload documents: ${error.message}` });
    } finally {
      connection.release();
    }
  }
);

app.get(
  "/api/vendororders/:poNumber/documents/:documentId",
  authenticateToken,
  async (req, res) => {
    const connection = await pool.getConnection();
    try {
      const { poNumber, documentId } = req.params;
      const [orders] = await connection.query(
        "SELECT order_id FROM vendor_orders WHERE po_number = ? AND vendor_id = ?",
        [poNumber, req.user.id]
      );

      if (orders.length === 0) {
        return res.status(404).json({ error: "Order not found" });
      }

      const [documents] = await connection.query(
        "SELECT * FROM vendor_order_documents WHERE document_id = ? AND order_id = ?",
        [documentId, orders[0].order_id]
      );

      if (documents.length === 0) {
        return res.status(404).json({ error: "Document not found" });
      }

      const filePath = path.join(__dirname, documents[0].storage_path);
      if (!fs.existsSync(filePath)) {
        return res
          .status(404)
          .json({ error: "Document file not found on server" });
      }

      // Clean up the filename by removing any trailing underscores
      let filename = documents[0].name.replace(/_+$/, "");

      res.setHeader(
        "Content-Disposition",
        `attachment; filename="${filename}"`
      );
      res.setHeader("Content-Type", documents[0].type);
      res.sendFile(filePath);
    } catch (error) {
      console.error("Error downloading document:", error);
      res
        .status(500)
        .json({ error: `Failed to download document: ${error.message}` });
    } finally {
      connection.release();
    }
  }
);

// --- Messages APIs ---

// Get all messages for the authenticated vendor
app.get("/api/vendor/messages", authenticateToken, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const [messages] = await connection.query(
      "SELECT * FROM vendor_messages WHERE vendor_id = ? ORDER BY timestamp ASC",
      [req.user.id]
    );
    res.json(messages);
  } catch (error) {
    console.error("Error fetching messages:", error);
    res.status(500).json({ error: "Failed to fetch messages" });
  } finally {
    connection.release();
  }
});

// Send a new message
app.post("/api/vendor/messages", authenticateToken, async (req, res) => {
  const { content } = req.body;
  if (!content || content.trim() === "") {
    return res.status(400).json({ error: "Message content is required" });
  }

  const connection = await pool.getConnection();
  try {
    const [result] = await connection.query(
      "INSERT INTO vendor_messages (vendor_id, sender, content, is_user, avatar) VALUES (?, ?, ?, ?, ?)",
      [req.user.id, "You", content, 1, null]
    );

    // Simulate support team response
    // setTimeout(async () => {
    //   await connection.query(
    //     'INSERT INTO vendor_messages (vendor_id, sender, content, is_user, avatar) VALUES (?, ?, ?, ?, ?)',
    //     [
    //       req.user.id,
    //       'SSC Support Team',
    //       'Thank you for your message. Our team will get back to you shortly.',
    //       0,
    //       'https://static.vecteezy.com/system/resources/previews/022/132/452/large_2x/personal-id-icon-logo-design-vector.jpg',
    //     ]
    //   );
    // }, 1000);

    res.status(201).json({
      id: result.insertId,
      content,
      sender: "You",
      is_user: 1,
      timestamp: new Date(),
    });
  } catch (error) {
    console.error("Error sending message:", error);
    res.status(500).json({ error: "Failed to send message" });
  } finally {
    connection.release();
  }
});

// --- Notifications APIs ---

// Get all notifications for the authenticated vendor
app.get("/api/vendor/notifications", authenticateToken, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const [notifications] = await connection.query(
      "SELECT * FROM vendor_notifications WHERE vendor_id = ? ORDER BY timestamp DESC",
      [req.user.id]
    );
    res.json(notifications);
  } catch (error) {
    console.error("Error fetching notifications:", error);
    res.status(500).json({ error: "Failed to fetch notifications" });
  } finally {
    connection.release();
  }
});

// Mark a notification as read
app.put(
  "/api/vendor/notifications/:id/read",
  authenticateToken,
  async (req, res) => {
    const connection = await pool.getConnection();
    try {
      const [result] = await connection.query(
        "UPDATE vendor_notifications SET is_read = 1 WHERE id = ? AND vendor_id = ?",
        [req.params.id, req.user.id]
      );
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: "Notification not found" });
      }
      res.json({ message: "Notification marked as read" });
    } catch (error) {
      console.error("Error marking notification as read:", error);
      res.status(500).json({ error: "Failed to mark notification as read" });
    } finally {
      connection.release();
    }
  }
);

// --- Support Tickets APIs ---

// Get all tickets for the authenticated vendor
app.get("/api/vendor/tickets", authenticateToken, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const [tickets] = await connection.query(
      "SELECT * FROM vendor_tickets WHERE vendor_id = ? ORDER BY updated_at DESC",
      [req.user.id]
    );

    for (let ticket of tickets) {
      const [responses] = await connection.query(
        "SELECT * FROM vendor_ticket_responses WHERE ticket_id = ? ORDER BY timestamp ASC",
        [ticket.id]
      );
      ticket.responses = responses;
    }

    res.json(tickets);
  } catch (error) {
    console.error("Error fetching tickets:", error);
    res.status(500).json({ error: "Failed to fetch tickets" });
  } finally {
    connection.release();
  }
});

// Create a new ticket
app.post("/api/vendor/tickets", authenticateToken, async (req, res) => {
  const { subject, description, priority } = req.body;
  if (!subject || !description || !priority) {
    return res
      .status(400)
      .json({ error: "Subject, description, and priority are required" });
  }

  const connection = await pool.getConnection();
  try {
    const ticketId = `TKT-2023-${Date.now()}`; // Simple unique ticket ID generator
    const [result] = await connection.query(
      "INSERT INTO vendor_tickets (ticket_id, vendor_id, subject, description, status, priority) VALUES (?, ?, ?, ?, ?, ?)",
      [ticketId, req.user.id, subject, description, "Open", priority]
    );

    res.status(201).json({
      id: result.insertId,
      ticket_id: ticketId,
      subject,
      description,
      status: "Open",
      priority,
      created_at: new Date(),
      updated_at: new Date(),
      responses: [],
    });
  } catch (error) {
    console.error("Error creating ticket:", error);
    res.status(500).json({ error: "Failed to create ticket" });
  } finally {
    connection.release();
  }
});

// Add a response to a ticket
app.post(
  "/api/vendor/tickets/:id/responses",
  authenticateToken,
  async (req, res) => {
    const { content } = req.body;
    if (!content || content.trim() === "") {
      return res.status(400).json({ error: "Response content is required" });
    }

    const connection = await pool.getConnection();
    try {
      const [ticket] = await connection.query(
        "SELECT * FROM vendor_tickets WHERE id = ? AND vendor_id = ?",
        [req.params.id, req.user.id]
      );
      if (ticket.length === 0) {
        return res.status(404).json({ error: "Ticket not found" });
      }

      const [result] = await connection.query(
        "INSERT INTO vendor_ticket_responses (ticket_id, vendor_id, sender, content) VALUES (?, ?, ?, ?)",
        [req.params.id, req.user.id, "You", content]
      );

      await connection.query(
        "UPDATE vendor_tickets SET updated_at = ? WHERE id = ?",
        [new Date(), req.params.id]
      );

      res.status(201).json({
        id: result.insertId,
        ticket_id: req.params.id,
        sender: "You",
        content,
        timestamp: new Date(),
      });
    } catch (error) {
      console.error("Error adding ticket response:", error);
      res.status(500).json({ error: "Failed to add ticket response" });
    } finally {
      connection.release();
    }
  }
);

app.get("/api/vendor/settings", authenticateToken, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    // Fetch user details
    const [users] = await connection.query(
      "SELECT id, email, full_name FROM users WHERE id = ? AND user_type = ?",
      [req.user.id, "vendor"]
    );
    if (users.length === 0) {
      return res.status(404).json({ error: "Vendor not found" });
    }

    // Fetch notification settings
    const [settings] = await connection.query(
      "SELECT * FROM vendor_notification_settings WHERE vendor_id = ?",
      [req.user.id]
    );

    const vendorSettings = {
      email: users[0].email,
      full_name: users[0].full_name,
      notification_settings: settings[0] || {
        email_notifications: false,
        in_app_notifications: false,
        sms_notifications: false,
        order_updates: false,
        payment_updates: false,
        rfq_updates: false,
      },
    };

    res.json(vendorSettings);
  } catch (error) {
    console.error("Error fetching settings:", error);
    res.status(500).json({ error: "Failed to fetch settings" });
  } finally {
    connection.release();
  }
});

// Update password
app.put(
  "/api/vendor/settings/password",
  authenticateToken,
  async (req, res) => {
    const { currentPassword, newPassword, confirmPassword } = req.body;

    if (!currentPassword || !newPassword || !confirmPassword) {
      return res
        .status(400)
        .json({ error: "All password fields are required" });
    }

    if (newPassword !== confirmPassword) {
      return res
        .status(400)
        .json({ error: "New password and confirmation do not match" });
    }

    if (newPassword.length < 8) {
      return res
        .status(400)
        .json({ error: "New password must be at least 8 characters long" });
    }

    const connection = await pool.getConnection();
    try {
      // Verify current password
      const [users] = await connection.query(
        "SELECT password FROM users WHERE id = ?",
        [req.user.id]
      );
      if (users.length === 0) {
        return res.status(404).json({ error: "Vendor not found" });
      }

      const isMatch = await bcrypt.compare(currentPassword, users[0].password);
      if (!isMatch) {
        return res.status(401).json({ error: "Current password is incorrect" });
      }

      // Hash new password
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      // Update password and increment token_version
      await connection.query(
        "UPDATE users SET password = ?, token_version = token_version + 1 WHERE id = ?",
        [hashedPassword, req.user.id]
      );

      res.json({ message: "Password updated successfully" });
    } catch (error) {
      console.error("Error updating password:", error);
      res.status(500).json({ error: "Failed to update password" });
    } finally {
      connection.release();
    }
  }
);

// Update notification settings
app.put(
  "/api/vendor/settings/notifications",
  authenticateToken,
  async (req, res) => {
    const {
      email_notifications,
      in_app_notifications,
      sms_notifications,
      order_updates,
      payment_updates,
      rfq_updates,
    } = req.body;

    // Validate all fields are provided
    if (
      email_notifications === undefined ||
      in_app_notifications === undefined ||
      sms_notifications === undefined ||
      order_updates === undefined ||
      payment_updates === undefined ||
      rfq_updates === undefined
    ) {
      return res
        .status(400)
        .json({ error: "All notification settings are required" });
    }

    const connection = await pool.getConnection();
    try {
      // Check if settings exist
      const [existing] = await connection.query(
        "SELECT id FROM vendor_notification_settings WHERE vendor_id = ?",
        [req.user.id]
      );

      if (existing.length > 0) {
        // Update existing settings
        await connection.query(
          `UPDATE vendor_notification_settings SET
          email_notifications = ?,
          in_app_notifications = ?,
          sms_notifications = ?,
          order_updates = ?,
          payment_updates = ?,
          rfq_updates = ?,
          updated_at = NOW()
        WHERE vendor_id = ?`,
          [
            email_notifications ? 1 : 0,
            in_app_notifications ? 1 : 0,
            sms_notifications ? 1 : 0,
            order_updates ? 1 : 0,
            payment_updates ? 1 : 0,
            rfq_updates ? 1 : 0,
            req.user.id,
          ]
        );
      } else {
        // Insert new settings
        await connection.query(
          `INSERT INTO vendor_notification_settings (
          vendor_id,
          email_notifications,
          in_app_notifications,
          sms_notifications,
          order_updates,
          payment_updates,
          rfq_updates
        ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [
            req.user.id,
            email_notifications ? 1 : 0,
            in_app_notifications ? 1 : 0,
            sms_notifications ? 1 : 0,
            order_updates ? 1 : 0,
            payment_updates ? 1 : 0,
            rfq_updates ? 1 : 0,
          ]
        );
      }

      // Fetch updated settings to return
      const [updatedSettings] = await connection.query(
        "SELECT * FROM vendor_notification_settings WHERE vendor_id = ?",
        [req.user.id]
      );

      res.json({
        message: "Notification settings updated successfully",
        notification_settings: updatedSettings[0] || {
          email_notifications: email_notifications ? 1 : 0,
          in_app_notifications: in_app_notifications ? 1 : 0,
          sms_notifications: sms_notifications ? 1 : 0,
          order_updates: order_updates ? 1 : 0,
          payment_updates: payment_updates ? 1 : 0,
          rfq_updates: rfq_updates ? 1 : 0,
        },
      });
    } catch (error) {
      console.error("Error updating notification settings:", error);
      res.status(500).json({ error: "Failed to update notification settings" });
    } finally {
      connection.release();
    }
  }
);

// Get all payments for the authenticated vendor
app.get("/api/vendor/payments", authenticateToken, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const [payments] = await connection.query(
      `SELECT payment_id AS id, order_id, invoice_number, client_name, amount, currency, 
              status, payment_date, due_date, payment_method, description 
       FROM vendor_payments 
       WHERE vendor_id = ? 
       ORDER BY COALESCE(payment_date, due_date) DESC`,
      [req.user.id]
    );
    res.json(payments);
  } catch (error) {
    console.error("Error fetching payments:", error);
    res.status(500).json({ error: "Failed to fetch payments" });
  } finally {
    connection.release();
  }
});

// Get payment details by payment_id
app.get(
  "/api/vendor/payments/:payment_id",
  authenticateToken,
  async (req, res) => {
    const connection = await pool.getConnection();
    try {
      const [payments] = await connection.query(
        `SELECT payment_id AS id, order_id, invoice_number, client_name, amount, currency, 
              status, payment_date, due_date, payment_method, description 
       FROM vendor_payments 
       WHERE vendor_id = ? AND payment_id = ?`,
        [req.user.id, req.params.payment_id]
      );
      if (payments.length === 0) {
        return res.status(404).json({ error: "Payment not found" });
      }
      res.json(payments[0]);
    } catch (error) {
      console.error("Error fetching payment details:", error);
      res.status(500).json({ error: "Failed to fetch payment details" });
    } finally {
      connection.release();
    }
  }
);

// Placeholder for invoice download (extend with actual PDF generation if needed)
app.get(
  "/api/vendor/payments/:payment_id/invoice",
  authenticateToken,
  async (req, res) => {
    const connection = await pool.getConnection();
    try {
      const [payments] = await connection.query(
        `SELECT payment_id AS id, order_id, invoice_number, client_name, amount, currency, 
              status, payment_date, due_date, description 
       FROM vendor_payments 
       WHERE vendor_id = ? AND payment_id = ?`,
        [req.user.id, req.params.payment_id]
      );
      if (payments.length === 0) {
        return res.status(404).json({ error: "Payment not found" });
      }

      // Placeholder response (extend with PDF generation library like pdfkit)
      res.json({
        message: "Invoice download initiated",
        payment: payments[0],
      });
    } catch (error) {
      console.error("Error generating invoice:", error);
      res.status(500).json({ error: "Failed to generate invoice" });
    } finally {
      connection.release();
    }
  }
);

// Get vendor analytics
app.get("/api/vendor/analytics", authenticateToken, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const { period = "monthly" } = req.query; // Default to monthly
    const vendorId = req.user.id;

    // Validate period
    const validPeriods = ["weekly", "monthly", "quarterly", "yearly"];
    if (!validPeriods.includes(period)) {
      return res.status(400).json({ error: "Invalid period" });
    }

    // Sales Trends (Paid payments)
    let salesQuery = "";
    let salesParams = [vendorId];
    let labels = [];

    if (period === "monthly") {
      // Query for the last 12 months
      salesQuery = `
        SELECT DATE_FORMAT(payment_date, '%Y-%m') AS period, 
               SUM(amount) AS total_sales
        FROM vendor_payments
        WHERE vendor_id = ? 
          AND status = 'Paid' 
          AND payment_date IS NOT NULL
          AND payment_date >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
        GROUP BY period
        ORDER BY period ASC
      `;
      // Generate labels for the last 12 months
      const today = new Date("2025-06-25"); // Hardcoded for consistency
      for (let i = 11; i >= 0; i--) {
        const date = new Date(today.getFullYear(), today.getMonth() - i, 1);
        const monthName = date.toLocaleString("default", { month: "short" });
        const year = date.getFullYear();
        labels.push(`${monthName} ${year}`);
      }
    } else if (period === "weekly") {
      salesQuery = `
        SELECT DATE_FORMAT(payment_date, '%Y-%U') AS period, 
               SUM(amount) AS total_sales
        FROM vendor_payments
        WHERE vendor_id = ? AND status = 'Paid' AND payment_date IS NOT NULL
        GROUP BY period
        ORDER BY period DESC
        LIMIT 4
      `;
      labels = ["Week 1", "Week 2", "Week 3", "Week 4"];
    } else if (period === "quarterly") {
      salesQuery = `
        SELECT CONCAT(YEAR(payment_date), '-Q', QUARTER(payment_date)) AS period, 
               SUM(amount) AS total_sales
        FROM vendor_payments
        WHERE vendor_id = ? AND status = 'Paid' AND payment_date IS NOT NULL
        GROUP BY period
        ORDER BY period DESC
        LIMIT 4
      `;
      labels = ["Q1", "Q2", "Q3", "Q4"];
    } else if (period === "yearly") {
      salesQuery = `
        SELECT YEAR(payment_date) AS period, 
               SUM(amount) AS total_sales
        FROM vendor_payments
        WHERE vendor_id = ? AND status = 'Paid' AND payment_date IS NOT NULL
        GROUP BY period
        ORDER BY period DESC
        LIMIT 3
      `;
      labels = ["Year 1", "Year 2", "Year 3"];
    }

    const [salesRows] = await connection.query(salesQuery, salesParams);
    const salesData = labels.map((label) => {
      const formattedPeriod =
        period === "monthly"
          ? `${new Date(label).getFullYear()}-${(new Date(label).getMonth() + 1)
              .toString()
              .padStart(2, "0")}`
          : label;
      const row = salesRows.find((r) => r.period === formattedPeriod);
      return row ? parseFloat(row.total_sales) : 0;
    });

    // Order Fulfillment Rates (Count by status)
    const [orderRows] = await connection.query(
      `
      SELECT 
        SUM(CASE WHEN status = 'Delivered' THEN 1 ELSE 0 END) AS delivered,
         SUM(CASE WHEN status IN ('Ready for Shipment', 'Shipped') THEN 1 ELSE 0 END) AS processing,
        SUM(CASE WHEN status = 'Cancelled' THEN 1 ELSE 0 END) AS cancelled
      FROM vendor_orders
      WHERE vendor_id = ?
    `,
      [vendorId]
    );

    const orderFulfillmentData = [
      orderRows[0].delivered || 0,
      orderRows[0].processing || 0,
      orderRows[0].cancelled || 0,
    ];

    // RFQ Conversion Rates (Query quotes table for vendor-specific statuses)
    const [rfqRows] = await connection.query(
      `
      SELECT 
        SUM(CASE WHEN status = 'Accepted' THEN 1 ELSE 0 END) AS converted,
        SUM(CASE WHEN status = 'Pending Quote' THEN 1 ELSE 0 END) AS pending,
        SUM(CASE WHEN status = 'Rejected' THEN 1 ELSE 0 END) AS declined,
        SUM(CASE WHEN status = 'Quoted' THEN 1 ELSE 0 END) AS quoted
      FROM quotes
      WHERE vendor_id = ?
    `,
      [vendorId]
    );

    const rfqConversionData = [
      rfqRows[0].converted || 0,
      rfqRows[0].quoted || 0,
      rfqRows[0].pending || 0,
      rfqRows[0].declined || 0,
    ];

    // Summary Metrics
    const [totalSalesRow] = await connection.query(
      `
      SELECT SUM(amount) AS total_sales
      FROM vendor_payments
      WHERE vendor_id = ? AND status = 'Paid'
    `,
      [vendorId]
    );

    const [fulfillmentRateRow] = await connection.query(
      `
      SELECT 
        (SUM(CASE WHEN status = 'Delivered' THEN 1 ELSE 0 END) / 
         NULLIF(COUNT(*), 0) * 100) AS fulfillment_rate
      FROM vendor_orders
      WHERE vendor_id = ?
    `,
      [vendorId]
    );

    const [conversionRateRow] = await connection.query(
      `
      SELECT 
        (SUM(CASE WHEN status = 'Accepted' THEN 1 ELSE 0 END) / 
         NULLIF(COUNT(*), 0) * 100) AS conversion_rate
      FROM quotes
      WHERE vendor_id = ?
    `,
      [vendorId]
    );

    res.json({
      sales: {
        labels,
        data: salesData,
      },
      orderFulfillment: {
        labels: ["Delivered", "Processing", "Cancelled"],
        data: orderFulfillmentData,
      },
      rfqConversion: {
        labels: ["Converted to Orders", "Quoted", "Pending Quote", "Declined"],
        data: rfqConversionData,
      },
      summary: {
        totalSales: parseFloat(totalSalesRow[0].total_sales || 0),
        fulfillmentRate: parseFloat(
          fulfillmentRateRow[0].fulfillment_rate || 0
        ).toFixed(2),
        conversionRate: parseFloat(
          conversionRateRow[0].conversion_rate || 0
        ).toFixed(2),
      },
    });
  } catch (error) {
    console.error("Error fetching analytics:", error);
    res.status(500).json({ error: "Failed to fetch analytics" });
  } finally {
    connection.release();
  }
});

// Get dashboard stats
app.get("/api/vendor/dashboard-stats", authenticateToken, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const vendorId = req.user.id;

    // Pending Orders: Orders not Delivered or Cancelled
    const [pendingOrdersRow] = await connection.query(
      `
      SELECT COUNT(*) AS count
      FROM vendor_orders
      WHERE vendor_id = ? AND status NOT IN ('Delivered', 'Cancelled')
    `,
      [vendorId]
    );
    const pendingOrdersCount = parseInt(pendingOrdersRow[0].count) || 0;

    // Active RFQs: Open RFQs where vendor has not submitted a quote
    const [activeRfqsRow] = await connection.query(
      `
      SELECT COUNT(DISTINCT rfqs.rfq_id) AS count
      FROM rfqs
      LEFT JOIN quotes ON rfqs.rfq_id = quotes.rfq_id AND quotes.vendor_id = ?
      WHERE rfqs.state = 'Open' AND quotes.quote_id IS NULL
    `,
      [vendorId]
    );
    const activeRfqsCount = parseInt(activeRfqsRow[0].count) || 0;

    // All Orders: Total orders for the vendor
    const [allOrdersRow] = await connection.query(
      `
      SELECT COUNT(*) AS count
      FROM vendor_orders
      WHERE vendor_id = ?
    `,
      [vendorId]
    );
    const allOrdersCount = parseInt(allOrdersRow[0].count) || 0;

    res.json({
      pendingOrders: pendingOrdersCount,
      activeRfqs: activeRfqsCount,
      allOrders: allOrdersCount,
    });
  } catch (error) {
    console.error("Error fetching dashboard stats:", error);
    res.status(500).json({ error: "Failed to fetch dashboard stats" });
  } finally {
    connection.release();
  }
});

app.post("/api/vendor/forgot-password", async (req, res) => {
  const { email } = req.body;

  if (!email) return res.status(400).json({ error: "Email is required" });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: "Invalid email format" });

  try {
    const [users] = await pool.query(
      "SELECT id, full_name FROM users WHERE email = ?",
      [email]
    );
    if (users.length === 0)
      return res.status(404).json({ error: "User not found" });

    const resetToken = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour from now

    // Delete previous token
    await pool.query("DELETE FROM password_resets WHERE email = ?", [email]);

    // Insert new token
    await pool.query(
      "INSERT INTO password_resets (email, token, expires_at) VALUES (?, ?, ?)",
      [email, resetToken, expiresAt]
    );

    const data = { token: resetToken, email };
    const encodedData = base64url.encode(JSON.stringify(data));
    const resetLink = `https://studiosignaturecabinets.com/vendor/reset-password?data=${encodedData}`;

    const mailOptions = {
      from: `"Studio Signature Cabinets" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Password Reset Request",
      html: `
        <h3>Password Reset Request</h3>
        <p>Dear ${users[0].full_name || "User"},</p>
        <p>We received a request to reset your password. Click the link below to set a new password:</p>
        <a href="${resetLink}" style="display:inline-block;padding:10px 20px;background-color:#007bff;color:#fff;text-decoration:none;border-radius:5px;">Reset Password</a>
        <p>This link will expire in 1 hour. If you didn’t request this, please ignore this email.</p>
        <p>Best regards,<br>Studio Signature Cabinets Team</p>
      `,
    };

    await transporter.sendMail(mailOptions);

    res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
    res.status(200).json({ message: "Password reset email sent successfully" });
  } catch (error) {
    console.error("Error processing forgot password:", error);
    res.status(500).json({ error: "Failed to send password reset email" });
  }
});

// POST /api/reset-password
app.post("/api/vendor/reset-password", async (req, res) => {
  const { email, token, newPassword, confirmPassword } = req.body;

  if (!email || !token || !newPassword || !confirmPassword) {
    return res.status(400).json({ error: "All fields are required" });
  }

  if (newPassword !== confirmPassword) {
    return res.status(400).json({ error: "New passwords do not match" });
  }

  const passwordRegex =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]).{8,}$/;
  if (!passwordRegex.test(newPassword) || /\s/.test(newPassword)) {
    return res.status(400).json({
      error:
        "Password must be at least 8 characters, include one uppercase, one lowercase, one number, one special character, and no spaces",
    });
  }

  try {
    // Log inputs
    console.log("Reset Password Payload:", { email, token });

    const [resets] = await pool.query(
      `SELECT * FROM password_resets WHERE email = ? AND token = ? AND expires_at > CONVERT_TZ(NOW(), 'SYSTEM', '+00:00')`,
      [email, token]
    );

    if (resets.length === 0) {
      return res.status(400).json({ error: "Invalid or expired reset token" });
    }

    const [users] = await pool.query(
      "SELECT id, full_name FROM users WHERE email = ?",
      [email]
    );
    if (users.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = users[0];
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await pool.query("UPDATE users SET password = ? WHERE id = ?", [
      hashedPassword,
      user.id,
    ]);
    await pool.query(
      "DELETE FROM password_resets WHERE email = ? AND token = ?",
      [email, token]
    );

    const mailOptions = {
      from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
      to: email,
      subject: "Password Reset Confirmation",
      html: `
        <h3>Password Reset Confirmation</h3>
        <p>Dear ${user.full_name || "User"},</p>
        <p>Your password has been successfully reset on ${new Date().toLocaleString(
          "en-US",
          { timeZone: "Asia/Kolkata" }
        )} IST.</p>
        <p>If you did not perform this action, please contact our support team immediately at <a href="mailto:info@studiosignaturecabinets.com">info@studiosignaturecabinets.com</a>.</p>
        <p>Best regards,<br>Studio Signature Cabinets Team</p>
      `,
    };

    await transporter.sendMail(mailOptions);

    res.status(200).json({ message: "Password reset successfully" });
  } catch (error) {
    console.error("Error resetting password:", error);
    res.status(500).json({ error: "Failed to reset password" });
  }
});

app.listen(port, "0.0.0.0", () => {
  console.log(`Server running on http://0.0.0.0:${port}`);
});


