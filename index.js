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

const router = express.Router();
const app = express();
const port = 3005;
const SALT_ROUNDS = 10;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = "1h";
app.use(cors({ origin: "*" })); // Allow all origins for testing
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
    // const [existingUsers] = await pool.query(
    //   "SELECT id FROM users WHERE email = ?",
    //   [email]
    // );
    // if (existingUsers.length > 0) {
    //   return res.status(400).json({ error: "Email already exists" });
    // }
    // Check if email already exists for same userType
    const [existingUsers] = await pool.query(
      "SELECT id FROM users WHERE email = ? AND user_type = ?",
      [email, userType]
    );
    if (existingUsers.length > 0) {
      return res
        .status(400)
        .json({
          error: `An account with this email already exists as a ${userType}`,
        });
    }

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

app.get("/api/profile", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const [users] = await pool.query(
      "SELECT id, user_type, full_name, company_name, email, phone, address, account_status, last_login, admin_discount,created_at FROM users WHERE id = ?",
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
            finishType === "Stain" ? stainOption : paintOption,
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

// app.get("/api/items", authenticateToken, async (req, res) => {
//   try {
//     const { item_type, value, sku_prefix,sku } = req.query;
//     let query = "SELECT * FROM items WHERE 1=1";
//     const params = [];

//     if (item_type) {
//       query += " AND item_type = ?";
//       params.push(item_type.toUpperCase());
//     }

//     if (sku) {
//       query += " AND sku = ?";
//       params.push(sku);
//     }

//     if (sku_prefix) {
//       query += " AND sku LIKE ?";
//       params.push(`${sku_prefix}%`);
//     }

//     const [rows] = await pool.query(query, params);
//     res.json(rows);
//   } catch (err) {
//     console.error("Error fetching items:", err);
//     res.status(500).json({ error: "Failed to fetch items", details: err.message });
//   }
// });

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
// app.get("/api/admin/users", adminauthenticateToken, async (req, res) => {
//   try {
//     const [users] = await pool.query(
//       "SELECT id, full_name, email,phone, created_at, last_login, account_status,is_active,company_name,address,admin_discount,updated_at	 FROM users"
//     );

//     res.json({
//       users: users.map((user) => ({
//         id: user.id,
//         fullName: user.full_name,
//         email: user.email,
//         phone: user.phone,
//         joinDate: user.created_at,
//         lastLogin: user.last_login || null,
//         account_status: user.account_status,
//         is_active: user.is_active,
//         company_name: user.company_name,
//         address: user.address,
//         admin_discount: user.admin_discount,
//         updated_at: user.updated_at,
//       })),
//     });
//   } catch (err) {
//     console.error("Server error:", err);
//     res.status(500).json({ error: "Server error" });
//   }
// });

app.get("/api/admin/users", adminauthenticateToken, async (req, res) => {
  try {
    const [users] = await pool.query(
      "SELECT id, full_name, email, phone, created_at, last_login, account_status, is_active, company_name, address, admin_discount, updated_at FROM users WHERE user_type = 'customer'"
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
      })),
    });
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// fetch all vendors

app.get("/api/admin/vendors", adminauthenticateToken, async (req, res) => {
  try {
    const [vendors] = await pool.query(
      "SELECT id, full_name, email, phone, created_at, last_login, account_status, is_active, company_name, address, updated_at FROM users WHERE user_type = 'vendor'"
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
      })),
    });
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.put(
  "/api/admin/vendor/:id/status",
  adminauthenticateToken,
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
app.put(
  "/api/admin/user/:id/discount",
  adminauthenticateToken,
  async (req, res) => {
    const { id } = req.params;
    const { admin_discount } = req.body;

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

    try {
      // Check if user exists
      const [users] = await pool.query("SELECT id FROM users WHERE id = ?", [
        id,
      ]);
      if (users.length === 0) {
        return res.status(404).json({ error: "User not found" });
      }

      // Update discount
      await pool.query(
        "UPDATE users SET admin_discount = ?, updated_at = NOW() WHERE id = ?",
        [admin_discount, id]
      );

      res.json({ message: "Customer discount updated successfully" });
    } catch (err) {
      console.error("Server error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Update User Status

app.put(
  "/api/admin/user/:id/status",
  adminauthenticateToken,
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
app.put(
  "/api/admin/orders/:id/shipping",
  adminauthenticateToken,
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

app.put(
  "/api/admin/orders/:id/status",
  adminauthenticateToken,
  async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;

    // Validate status
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
      // Check if order exists and fetch details
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

      // Prevent status changes if order is Cancelled
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

      // Update status
      await pool.query("UPDATE orders SET status = ? WHERE id = ?", [
        status,
        id,
      ]);

      // Send email for Accepted, Processing, Completed, or Cancelled
      if (
        ["Accepted", "Processing", "Completed", "Cancelled"].includes(status) &&
        user.email !== "N/A"
      ) {
        let mailOptions;
        switch (status) {
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
          case "Completed":
            mailOptions = {
              from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
              to: user.email,
              subject: `Your Order #${order.order_id} Has Been Completed!`,
              html: `
              <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2>Hello, ${user.full_name}!</h2>
                <p>Fantastic news! Your order <strong>#${
                  order.order_id
                }</strong> has been completed and shipped.</p>
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
                  <li>Your order has been shipped. Check your email for tracking information.</li>
                  <li>View your order history at <a href="https://studiosignaturecabinets.com/customer/orders">My Orders</a>.</li>
                </ul>
                <p>If you have any issues, contact us at <a href="mailto:info@studiosignaturecabinets.com">info@studiosignaturecabinets.com</a>.</p>
                <p>Enjoy your new cabinets!</p>
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
          // Log error but don't fail the status update
        }
      }

      res.json({ message: "Order status updated successfully" });
    } catch (err) {
      console.error("Server error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Schedule task to run every minute
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

// app.put("/api/admin/orders/:id/status", adminauthenticateToken, async (req, res) => {
//   const { id } = req.params;
//   const { status } = req.body;

//   // Validate status
//   if (!["Pending", "Accepted", "Processing", "Completed", "Cancelled"].includes(status)) {
//     return res.status(400).json({
//       error: "Invalid status. Must be Pending, Accepted, Processing, Completed, or Cancelled",
//     });
//   }

//   try {
//     // Check if order exists and fetch details
//     const [orders] = await pool.query(
//       `SELECT o.id, o.order_id, o.user_id, o.door_style, o.finish_type, o.stain_option, o.paint_option,
//               o.subtotal, o.tax, o.shipping, o.discount, o.additional_discount, o.total, o.status,
//               u.full_name, u.email
//        FROM orders o
//        LEFT JOIN users u ON o.user_id = u.id
//        WHERE o.id = ?`,
//       [id]
//     );
//     if (orders.length === 0) {
//       return res.status(404).json({ error: "Order not found" });
//     }

//     const order = orders[0];

//     // Prevent status changes if order is Cancelled
//     if (order.status === "Cancelled") {
//       return res.status(400).json({
//         error: "Cannot update status of a cancelled order",
//       });
//     }

//     const user = {
//       full_name: order.full_name || "Customer",
//       email: order.email || "N/A",
//     };
//     const additionalDiscountPercent =
//       order.subtotal && order.additional_discount
//         ? ((order.additional_discount / order.subtotal) * 100).toFixed(2)
//         : "0.00";

//     // Update status
//     await pool.query("UPDATE orders SET status = ? WHERE id = ?", [status, id]);

//     // If status is Completed, check for pending orders older than 24 hours
//     if (status === "Completed") {
//       const [pendingOrders] = await pool.query(
//         `SELECT o.id, o.order_id, o.user_id, o.door_style, o.finish_type, o.stain_option, o.paint_option,
//                 o.subtotal, o.tax, o.shipping, o.discount, o.additional_discount, o.total, o.status,
//                 u.full_name, u.email
//          FROM orders o
//          LEFT JOIN users u ON o.user_id = u.id
//          WHERE o.status = 'Pending' AND o.created_at < DATEADD(HOUR, -24, GETDATE())`
//       );

//       for (const pendingOrder of pendingOrders) {
//         const pendingUser = {
//           full_name: pendingOrder.full_name || "Customer",
//           email: pendingOrder.email || "N/A",
//         };
//         const pendingAdditionalDiscountPercent =
//           pendingOrder.subtotal && pendingOrder.additional_discount
//             ? ((pendingOrder.additional_discount / pendingOrder.subtotal) * 100).toFixed(2)
//             : "0.00";

//         // Update pending order to Accepted
//         await pool.query("UPDATE orders SET status = 'Accepted' WHERE id = ?", [pendingOrder.id]);

//         // Send email for Accepted status if email is available
//         if (pendingUser.email !== "N/A") {
//           const mailOptions = {
//             from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
//             to: pendingUser.email,
//             subject: `Your Order #${pendingOrder.order_id} Has Been Accepted!`,
//             html: `
//               <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
//                 <h2>Hello, ${pendingUser.full_name}!</h2>
//                 <p>Great news! Your order <strong>#${pendingOrder.order_id}</strong> has been accepted and is now being processed.</p>
//                 <h3>Order Details:</h3>
//                 <ul style="list-style: none; padding: 0;">
//                   <li><strong>Order ID:</strong> ${pendingOrder.order_id}</li>
//                   <li><strong>Door Style:</strong> ${pendingOrder.door_style}</li>
//                   <li><strong>Finish Type:</strong> ${pendingOrder.finish_type}</li>
//                   ${pendingOrder.stain_option ? `<li><strong>Stain Option:</strong> ${pendingOrder.stain_option}</li>` : ""}
//                   ${pendingOrder.paint_option ? `<li><strong>Paint Option:</strong> ${pendingOrder.paint_option}</li>` : ""}
//                   <li><strong>Subtotal:</strong> $${parseFloat(pendingOrder.subtotal).toFixed(2)}</li>
//                   <li><strong>Special Discount:</strong> $${parseFloat(pendingOrder.discount || 0).toFixed(2)}</li>
//                   <li><strong>Additional Discount:</strong> ${pendingAdditionalDiscountPercent}% ($${parseFloat(pendingOrder.additional_discount || 0).toFixed(2)})</li>
//                   <li><strong>Tax:</strong> $${parseFloat(pendingOrder.tax).toFixed(2)}</li>
//                   <li><strong>Shipping:</strong> ${pendingOrder.shipping !== null ? `$${parseFloat(pendingOrder.shipping).toFixed(2)}` : "-"}</li>
//                   <li><strong>Total:</strong> $${parseFloat(pendingOrder.total).toFixed(2)}</li>
//                 </ul>
//                 <p><strong>Next Steps:</strong></p>
//                 <ul>
//                   <li>Your order is now in the processing stage. We’ll notify you with updates on its progress.</li>
//                   <li>You can track your order status in your account at <a href="https://studiosignaturecabinets.com/customer/orders">My Orders</a>.</li>
//                 </ul>
//                 <p>If you have any questions, please contact our support team at <a href="mailto:info@studiosignaturecabinets.com">info@studiosignaturecabinets.com</a>.</p>
//                 <p>Thank you for choosing Studio Signature Cabinets!</p>
//                 <p>Best regards,<br>Team Studio Signature Cabinets</p>
//               </div>
//             `,
//           };

//           try {
//             await transporter.sendMail(mailOptions);
//             console.log(`Email sent for order ${pendingOrder.order_id} status: Accepted`);
//           } catch (emailErr) {
//             console.error(`Failed to send email for Accepted status:`, emailErr);
//           }
//         }
//       }
//     }

//     // Send email for Accepted, Processing, Completed, or Cancelled
//     if (["Accepted", "Processing", "Completed", "Cancelled"].includes(status) && user.email !== "N/A") {
//       let mailOptions;
//       switch (status) {
//         case "Accepted":
//           mailOptions = {
//             from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
//             to: user.email,
//             subject: `Your Order #${order.order_id} Has Been Accepted!`,
//             html: `
//               <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
//                 <h2>Hello, ${user.full_name}!</h2>
//                 <p>Great news! Your order <strong>#${order.order_id}</strong> has been accepted and is now being processed.</p>
//                 <h3>Order Details:</h3>
//                 <ul style="list-style: none; padding: 0;">
//                   <li><strong>Order ID:</strong> ${order.order_id}</li>
//                   <li><strong>Door Style:</strong> ${order.door_style}</li>
//                   <li><strong>Finish Type:</strong> ${order.finish_type}</li>
//                   ${order.stain_option ? `<li><strong>Stain Option:</strong> ${order.stain_option}</li>` : ""}
//                   ${order.paint_option ? `<li><strong>Paint Option:</strong> ${order.paint_option}</li>` : ""}
//                   <li><strong>Subtotal:</strong> $${parseFloat(order.subtotal).toFixed(2)}</li>
//                   <li><strong>Special Discount:</strong> $${parseFloat(order.discount || 0).toFixed(2)}</li>
//                   <li><strong>Additional Discount:</strong> ${additionalDiscountPercent}% ($${parseFloat(order.additional_discount || 0).toFixed(2)})</li>
//                   <li><strong>Tax:</strong> $${parseFloat(order.tax).toFixed(2)}</li>
//                   <li><strong>Shipping:</strong> ${order.shipping !== null ? `$${parseFloat(order.shipping).toFixed(2)}` : "-"}</li>
//                   <li><strong>Total:</strong> $${parseFloat(order.total).toFixed(2)}</li>
//                 </ul>
//                 <p><strong>Next Steps:</strong></p>
//                 <ul>
//                   <li>Your order is now in the processing stage. We’ll notify you with updates on its progress.</li>
//                   <li>You can track your order status in your account at <a href="https://studiosignaturecabinets.com/customer/orders">My Orders</a>.</li>
//                 </ul>
//                 <p>If you have any questions, please contact our support team at <a href="mailto:info@studiosignaturecabinets.com">info@studiosignaturecabinets.com</a>.</p>
//                 <p>Thank you for choosing Studio Signature Cabinets!</p>
//                 <p>Best regards,<br>Team Studio Signature Cabinets</p>
//               </div>
//             `,
//           };
//           break;
//         case "Processing":
//           mailOptions = {
//             from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
//             to: user.email,
//             subject: `Your Order #${order.order_id} is Being Processed!`,
//             html: `
//               <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
//                 <h2>Hello, ${user.full_name}!</h2>
//                 <p>Your order <strong>#${order.order_id}</strong> is now being processed. We're preparing your items for shipment.</p>
//                 <h3>Order Details:</h3>
//                 <ul style="list-style: none; padding: 0;">
//                   <li><strong>Order ID:</strong> ${order.order_id}</li>
//                   <li><strong>Door Style:</strong> ${order.door_style}</li>
//                   <li><strong>Finish Type:</strong> ${order.finish_type}</li>
//                   ${order.stain_option ? `<li><strong>Stain Option:</strong> ${order.stain_option}</li>` : ""}
//                   ${order.paint_option ? `<li><strong>Paint Option:</strong> ${order.paint_option}</li>` : ""}
//                   <li><strong>Subtotal:</strong> $${parseFloat(order.subtotal).toFixed(2)}</li>
//                   <li><strong>Special Discount:</strong> $${parseFloat(order.discount || 0).toFixed(2)}</li>
//                   <li><strong>Additional Discount:</strong> ${additionalDiscountPercent}% ($${parseFloat(order.additional_discount || 0).toFixed(2)})</li>
//                   <li><strong>Tax:</strong> $${parseFloat(order.tax).toFixed(2)}</li>
//                   <li><strong>Shipping:</strong> ${order.shipping !== null ? `$${parseFloat(order.shipping).toFixed(2)}` : "-"}</li>
//                   <li><strong>Total:</strong> $${parseFloat(order.total).toFixed(2)}</li>
//                 </ul>
//                 <p><strong>Next Steps:</strong></p>
//                 <ul>
//                   <li>We are preparing your order for shipment. You’ll receive a shipping confirmation soon.</li>
//                   <li>Track your order status at <a href="https://studiosignaturecabinets.com/customer/orders">My Orders</a>.</li>
//                 </ul>
//                 <p>For inquiries, contact us at <a href="mailto:info@studiosignaturecabinets.com">info@studiosignaturecabinets.com</a>.</p>
//                 <p>Thank you for your patience!</p>
//                 <p>Best regards,<br>Team Studio Signature Cabinets</p>
//               </div>
//             `,
//           };
//           break;
//         case "Completed":
//           mailOptions = {
//             from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
//             to: user.email,
//             subject: `Your Order #${order.order_id} Has Been Completed!`,
//             html: `
//               <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
//                 <h2>Hello, ${user.full_name}!</h2>
//                 <p>Fantastic news! Your order <strong>#${order.order_id}</strong> has been completed and shipped.</p>
//                 <h3>Order Details:</h3>
//                 <ul style="list-style: none; padding: 0;">
//                   <li><strong>Order ID:</strong> ${order.order_id}</li>
//                   <li><strong>Door Style:</strong> ${order.door_style}</li>
//                   <li><strong>Finish Type:</strong> ${order.finish_type}</li>
//                   ${order.stain_option ? `<li><strong>Stain Option:</strong> ${order.stain_option}</li>` : ""}
//                   ${order.paint_option ? `<li><strong>Paint Option:</strong> ${order.paint_option}</li>` : ""}
//                   <li><strong>Subtotal:</strong> $${parseFloat(order.subtotal).toFixed(2)}</li>
//                   <li><strong>Special Discount:</strong> $${parseFloat(order.discount || 0).toFixed(2)}</li>
//                   <li><strong>Additional Discount:</strong> ${additionalDiscountPercent}% ($${parseFloat(order.additional_discount || 0).toFixed(2)})</li>
//                   <li><strong>Tax:</strong> $${parseFloat(order.tax).toFixed(2)}</li>
//                   <li><strong>Shipping:</strong> ${order.shipping !== null ? `$${parseFloat(order.shipping).toFixed(2)}` : "-"}</li>
//                   <li><strong>Total:</strong> $${parseFloat(order.total).toFixed(2)}</li>
//                 </ul>
//                 <p><strong>Next Steps:</strong></p>
//                 <ul>
//                   <li>Your order has been shipped. Check your email for tracking information.</li>
//                   <li>View your order history at <a href="https://studiosignaturecabinets.com/customer/orders">My Orders</a>.</li>
//                 </ul>
//                 <p>If you have any issues, contact us at <a href="mailto:info@studiosignaturecabinets.com">info@studiosignaturecabinets.com</a>.</p>
//                 <p>Enjoy your new cabinets!</p>
//                 <p>Best regards,<br>Team Studio Signature Cabinets</p>
//               </div>
//             `,
//           };
//           break;
//         case "Cancelled":
//           mailOptions = {
//             from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
//             to: user.email,
//             subject: `Your Order #${order.order_id} Has Been Cancelled`,
//             html: `
//               <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
//                 <h2>Hello, ${user.full_name}!</h2>
//                 <p>We’re sorry to inform you that your order <strong>#${order.order_id}</strong> has been cancelled.</p>
//                 <p><strong>Note:</strong> This order cannot be reinstated or modified once cancelled.</p>
//                 <h3>Order Details:</h3>
//                 <ul style="list-style: none; padding: 0;">
//                   <li><strong>Order ID:</strong> ${order.order_id}</li>
//                   <li><strong>Door Style:</strong> ${order.door_style}</li>
//                   <li><strong>Finish Type:</strong> ${order.finish_type}</li>
//                   ${order.stain_option ? `<li><strong>Stain Option:</strong> ${order.stain_option}</li>` : ""}
//                   ${order.paint_option ? `<li><strong>Paint Option:</strong> ${order.paint_option}</li>` : ""}
//                   <li><strong>Subtotal:</strong> $${parseFloat(order.subtotal).toFixed(2)}</li>
//                   <li><strong>Special Discount:</strong> $${parseFloat(order.discount || 0).toFixed(2)}</li>
//                   <li><strong>Additional Discount:</strong> ${additionalDiscountPercent}% ($${parseFloat(order.additional_discount || 0).toFixed(2)})</li>
//                   <li><strong>Tax:</strong> $${parseFloat(order.tax).toFixed(2)}</li>
//                   <li><strong>Shipping:</strong> ${order.shipping !== null ? `$${parseFloat(order.shipping).toFixed(2)}` : "-"}</li>
//                   <li><strong>Total:</strong> $${parseFloat(order.total).toFixed(2)}</li>
//                 </ul>
//                 <p><strong>Next Steps:</strong></p>
//                 <ul>
//                   <li>If this was unexpected, please contact us immediately at <a href="mailto:info@studiosignaturecabinets.com">info@studiosignaturecabinets.com</a>.</li>
//                   <li>Explore our products to place a new order at <a href="https://studiosignaturecabinets.com">Studio Signature Cabinets</a>.</li>
//                 </ul>
//                 <p>We apologize for any inconvenience. Let us know how we can assist you further.</p>
//                 <p>Best regards,<br>Team Studio Signature Cabinets</p>
//               </div>
//             `,
//           };
//           break;
//       }

//       try {
//         await transporter.sendMail(mailOptions);
//         console.log(`Email sent for order ${order.order_id} status: ${status}`);
//       } catch (emailErr) {
//         console.error(`Failed to send email for ${status} status:`, emailErr);
//       }
//     }

//     res.json({ message: "Order status updated successfully" });
//   } catch (err) {
//     console.error("Server error:", err);
//     res.status(500).json({ error: "Server error" });
//   }
// });

// Delete Order

app.delete(
  "/api/admin/orders/:id",
  adminauthenticateToken,
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
app.get(
  "/api/admin/contact/messages",
  adminauthenticateToken,
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
app.post(
  "/api/admin/elearning/upload",
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
app.get(
  "/api/adminuserpanel/users",
  adminauthenticateToken,
  async (req, res) => {
    try {
      const [customerVendorUsers] = await pool.query(
        "SELECT id, full_name AS fullName, email, user_type AS userType, created_at, updated_at FROM users "
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
      return res
        .status(400)
        .json({
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
        "INSERT INTO admins (full_name, email, password, role, phone, bio, is_active) VALUES (?, ?, ?, 'Administrator', ?, ?, 1)",
        [fullName, email, hashedPassword, phone || null, bio || null]
      );

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
      return res
        .status(400)
        .json({
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
      res.json(rows);
    } catch (err) {
      console.error("Error fetching vendor products:", err);
      res.status(500).json({ error: "Failed to fetch vendor products" });
    }
  }
);

//-----------------------------------------------------------------------VEndor API Endpoints-----------------------------------------------------------------------

/////////////vendor////////////////////

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

app.listen(port, "0.0.0.0", () => {
  console.log(`Server running on http://0.0.0.0:${port}`);
});
