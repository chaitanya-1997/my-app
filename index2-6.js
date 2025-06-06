const express = require("express");
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const nodemailer = require("nodemailer");

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
            <li>If you have any urgent questions, please contact our support team at <a href="mailto:support@studiosignaturecabinets.com">support@studiosignaturecabinets.com</a>.</li>
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
            <a href="http://localhost:3005/admin/users/${userId}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Review User</a>
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

    // Check if user is a customer (not a vendor)
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

    // Create JWT
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "1d",
    });

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
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
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
      "SELECT password FROM users WHERE id = ?",
      [userId]
    );
    if (users.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    // Verify current password
    const isMatch = await bcrypt.compare(currentPassword, users[0].password);
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

    res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

//place an order

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
    discount, // New field
  } = req.body;

  try {
    // Validations
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

    // Get user info, including admin_discount
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

    // Verify discount
    const expectedDiscount = parseFloat((subtotal * adminDiscount).toFixed(2));
    if (
      discount === undefined ||
      parseFloat(discount.toFixed(2)) !== expectedDiscount
    ) {
      return res.status(400).json({
        error: `Invalid discount amount. Expected: ${expectedDiscount}, Received: ${discount}`,
      });
    }

    // Generate unique order_id
    const [lastOrder] = await pool.query(
      "SELECT order_id FROM orders ORDER BY id DESC LIMIT 1"
    );
    let newOrderNumber = 1;
    if (lastOrder.length > 0) {
      const lastOrderId = lastOrder[0].order_id;
      newOrderNumber = parseInt(lastOrderId.split("-")[1]) + 1;
    }
    const orderId = `ORD-${String(newOrderNumber).padStart(3, "0")}`;

    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // Insert into orders table
      const [orderResult] = await connection.query(
        `INSERT INTO orders (
          order_id, user_id, door_style, finish_type, stain_option, paint_option, 
          account, bill_to, subtotal, tax, shipping, discount, total, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending', NOW())`,
        [
          orderId,
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
          discount || 0, // Store 0 if discount is 0
          total,
        ]
      );

      const dbOrderId = orderResult.insertId;

      // Insert items
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
            dbOrderId,
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

      // Email template
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
              shipping !== null ? `$${parseFloat(shipping).toFixed(2)}` : "Free"
            }</li>
            <li><strong>Total:</strong> $${parseFloat(total).toFixed(2)}</li>
          </ul>
        </div>
      `;

      // Send emails
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

// Fetch orders for the authenticated user

// app.get("/api/orders", authenticateToken, async (req, res) => {
//   try {
//     const userId = req.user.id;

//     const [orders] = await pool.query(
//       `SELECT
//           o.order_id AS id,
//           o.created_at AS created_at,
//           o.door_style,
//           o.finish_type,
//           o.stain_option,
//           o.paint_option,
//           o.account,
//           o.bill_to,
//           o.subtotal,
//           o.tax,
//           o.shipping,
//           o.total,
//           o.discount,
//           o.status,

//           GROUP_CONCAT(
//             JSON_OBJECT(
//               'sku', oi.sku,
//               'name', oi.name,
//               'quantity', oi.quantity,
//               'price', oi.price,
//               'totalAmount', oi.total_amount
//             )
//           ) AS items
//           FROM orders o
//           LEFT JOIN order_items oi ON o.id = oi.order_id
//           WHERE o.user_id = ?
//           GROUP BY o.id
//           ORDER BY o.created_at DESC`,
//       [userId]
//     );

//     const formattedOrders = orders.map((order) => {
//       console.log(`Order ${order.id}: created_at = ${order.created_at}`); // Debug log
//       return {
//         id: order.id,
//         created_at: order.created_at
//           ? new Date(order.created_at).toISOString()
//           : null, // Ensure ISO format
//         date: order.created_at
//           ? new Date(order.created_at).toISOString().split("T")[0]
//           : null, // For display
//         productLine: order.door_style.includes("Shaker")
//           ? "Kitchen Shaker"
//           : "Bath Shaker",
//         status: order.status,
//         total: `$${parseFloat(order.total || 0).toFixed(2)}`,
//         subtotal: parseFloat(order.subtotal || 0).toFixed(2),
//         discount: parseFloat(order.discount || 0).toFixed(2),
//         tax: parseFloat(order.tax || 0).toFixed(2),
//         shipping:
//           order.shipping !== null
//             ? parseFloat(order.shipping).toFixed(2)
//             : null,
//         account: order.account,
//         bill_to: order.bill_to,
//         items: order.items ? JSON.parse(`[${order.items}]`) : [],
//         door_style: order.door_style,
//         finish_type: order.finish_type,
//         stain_option: order.stain_option,
//         paint_option: order.paint_option,
//       };
//     });

//     res.json(formattedOrders);
//   } catch (err) {
//     console.error("Server error:", err);
//     res.status(500).json({ error: "Server error" });
//   }
// });

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
            shipping !== null ? `$${parseFloat(shipping).toFixed(2)}` : "Free"
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
            : "Free"
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

// New endpoint to get next order ID
app.get("/api/orders/next-id", async (req, res) => {
  try {
    const [lastOrder] = await pool.query(
      "SELECT order_id FROM orders ORDER BY id DESC LIMIT 1"
    );
    let newOrderNumber = 1;
    if (lastOrder.length > 0) {
      const lastOrderId = lastOrder[0].order_id;
      newOrderNumber = parseInt(lastOrderId.split("-")[1]) + 1;
    }
    const nextOrderId = `ORD-${String(newOrderNumber).padStart(3, "0")}`;
    res.status(200).json({ nextOrderId: nextOrderId });
  } catch (err) {
    console.error("Error fetching next order ID:", err);
    res.status(500).json({ error: "Failed to fetch next order ID" });
  }
});

// Fetch items (filtered by item_type or SKU)
app.get("/api/items", authenticateToken, async (req, res) => {
  try {
    const { item_type, sku } = req.query;
    let query =
      "SELECT sku, description, price, item_type FROM items WHERE 1=1";
    const params = [];

    if (item_type) {
      query += " AND item_type = ?";
      params.push(item_type.toUpperCase()); // Ensure STAINED PLYWOOD or PAINTED PLYWOOD
    }

    if (sku) {
      query += " AND sku = ?";
      params.push(sku);
    }

    const [rows] = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    console.error("Error fetching items:", err);
    res
      .status(500)
      .json({ error: "Failed to fetch items", details: err.message });
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
            <a href="http://localhost:3005/admin/login" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Log In Now</a>
          </p>
          <p>For support, contact us at <a href="mailto:support@studiosignaturecabinets.com">support@studiosignaturecabinets.com</a>.</p>
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
            <a href="http://localhost:3005/admin/admins/${adminId}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">View Admin</a>
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
  if (newPassword.length < 8) {
    return res
      .status(400)
      .json({ error: "New password must be at least 8 characters" });
  }
  if (newPassword !== confirmPassword) {
    return res
      .status(400)
      .json({ error: "New password and confirm password do not match" });
  }

  try {
    // Fetch current password
    const [admins] = await pool.query(
      "SELECT password FROM admins WHERE id = ?",
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

    res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Fetch All Users
app.get("/api/admin/users", adminauthenticateToken, async (req, res) => {
  try {
    const [users] = await pool.query(
      "SELECT id, full_name, email,phone, created_at, last_login, account_status,is_active,company_name,address,admin_discount,updated_at	 FROM users"
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
            <p>If you have any questions, please contact our support team at <a href="mailto:support@studiosignaturecabinets.com">support@studiosignaturecabinets.com</a>.</p>
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

// Fetch All Orders
// app.get('/api/admin/orders', adminauthenticateToken, async (req, res) => {
//   try {
//     const [orders] = await pool.query(`
//       SELECT
//         o.id,
//         o.order_id,
//         o.user_id,
//         u.full_name AS user_name,
//         u.email AS user_email,
//         o.door_style,
//         o.finish_type,
//         o.stain_option,
//         o.paint_option,
//         o.account,
//         o.bill_to,
//         o.subtotal,
//         o.tax,
//         o.shipping,
//         o.total,
//         o.status,
//         o.created_at
//       FROM orders o
//       LEFT JOIN users u ON o.user_id = u.id
//       ORDER BY o.created_at DESC
//     `);

//     res.json({
//       orders: orders.map(order => ({
//         id: order.id,
//         orderId: order.order_id,
//         userId: order.user_id,
//         userName: order.user_name || 'Unknown User',
//         userEmail: order.user_email || 'N/A',
//         doorStyle: order.door_style,
//         finishType: order.finish_type,
//         stainOption: order.stain_option || 'None',
//         paintOption: order.paint_option || 'None',
//         account: order.account,
//         billTo: order.bill_to,
//         subtotal: parseFloat(order.subtotal).toFixed(2),
//         tax: parseFloat(order.tax).toFixed(2),
//         shipping: order.shipping ? parseFloat(order.shipping).toFixed(2) : '0.00',
//         total: parseFloat(order.total).toFixed(2),
//         status: order.status,
//         createdAt: order.created_at,
//       })),
//     });
//   } catch (err) {
//     console.error('Server error:', err);
//     res.status(500).json({ error: 'Server error' });
//   }
// });

// // GET /api/admin/orders
// app.get("/api/admin/orders", adminauthenticateToken, async (req, res) => {
//   try {
//     const [orders] = await pool.query(`
//       SELECT
//         o.id AS id,
//         o.order_id AS orderId,
//         o.user_id,
//         u.full_name AS userName,
//         u.email AS userEmail,
//         o.created_at AS created_at,
//         o.door_style AS door_style,
//         o.finish_type AS finish_type,
//         o.stain_option AS stain_option,
//         o.paint_option AS paint_option,
//         o.account,
//         o.bill_to,
//         o.subtotal,
//         o.tax,
//         o.shipping,
//         o.total,
//         o.discount,
//         o.additional_discount AS additional_discount,
//         o.status,
//         GROUP_CONCAT(
//           JSON_OBJECT(
//             'sku', oi.sku,
//             'name', oi.name,
//             'quantity', oi.quantity,
//             'price', oi.price,
//             'totalAmount', oi.total_amount
//           )
//         ) AS items
//       FROM orders o
//       LEFT JOIN users u ON o.user_id = u.id
//       LEFT JOIN order_items oi ON o.id = oi.order_id
//       GROUP BY o.id
//       ORDER BY o.created_at DESC
//     `);

//     const formattedOrders = orders.map((order) => {
//       console.log(`Order ${order.orderId}: created_at = ${order.created_at}`); // Debug log
//       return {
//         id: order.id,
//         orderId: order.orderId,
//         userId: order.user_id,
//         userName: order.userName || "Unknown User",
//         userEmail: order.userEmail || "N/A",
//         created_at: order.created_at
//           ? new Date(order.created_at).toISOString()
//           : null,
//         date: order.created_at
//           ? new Date(order.created_at).toISOString().split("T")[0]
//           : null,
//         productLine: order.door_style.includes("Shaker")
//           ? "Kitchen Shaker"
//           : "Bath Shaker",
//         status: order.status,
//         total: `$${parseFloat(order.total || 0).toFixed(2)}`,
//         subtotal: parseFloat(order.subtotal || 0).toFixed(2),
//         discount: parseFloat(order.discount || 0).toFixed(2),
//         additional_discount: parseFloat(order.additional_discount || 0).toFixed(
//           2
//         ),
//         tax: parseFloat(order.tax || 0).toFixed(2),
//         shipping:
//           order.shipping !== null
//             ? parseFloat(order.shipping).toFixed(2)
//             : null,
//         account: order.account,
//         bill_to: order.bill_to,
//         items: order.items ? JSON.parse(`[${order.items}]`) : [],
//         door_style: order.door_style,
//         finish_type: order.finish_type,
//         stain_option: order.stain_option,
//         paint_option: order.paint_option,
//       };
//     });

//     res.json(formattedOrders);
//   } catch (err) {
//     console.error("Server error:", err);
//     res.status(500).json({ error: "Server error" });
//   }
// });

// // GET /api/admin/orders/:id (unchanged)
// app.get("/api/admin/orders/:id", adminauthenticateToken, async (req, res) => {
//   const orderId = req.params.id;
//   try {
//     const [orders] = await pool.query(
//       `
//       SELECT
//         o.id,
//         o.order_id AS orderId,
//         o.user_id,
//         u.full_name AS userName,
//         u.email AS userEmail,
//         o.door_style AS doorStyle,
//         o.finish_type AS finishType,
//         o.stain_option AS stainOption,
//         o.paint_option AS paintOption,
//         o.account,
//         o.bill_to AS billTo,
//         o.subtotal,
//         o.tax,
//         o.shipping,
//         o.total,
//         o.discount,
//         o.additional_discount AS additionalDiscount,
//         o.status,
//         o.created_at AS createdAt,
//         GROUP_CONCAT(
//           JSON_OBJECT(
//             'sku', oi.sku,
//             'name', oi.name,
//             'quantity', oi.quantity,
//             'price', oi.price,
//             'totalAmount', oi.total_amount
//           )
//         ) AS items
//       FROM orders o
//       LEFT JOIN users u ON o.user_id = u.id
//       LEFT JOIN order_items oi ON o.id = oi.order_id
//       WHERE o.id = ?
//       GROUP BY o.id
//     `,
//       [orderId]
//     );

//     if (orders.length === 0) {
//       return res.status(404).json({ error: "Order not found" });
//     }

//     const order = orders[0];
//     res.json({
//       order: {
//         id: order.id,
//         orderId: order.orderId,
//         userId: order.user_id,
//         userName: order.userName || "Unknown User",
//         userEmail: order.userEmail || "N/A",
//         door_style: order.doorStyle,
//         finish_type: order.finishType,
//         stain_option: order.stainOption || "None",
//         paint_option: order.paintOption || "None",
//         account: order.account,
//         bill_to: order.billTo,
//         subtotal: parseFloat(order.subtotal || 0).toFixed(2),
//         tax: parseFloat(order.tax || 0).toFixed(2),
//         shipping: order.shipping ? parseFloat(order.shipping).toFixed(2) : null,
//         discount: parseFloat(order.discount || 0).toFixed(2),
//         additional_discount: parseFloat(order.additional_discount || 0).toFixed(
//           2
//         ),
//         total: parseFloat(order.total || 0).toFixed(2),
//         status: order.status,
//         created_at: order.createdAt
//           ? new Date(order.createdAt).toISOString()
//           : null,
//         date: order.createdAt
//           ? new Date(order.createdAt).toISOString().split("T")[0]
//           : null,
//         productLine: order.doorStyle.includes("Shaker")
//           ? "Kitchen Shaker"
//           : "Bath Shaker",
//         items: order.items ? JSON.parse(`[${order.items}]`) : [],
//       },
//     });
//   } catch (err) {
//     console.error("Server error:", err);
//     res.status(500).json({ error: "Server error" });
//   }
// });

// GET /api/admin/orders
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

// GET /api/admin/orders/:id
// app.get("/api/admin/orders/:id", adminauthenticateToken, async (req, res) => {
//   const orderId = req.params.id;
//   try {
//     const [orders] = await pool.query(
//       `
//       SELECT
//         o.id,
//         o.order_id AS orderId,
//         o.user_id,
//         u.full_name AS userName,
//         u.email AS userEmail,
//         o.door_style AS doorStyle,
//         o.finish_type AS finishType,
//         o.stain_option AS stainOption,
//         o.paint_option AS paintOption,
//         o.account,
//         o.bill_to AS billTo,
//         o.subtotal,
//         o.tax,
//         o.shipping,
//         o.discount,
//         o.additional_discount,
//         o.total,
//         o.status,
//         o.created_at AS createdAt,
//         GROUP_CONCAT(
//           JSON_OBJECT(
//             'sku', oi.sku,
//             'name', oi.name,
//             'quantity', oi.quantity,
//             'price', oi.price,
//             'totalAmount', oi.total_amount
//           )
//         ) AS items
//       FROM orders o
//       LEFT JOIN users u ON o.user_id = u.id
//       LEFT JOIN order_items oi ON o.id = oi.order_id
//       WHERE o.id = ?
//       GROUP BY o.id
//     `,
//       [orderId]
//     );

//     if (orders.length === 0) {
//       return res.status(404).json({ error: "Order not found" });
//     }

//     const order = orders[0];
//     res.json({
//       order: {
//         id: order.id,
//         orderId: order.orderId,
//         userId: order.user_id,
//         userName: order.userName || "Unknown User",
//         userEmail: order.userEmail || "N/A",
//         door_style: order.doorStyle,
//         finish_type: order.finishType,
//         stain_option: order.stainOption || "None",
//         paint_option: order.paintOption || "None",
//         account: order.account,
//         bill_to: order.billTo,
//         subtotal: parseFloat(order.subtotal || 0).toFixed(2),
//         tax: parseFloat(order.tax || 0).toFixed(2),
//         shipping: order.shipping ? parseFloat(order.shipping).toFixed(2) : null,
//         discount: parseFloat(order.discount || 0).toFixed(2),
//         additional_discount: parseFloat(order.additional_discount || 0).toFixed(2),
//         total: parseFloat(order.total || 0).toFixed(2),
//         status: order.status,
//         created_at: order.createdAt
//           ? new Date(order.createdAt).toISOString()
//           : null,
//         date: order.createdAt
//           ? new Date(order.createdAt).toISOString().split("T")[0]
//           : null,
//       },
//     });
//   } catch (err) {
//     console.error("Server error:", err);
//     res.status(500).json({ error: "Server error" });
//   }
// });

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

// // UPDATED: POST /api/admin/orders/:id to update shipping and total
// app.post("/api/admin/orders/:id", adminauthenticateToken, async (req, res) => {
//   const { id } = req.params;
//   const { shipping } = req.body;

//   console.log(`POST /api/admin/orders/${id} called with shipping: ${shipping}`);

//   // Validate shipping
//   if (typeof shipping !== "number" || shipping < 0) {
//     console.log(`Invalid shipping charge: ${shipping}`);
//     return res.status(400).json({ error: "Invalid shipping charge" });
//   }

//   try {
//     // Fetch order details
//     const [orders] = await pool.query(
//       `SELECT o.id, o.order_id, o.total, o.user_id, u.full_name, u.email
//          FROM orders o
//          LEFT JOIN users u ON o.user_id = u.id
//          WHERE o.id = ?`,
//       [id]
//     );
//     if (orders.length === 0) {
//       console.log(`Order ${id} not found`);
//       return res.status(404).json({ error: "Order not found" });
//     }

//     const order = orders[0];
//     const user = {
//       full_name: order.full_name || "Customer",
//       email: order.email || "N/A",
//     };

//     // Calculate new total
//     const currentTotal = parseFloat(order.total) || 0;
//     const newShipping = parseFloat(shipping);
//     const newTotal = currentTotal + newShipping;

//     // Update shipping and total
//     await pool.query("UPDATE orders SET shipping = ?, total = ? WHERE id = ?", [
//       newShipping,
//       newTotal,
//       id,
//     ]);

//     // Send email to user
//     const mailOptions = {
//       from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
//       to: user.email,
//       subject: `Updated Order #${order.order_id}: Final Amount with Shipping`,
//       html: `
//           <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
//             <h2>Hello, ${user.full_name}!</h2>
//             <p>We’ve updated the shipping charges for your order <strong>#${
//               order.order_id
//             }</strong>. Below is the final amount including the new shipping charges.</p>
//             <h3>Order Summary:</h3>
//             <ul style="list-style: none; padding: 0;">
//               <li><strong>Order ID:</strong> ${order.order_id}</li>
//               <li><strong>Shipping Charges:</strong> $${newShipping.toFixed(
//                 2
//               )}</li>
//               <li><strong>Final Total:</strong> $${newTotal.toFixed(2)}</li>
//             </ul>
//             <p><strong>Next Steps:</strong></p>
//             <ul>
//               <li>You can view your updated order details in your account at <a href="https://studiosignaturecabinets.com/customer/orders">My Orders</a>.</li>
//               <li>If you have any questions, please contact our support team at <a href="mailto:support@studiosignaturecabinets.com">support@studiosignaturecabinets.com</a>.</li>
//             </ul>
//             <p>Thank you for choosing Studio Signature Cabinets!</p>
//             <p>Best regards,<br>Team Studio Signature Cabinets</p>
//           </div>
//         `,
//     };

//     try {
//       await transporter.sendMail(mailOptions);
//       console.log(`Shipping update email sent to ${user.email}`);
//     } catch (emailErr) {
//       console.error("Failed to send shipping update email:", emailErr);
//       // Log error but don't fail the update
//     }

//     console.log(
//       `Shipping and total updated for order ${id}: shipping=${newShipping}, total=${newTotal}`
//     );
//     res.json({
//       message: "Shipping charges and total updated successfully",
//       shipping: newShipping,
//       total: newTotal,
//     });
//   } catch (err) {
//     console.error("Server error updating shipping:", err);
//     res.status(500).json({ error: "Server error" });
//   }
// });

// // Fallback: PUT /api/admin/orders/:id/shipping
// app.put(
//   "/api/admin/orders/:id/shipping",
//   adminauthenticateToken,
//   async (req, res) => {
//     const { id } = req.params;
//     const { shipping } = req.body;

//     console.log(
//       `PUT /api/admin/orders/${id}/shipping called with shipping: ${shipping}`
//     );

//     // Validate shipping
//     if (typeof shipping !== "number" || shipping < 0) {
//       console.log(`Invalid shipping charge: ${shipping}`);
//       return res.status(400).json({ error: "Invalid shipping charge" });
//     }

//     try {
//       // Fetch order details
//       const [orders] = await pool.query(
//         `SELECT o.id, o.order_id, o.total, o.user_id, u.full_name, u.email
//          FROM orders o
//          LEFT JOIN users u ON o.user_id = u.id
//          WHERE o.id = ?`,
//         [id]
//       );
//       if (orders.length === 0) {
//         console.log(`Order ${id} not found`);
//         return res.status(404).json({ error: "Order not found" });
//       }

//       const order = orders[0];
//       const user = {
//         full_name: order.full_name || "Customer",
//         email: order.email || "N/A",
//       };

//       // Calculate new total
//       const currentTotal = parseFloat(order.total) || 0;
//       const newShipping = parseFloat(shipping);
//       const newTotal = currentTotal + newShipping;

//       // Update shipping and total
//       await pool.query(
//         "UPDATE orders SET shipping = ?, total = ? WHERE id = ?",
//         [newShipping, newTotal, id]
//       );

//       // Send email to user
//       const mailOptions = {
//         from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
//         to: user.email,
//         subject: `Updated Order #${order.order_id}: Final Amount with Shipping`,
//         html: `
//           <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
//             <h2>Hello, ${user.full_name}!</h2>
//             <p>We’ve updated the shipping charges for your order <strong>#${
//               order.order_id
//             }</strong>. Below is the final amount including the new shipping charges.</p>
//             <h3>Order Summary:</h3>
//             <ul style="list-style: none; padding: 0;">
//               <li><strong>Order ID:</strong> ${order.order_id}</li>
//               <li><strong>Shipping Charges:</strong> $${newShipping.toFixed(
//                 2
//               )}</li>
//               <li><strong>Final Total:</strong> $${newTotal.toFixed(2)}</li>
//             </ul>
//             <p><strong>Next Steps:</strong></p>
//             <ul>
//               <li>You can view your updated order details in your account at <a href="https://studiosignaturecabinets.com/customer/orders">My Orders</a>.</li>
//               <li>If you have any questions, please contact our support team at <a href="mailto:support@studiosignaturecabinets.com">support@studiosignaturecabinets.com</a>.</li>
//             </ul>
//             <p>Thank you for choosing Studio Signature Cabinets!</p>
//             <p>Best regards,<br>Team Studio Signature Cabinets</p>
//           </div>
//         `,
//       };

//       try {
//         await transporter.sendMail(mailOptions);
//         console.log(`Shipping update email sent to ${user.email}`);
//       } catch (emailErr) {
//         console.error("Failed to send shipping update email:", emailErr);
//         // Log error but don't fail the update
//       }

//       console.log(
//         `Shipping and total updated for order ${id}: shipping=${newShipping}, total=${newTotal}`
//       );
//       res.json({
//         message: "Shipping charges and total updated successfully",
//         shipping: newShipping,
//         total: newTotal,
//       });
//     } catch (err) {
//       console.error("Server error updating shipping:", err);
//       res.status(500).json({ error: "Server error" });
//     }
//   }
// );

// POST /api/admin/orders/:id

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
                <li>Contact us at <a href="mailto:support@studiosignaturecabinets.com">support@studiosignaturecabinets.com</a> for questions.</li>
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
                <li>Contact us at <a href="mailto:support@studiosignaturecabinets.com">support@studiosignaturecabinets.com</a> for questions.</li>
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

// PUT /api/admin/orders/:id/shipping (fallback)
// app.put(
//   "/api/admin/orders/:id/shipping",
//   adminauthenticateToken,
//   async (req, res) => {
//     const { id } = req.params;
//     const { shipping, additional_discount } = req.body;

//     console.log(`PUT /api/admin/orders/${id}/shipping called with shipping: ${shipping}, additional_discount: ${additional_discount}`);

//     // Validate inputs if provided
//     if (
//       (shipping !== undefined && (typeof shipping !== "number" || shipping < 0)) ||
//       (additional_discount !== undefined && (typeof additional_discount !== "number" || additional_discount < 0))
//     ) {
//       console.log(`Invalid input: shipping=${shipping}, additional_discount=${additional_discount}`);
//       return res.status(400).json({ error: "Invalid shipping or additional discount" });
//     }

//     try {
//       // Fetch order details
//       const [orders] = await pool.query(
//         `SELECT o.id, o.order_id, o.subtotal, o.tax, o.discount, o.additional_discount AS current_additional_discount,
//                 o.shipping AS current_shipping, o.total, o.user_id, u.full_nameacidade, u.id AS userId, u.full_name, u.email
//          FROM orders o
//          LEFT JOIN users u ON o.user_id = u.id
//          WHERE o.id = ?`,
//         [id]
//       );
//       if (orders.length === 0) {
//         console.log(`Order ${id} not found`);
//         return res.status(404).json({ error: "Order not found" });
//       }

//       const order = orders[0];
//       const user = {
//         full_name: order.full_name || "Customer order",
//         email: order.email || 'N/A'
//       };

//       // Use provided values or keep current
//       const newShippingAmount = shipping !== undefined ? parseFloat(shipping) : parseFloat(order.current_shipping || 0);
//       const newDiscountAmount = additional_discount !== undefined ? parseFloat(additional_discount) : parseFloat(order.current_additional_discount || 0);
//       // Calculate new shipping
//       const subtotalAmount = parseFloat(order.subtotal) || 0;
//       const taxAmount = parseFloat(order.tax) || 0;
//       const discountAmount = parseFloat(order.discount) || 0;
//       let newTotalAmount;
//       if (discountAmount > 0) {
//         newTotalAmount = subtotalAmount - newAdditionalDiscountAmount - discountAmount + taxAmount + newShippingAmount;
//       } else {
//         newTotalAmount = subtotalAmount - newAdditionalDiscountAmount + taxAmount + newShippingAmount;
//       }

//       // Use provided values or keep current
//       const newShipping = shipping !== undefined ? parseFloat(shipping) : parseFloat(order.current_shipping || 0);
//       const newAdditionalDiscount = additional_discount !== undefined ? parseFloat(additional_discount) : parseFloat(order.current_additional_discount || 0);

//       // Calculate new total
//       const subtotal = parseFloat(order.subtotal) || 0;
//       const tax = parseFloat(order.tax) || 0;
//       const discount = parseFloat(order.discount) || 0;
//       let newTotal;
//       if (discount > 0) {
//         newTotal = subtotal - newAdditionalDiscount - discount + tax + newShipping;
//       } else {
//         newTotal = subtotal - newAdditionalDiscount + tax + newShipping;

//       }

//       // Ensure total is non-negative
//       if (newTotalAmount < 0) {
//         console.log('Invalid total calculated: ${newTotalAmount}');
//         return res.status(400).json({ error: 'Total cannot be negative' });
//         return res.status(400).json({ error: "Total cannot be negative" });
//       }

//       // Update database
//       await pool.query(
//         'UPDATE orders SET shipping = ?, additionalDiscountAmount = ?, totalAmount = ? WHERE id = ?', [newShippingAmount, newDiscountAmount, newTotalAmount, id]
//         "UPDATE orders SET shipping = ?, additional_discount = ?, total = ? WHERE id = ?",
//         [newShipping, newAdditionalDiscount, newTotalAmount, id]
//       );

//       // Send email if changes were made
//       if (shipping !== undefined || additionalDiscount !== undefined) {
//       {
//         const emailOptions = {
//           from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
//           to: user.email,
//           subject: `Updated Order #${orderDetails.order_id}: Final Amount`,
//           html: `
//             <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; items: padding: 20px;">
//               <p>Hello, ${userDetails.fullName}!</p>,
//               <p>We’ve updated your order <strong>#${order.order_id}</strong>. Below is the final amount including any shipping charges and additional discounts.</p>
//               <h3>Order Details:</h3>
//               <ul style="list-style: none; padding: 0;">
//                 <li><strong>Order ID:</strong> ${order.order_id}</li>
//                 <li>Subtotal:</li> $${subtotalAmount.toFixed(2)}</li>
//                 <li>Tax:</li> $${taxAmount.toFixed(2)}</li>
//                 <li>Discount:</li> $${discountAmount.toFixed(2)}</li>
//                 <li>Additional Discount:</li> $${newDiscountAmount.toFixed(2)}</li>
//                 <li>Shipping Charges:</li> $${newShippingAmount.toFixed(2)}</li>
//                 <li>Final Total:</li> $${newTotalAmount.toFixed(2)}</li>
//               </ul>
//               <p><strong>Next Steps:</strong> </p>
//               <ul>
//                 <li>You can view your updated order details at <a href="https://studiosignaturecabinets.com/customer/orders">My Orders</a>.</li>
//                 <li>Contact us at <a href="mailto:support@studiosignaturecabinets.com">support@studiosignaturecabinets.com</a> for questions.</li>
//               </ul>
//               <p>Thank you for choosing Studio Signature Cabinets!</p>
//               <p>Best regards,<br>Team Studio Signature Cabinets</p>
//             </div>
//           `
//         };
//       if (shipping !== undefined || additional_discount !== undefined) {
//         const mailOptions = {
//           from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
//           to: order.email,
//           subject: `Updated Order #${order.order_id}: Final Amount`,
//           html: `
//             <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
//               <h2>Hello, ${user.full_name}!</h2>
//               <p>We’ve updated your order <strong>#${order.order_id}</strong>. Below is the final amount including any shipping charges and additional discounts.</p>
//               <h3>Order Summary:</h3>
//               <ul style="list-style: none; padding: 0;">
//                 <li><strong>Order ID:</strong> ${order.order_id}</li>
//                 <li><strong>Subtotal:</strong> $${subtotal.toFixed(2)}</li>
//                 <li><strong>Tax:</strong> $${tax.toFixed(2)}</li>
//                 <li><strong>Discount:</strong> $${discount.toFixed(2)}</li>
//                 <li><strong>Additional Discount:</strong> $${newAdditionalDiscount.toFixed(2)}</li>
//                 <li><strong>Shipping Charges:</strong> $${newShipping.toFixed(2)}</li>
//                 <li><strong>Total:</strong> $${newTotal.toFixed(2)}</li>
//               </ul>
//               <p><strong>Next Steps:</strong></p>
//               <ul>
//                 <li>You can view your updated order details at <a href="https://studiosignaturecabinets.com/customer/orders">My Orders</a>.</li>
//                 <li>Contact us at <a href="mailto:support@studiosignaturecabinets.com">support@studiosignaturecabinets.com</a> for questions.</li>
//               </ul>
//               <p>Thank you for choosing Studio Signature Cabinets!</p>
//               <p>Best regards,<br>Team Studio Signature Cabinets</p>
//             </div>
//           `,
//         };

//         try {
//           await transporter.sendMail(mailOptions);
//           console.log(`Update email sent to ${order.email}`);
//         } catch (error) {
//           console.error('Failed to send email:', error);
//           console.error('Failed to send update email:', emailErr);
//         }
//       }

//       console.log(`Order ${order.id} updated: shipping=${shippingAmount}, additionalDiscount=${discountAmount}, total=${totalAmount}`);
//       res.status(200).json({
//         message: 'Success: Order updated successfully',
//         shipping: shippingAmount,
//         additionalDiscount: discountAmount,
//         total: totalAmount
//       });
//       console.log(`Order ${id} updated: shipping=${newShipping}, additional_discount=${newAdditionalDiscount}, total=${newTotal}`);
//       res.json({
//         message: "Changes updated successfully",
//         shipping: newShipping,
//         additional_discount: newAdditionalDiscount,
//         total: newTotal
//       });
//     } catch (err) {
//       console.error("Server error updating order:", err);
//       res.status(500).json({ error: "Server error" });
//     }
//   }
// );

// app.put(
//   "/api/admin/orders/:id/status",
//   adminauthenticateToken,
//   async (req, res) => {
//     const { id } = req.params;
//     const { status } = req.body;

//     // Validate status
//     if (
//       !["Pending", "Accepted", "Processing", "Completed", "Cancelled"].includes(
//         status
//       )
//     ) {
//       return res.status(400).json({
//         error:
//           "Invalid status. Must be Pending, Accepted, Processing, Completed, or Cancelled",
//       });
//     }

//     try {
//       // Check if order exists and fetch details
//       const [orders] = await pool.query(
//         `SELECT o.id, o.order_id, o.user_id, o.door_style, o.finish_type, o.stain_option, o.paint_option,
//               o.subtotal, o.tax, o.shipping, o.total, u.full_name, u.email
//        FROM orders o
//        LEFT JOIN users u ON o.user_id = u.id
//        WHERE o.id = ?`,
//         [id]
//       );
//       if (orders.length === 0) {
//         return res.status(404).json({ error: "Order not found" });
//       }

//       const order = orders[0];
//       const user = {
//         full_name: order.full_name || "Customer",
//         email: order.email || "N/A",
//       };

//       // Update status
//       await pool.query("UPDATE orders SET status = ? WHERE id = ?", [
//         status,
//         id,
//       ]);

//       // Send email if status is Accepted
//       if (status === "Accepted") {
//         const mailOptions = {
//           from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
//           to: user.email,
//           subject: `Your Order #${order.order_id} Has Been Accepted!`,
//           html: `
//           <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
//             <h2>Hello, ${user.full_name}!</h2>
//             <p>Great news! Your order <strong>#${
//               order.order_id
//             }</strong> has been accepted and is now being processed.</p>
//             <h3>Order Details:</h3>
//             <ul style="list-style: none; padding: 0;">
//               <li><strong>Order ID:</strong> ${order.order_id}</li>
//               <li><strong>Door Style:</strong> ${order.door_style}</li>
//               <li><strong>Finish Type:</strong> ${order.finish_type}</li>
//               ${
//                 order.stain_option
//                   ? `<li><strong>Stain Option:</strong> ${order.stain_option}</li>`
//                   : ""
//               }
//               ${
//                 order.paint_option
//                   ? `<li><strong>Paint Option:</strong> ${order.paint_option}</li>`
//                   : ""
//               }
//               <li><strong>Subtotal:</strong> $${parseFloat(
//                 order.subtotal
//               ).toFixed(2)}</li>
//               <li><strong>Tax:</strong> $${parseFloat(order.tax).toFixed(
//                 2
//               )}</li>
//               <li><strong>Shipping:</strong> ${
//                 order.shipping !== null
//                   ? `$${parseFloat(order.shipping).toFixed(2)}`
//                   : "Free"
//               }</li>
//               <li><strong>Total:</strong> $${parseFloat(order.total).toFixed(
//                 2
//               )}</li>
//             </ul>
//             <p><strong>Next Steps:</strong></p>
//             <ul>
//               <li>Your order is now in the processing stage. We’ll notify you with updates on its progress.</li>
//               <li>You can track your order status in your account at <a href="https://studiosignaturecabinets.com/customer/orders">My Orders</a>.</li>
//             </ul>
//             <p>If you have any questions, please contact our support team at <a href="mailto:support@studiosignaturecabinets.com">support@studiosignaturecabinets.com</a>.</p>
//             <p>Thank you for choosing Studio Signature Cabinets!</p>
//             <p>Best regards,<br>Team Studio Signature Cabinets</p>
//           </div>
//         `,
//         };

//         try {
//           await transporter.sendMail(mailOptions);
//         } catch (emailErr) {
//           console.error("Failed to send order acceptance email:", emailErr);
//           // Log error but don't fail the status update
//         }
//       }

//       res.json({ message: "Order status updated successfully" });
//     } catch (err) {
//       console.error("Server error:", err);
//       res.status(500).json({ error: "Server error" });
//     }
//   }
// );

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
              o.subtotal, o.tax, o.shipping, o.discount, o.additional_discount, o.total, u.full_name, u.email 
       FROM orders o 
       LEFT JOIN users u ON o.user_id = u.id 
       WHERE o.id = ?`,
        [id]
      );
      if (orders.length === 0) {
        return res.status(404).json({ error: "Order not found" });
      }

      const order = orders[0];
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
                      : "Free"
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
                <p>If you have any questions, please contact our support team at <a href="mailto:support@studiosignaturecabinets.com">support@studiosignaturecabinets.com</a>.</p>
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
                      : "Free"
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
                <p>For inquiries, contact us at <a href="mailto:support@studiosignaturecabinets.com">support@studiosignaturecabinets.com</a>.</p>
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
                      : "Free"
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
                <p>If you have any issues, contact us at <a href="mailto:support@studiosignaturecabinets.com">support@studiosignaturecabinets.com</a>.</p>
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
                      : "Free"
                  }</li>
                  <li><strong>Total:</strong> $${parseFloat(
                    order.total
                  ).toFixed(2)}</li>
                </ul>
                <p><strong>Next Steps:</strong></p>
                <ul>
                  <li>If this was unexpected, please contact us immediately at <a href="mailto:support@studiosignaturecabinets.com">support@studiosignaturecabinets.com</a>.</li>
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

// POST /api/addresses - Create a new billing or shipping address
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
        // Insert new shipping address (multiple allowed)
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

app.listen(port, "0.0.0.0", () => {
  console.log(`Server running on http://0.0.0.0:${port}`);
});
