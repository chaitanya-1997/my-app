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

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: "sssdemo6@gmail.com",
    pass: "qhxc jbqc kami owim",
  },
});

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
    await pool.query(
      `INSERT INTO users (user_type, full_name, email, password, company_name, tax_id, phone, address, is_active)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        userType,
        fullName,
        email,
        hashedPassword,
        businessName || null,
        taxId || null,
        phone || null,
        address || null,
        1,
      ]
    );

    // Send confirmation email to the user
    const userMailOptions = {
      from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
      to: email,
      subject: "Welcome to Our Platform!",
      html: `<p>Hi ${fullName},</p>
             <p>Thank you for signing up as a ${userType}. We're excited to have you on board.</p>
             <p>Regards,<br/>Team SSC</p>`,
    };

    // Send notification email to admin
    const adminMailOptions = {
      from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
      to: "aashish.shroff@zeta-v.com", // replace with your admin email
      subject: "New User Signup Alert",
      html: `<p>A new ${userType} has signed up.</p>
             <p><strong>Name:</strong> ${fullName}<br/>
             <strong>Email:</strong> ${email}<br/>
             <strong>Phone:</strong> ${phone || "N/A"}<br/>
             <strong>Company:</strong> ${businessName || "N/A"}</p>`,
    };

    // Send emails
    await transporter.sendMail(userMailOptions);
    await transporter.sendMail(adminMailOptions);

    // Respond success
    res.status(201).json({
      message: "Account created successfully. Confirmation email sent.",
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

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

app.get("/api/profile", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const [users] = await pool.query(
      "SELECT id, user_type, full_name, company_name, email, phone, address, account_status, last_login, created_at FROM users WHERE id = ?",
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

    // Get user info
    const [userResult] = await pool.query(
      "SELECT full_name, email FROM users WHERE id = ?",
      [userId]
    );
    const userFullName = userResult[0].full_name;
    const userEmail = userResult[0].email;

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
          account, bill_to, subtotal, tax, shipping, total, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending', NOW())`,
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

      // ✉️ Send Emails
      const userMailOptions = {
        from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
        to: userEmail,
        subject: `Order Confirmation - ${orderId}`,
        html: `
          <p>Hi ${userFullName},</p>
          <p>Your order <strong>${orderId}</strong> has been placed successfully.</p>
          <p><strong>Total:</strong> $${total}</p>
          <p>Thank you for shopping with us!</p>
        `,
      };

      const adminMailOptions = {
        from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
        to: "aashish.shroff@zeta-v.com", // replace with your admin email
        subject: `New Order Placed - ${orderId}`,
        html: `
          <p>A new order has been placed by ${userFullName} (${userEmail}).</p>
          <p><strong>Order ID:</strong> ${orderId}</p>
          <p><strong>Total:</strong> $${total}</p>
          <p>Please check the admin panel for full details.</p>
        `,
      };

      await transporter.sendMail(userMailOptions);
      await transporter.sendMail(adminMailOptions);

      res
        .status(201)
        .json({ message: "Order placed successfully", order_id: orderId });
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
app.get("/api/orders", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    const [orders] = await pool.query(
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
          WHERE o.user_id = ?
          GROUP BY o.id
          ORDER BY o.created_at DESC`,
      [userId]
    );

    const formattedOrders = orders.map((order) => ({
      id: order.id,
      date: new Date(order.date).toISOString().split("T")[0],
      productLine: order.door_style.includes("Shaker")
        ? "Kitchen Shaker"
        : "Bath Shaker",
      status: order.status,
      total: `$${parseFloat(order.total || 0).toFixed(2)}`,
      subtotal: parseFloat(order.subtotal || 0).toFixed(2),
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
            const [userResult] = await pool.query(
      "SELECT full_name, email FROM users WHERE id = ?",
      [userId]
    );
    const userEmail = userResult[0].email;
     const userFullName = userResult[0].full_name;
      // AFTER THE ORDER IS SUCCESSFULLY UPDATED
      // Send email to user
      const userEmailOptions = {
        from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
        to: userEmail,
        subject: `Order Updated - ${orderId}`,
        html: `
    <p>Hi ${userFullName},</p>
    <p>Your order <strong>${orderId}</strong> has been updated.</p>
    <p><strong>Total:</strong> $${total}</p>
   
    <p>Thank you for shopping with us!</p>
  `,
      };

      // Admin email
      const adminMailOptions = {
        from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
        to: "aashish.shroff@zeta-v.com",
        subject: `Order Updated - ${orderId}`,
        html: `
    <p>An order has been updated by ${userFullName} (${userEmail}).</p>
    <p><strong>Order ID:</strong> ${orderId}</p>
    <p><strong>Total:</strong> $${total}</p>
    <p><strong>New Status:</strong> ${order.status}</p>
    <p>Please check the admin panel for full details.</p>
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

// Cancel an order
app.put("/api/orders/:id/cancel", authenticateToken, async (req, res) => {
  const orderId = req.params.id;
  const userId = req.user.id;

  try {
    // Fetch the order from database
    const [orders] = await pool.query(
      `SELECT id, order_id, created_at, status
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

    // AFTER UPDATING STATUS TO 'Cancelled'

    // Fetch user info for email
    const [userResult] = await pool.query(
      `SELECT email, full_name FROM users WHERE id = ?`,
      [userId]
    );

    const userEmail = userResult[0]?.email ;
    const userFullName = userResult[0]?.full_name ;

    // User Email
    const userEmailOptions = {
      from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
      to: userEmail,
      subject: `Order Canceled - ${orderId}`,
      html: `
    <p>Hi ${userFullName},</p>
    <p>Your order <strong>${orderId}</strong> has been canceled.</p>
    <p>We're sorry to see this change. If you need help, feel free to reach out.</p>
    <p>Thank you,</p>
    <p>Studio Signature Cabinets</p>
  `,
    };

    // Admin Email
    const adminMailOptions = {
      from: '"Studio Signature Cabinets" <sssdemo6@gmail.com>',
      to: "aashish.shroff@zeta-v.com",
      subject: `Order Canceled - ${orderId}`,
      html: `
    <p>An order has been canceled by ${userFullName} (${userEmail}).</p>
    <p><strong>Order ID:</strong> ${orderId}</p>
    <p><strong>Status:</strong> ${formattedOrder.status}</p>
    <p>Please check the admin panel for full details.</p>
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

app.listen(port, "0.0.0.0", () => {
  console.log(`Server running on http://0.0.0.0:${port}`);
});
