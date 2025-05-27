const express = require('express');
const { pool } = require('./dbConfig');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const XLSX = require('xlsx');
const mysql = require('mysql2/promise');
require('dotenv').config();

const app = express();
const port = 3005;
const SALT_ROUNDS = 10;
const JWT_SECRET = process.env.JWT_SECRET;
app.use(cors({ origin: '*' }));
app.use(express.json());

// Import Excel data into items table (no authentication)
app.post('/api/import-items', async (req, res) => {
  let connection;
  try {
    // Database connection
    connection = await mysql.createConnection({
      host: 'md-in-10.webhostbox.net',
      user: 'insideth_chaitanya',
      password: process.env.DB_PASSWORD,
      database: 'insideth_ssc_customer'
    });

    // Read Excel file (Items 2.xlsx, single sheet)
    const filePath = 'Items 2.xlsx';
    const workbook = XLSX.readFile(filePath);
    const sheet = workbook.Sheets[workbook.SheetNames[0]];
    const data = XLSX.utils.sheet_to_json(sheet);

    // Log headers for debugging
    if (data.length > 0) {
      console.log('Excel headers:', Object.keys(data[0]));
    } else {
      throw new Error('Excel file is empty or has no data rows');
    }

    let skippedRows = [];

    await connection.beginTransaction();

    for (const [index, item] of data.entries()) {
      // Normalize column names (case-insensitive, trim spaces)
      const itemKeys = Object.keys(item).reduce((acc, key) => {
        acc[key.toLowerCase().trim()] = item[key];
        return acc;
      }, {});

      // Map Excel columns to table fields
      const sku = itemKeys['no.'] ? String(itemKeys['no.']).trim() : null;
      const description = itemKeys['description'] ? String(itemKeys['description']).trim() : null;
      const item_type = itemKeys['description 2'] ? String(itemKeys['description 2']).trim() : 'STAINED PLYWOOD';
      const search_description = itemKeys['search description'] ? String(itemKeys['search description']).trim() : null;
      const unit_of_measure = itemKeys['base unit of measure'] ? String(itemKeys['base unit of measure']).trim() : 'NOS';
      const price = itemKeys['unit price'] !== undefined ? parseFloat(itemKeys['unit price']) : null;

      // Debug log for each row
      console.log(`Row ${index + 2}: SKU = ${sku}, Description = ${description}`);

      // Validate required fields
      if (!sku || !description) {
        skippedRows.push({
          row: index + 2,
          item,
          reason: `Missing No. (SKU) or Description (SKU: ${sku}, Description: ${description})`
        });
        continue;
      }

      // Insert into items table
      await connection.query(
        `INSERT INTO items (
          sku, description, item_type, search_description, unit_of_measure, price,
          weight, cube, cw, gr, se, sw
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          sku,
          description,
          item_type,
          search_description,
          unit_of_measure,
          price,
          null, // weight
          null, // cube
          null, // cw
          null, // gr
          null, // se
          null  // sw
        ]
      );
    }

    await connection.commit();
    res.json({
      message: 'Data imported successfully',
      skippedRows
    });
  } catch (err) {
    console.error('Error importing data:', err);
    if (connection) {
      await connection.rollback();
    }
    res.status(500).json({ error: 'Failed to import data', details: err.message });
  } finally {
    if (connection) {
      await connection.end();
    }
  }
});

// ... (Existing endpoints: signup, login, profile, orders, /api/items, etc.)

app.listen(port, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${port}`);
});