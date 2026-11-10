// server.js -- the CampusEats Secured API (Node + Express)
// CS543 Web Services · Securing the API
// Complete implementation: JWT Authentication, Role-Based Access Control (RBAC),
// Object-Level Access Control (IDOR Prevention), Bcrypt Hashing, and .env configuration.

require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('./db');

const app = express();
app.use(express.json());
app.use(express.static('public'));

// The signing secret lives in environment variables, never hard-coded in production.
const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

// ============================================================================
// 1. AUTHENTICATION & AUTHORIZATION GUARDS (MIDDLEWARES)
// ============================================================================

// Authentication Middleware -- WHO are you?
// Reads "Bearer <token>" from Authorization header, verifies signature & expiry.
function auth(req, res, next) {
  const authHeader = req.get('Authorization') || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : '';

  if (!token) {
    return res.status(401).json({ error: 'invalid or missing token' });
  }

  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: 'invalid or missing token' });
  }
}

// Authorization Middleware -- are you ALLOWED?
// Checks if the authenticated user's role is in the allowed list.
function requireRole(...allowed) {
  return (req, res, next) => {
    if (!req.user || !allowed.includes(req.user.role)) {
      return res.status(403).json({ error: 'forbidden' });
    }
    next();
  };
}

// ============================================================================
// 2. AUTHENTICATION ROUTES
// ============================================================================

// POST /login -- verify password against bcrypt hash, issue signed JWT
app.post('/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(401).json({ error: 'bad login' });
  }

  const user = db.findUserByEmail(email);
  if (!user || !bcrypt.compareSync(password, user.hash)) {
    return res.status(401).json({ error: 'bad login' });
  }

  // Token carries identity (sub = user.id) and role for authorization
  const token = jwt.sign(
    { sub: user.id, email: user.email, name: user.name, role: user.role },
    SECRET,
    { expiresIn: '1h' }
  );

  res.json({
    token,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role
    }
  });
});

// GET /me -- verify current session and return decoded user info
app.get('/me', auth, (req, res) => {
  const user = db.findUserById(req.user.sub);
  if (!user) {
    return res.json({ sub: req.user.sub, role: req.user.role });
  }
  res.json({
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role
  });
});

// ============================================================================
// 3. CATALOGUE / ITEMS ROUTES
// ============================================================================

// GET /items -- any authenticated user (customer, restaurant, admin) may read the menu
app.get('/items', auth, (req, res) => {
  res.json(db.getAllItems());
});

// GET /items/:id -- read a single dish by ID
app.get('/items/:id', auth, (req, res) => {
  const item = db.getItemById(req.params.id);
  if (!item) {
    return res.status(404).json({ error: 'not found' });
  }
  res.json(item);
});

// POST /items -- only restaurant or admin may add a dish
app.post('/items', auth, requireRole('restaurant', 'admin'), (req, res) => {
  const { name, price } = req.body || {};
  if (!name || String(name).trim() === '') {
    return res.status(422).json({ error: 'name required' });
  }

  const newItem = db.addItem({
    name: String(name).trim(),
    price: Number(price) || 0
  });

  res.status(201).json(newItem);
});

// DELETE /items/:id -- only restaurant or admin may delete a dish
app.delete('/items/:id', auth, requireRole('restaurant', 'admin'), (req, res) => {
  const deleted = db.deleteItem(req.params.id);
  if (!deleted) {
    return res.status(404).json({ error: 'not found' });
  }
  res.json({ message: 'item deleted', item: deleted });
});

// ============================================================================
// 4. ORDERS & OBJECT-LEVEL ACCESS CONTROL (IDOR PROTECTION)
// ============================================================================

// POST /orders -- place an order
// Customers (or admins) can create an order; order is stamped with customerId = req.user.sub
app.post('/orders', auth, (req, res) => {
  const { items: orderItems } = req.body || {};
  if (!Array.isArray(orderItems) || orderItems.length === 0) {
    return res.status(422).json({ error: 'items array required with at least one item' });
  }

  const user = db.findUserById(req.user.sub);
  const newOrder = db.createOrder({
    customerId: req.user.sub,
    customerEmail: req.user.email || (user ? user.email : 'unknown'),
    customerName: (user ? user.name : 'Customer'),
    orderItems
  });

  res.status(201).json(newOrder);
});

// GET /orders -- list orders
// Object-level rule:
// - A customer may only see their own orders.
// - Restaurant and Admin roles may see all orders.
app.get('/orders', auth, (req, res) => {
  if (req.user.role === 'customer') {
    const myOrders = db.getOrdersByCustomerId(req.user.sub);
    return res.json(myOrders);
  }
  // restaurant or admin sees all
  res.json(db.getAllOrders());
});

// GET /orders/:id -- view a single order
// Object-level check (IDOR guard):
// - A customer can ONLY view an order if order.customerId === req.user.sub.
// - Attempting to view another user's order yields 403 Forbidden.
app.get('/orders/:id', auth, (req, res) => {
  const order = db.getOrderById(req.params.id);
  if (!order) {
    return res.status(404).json({ error: 'order not found' });
  }

  // Object-level authorization check
  if (req.user.role === 'customer' && order.customerId !== req.user.sub) {
    return res.status(403).json({
      error: 'forbidden: you can only view your own orders'
    });
  }

  res.json(order);
});

// PATCH /orders/:id/status -- update order status (restaurant or admin only)
app.patch('/orders/:id/status', auth, requireRole('restaurant', 'admin'), (req, res) => {
  const { status } = req.body || {};
  if (!status) {
    return res.status(422).json({ error: 'status required' });
  }

  const updated = db.updateOrderStatus(req.params.id, status);
  if (!updated) {
    return res.status(404).json({ error: 'order not found' });
  }

  res.json(updated);
});

// ============================================================================
// 5. ADMIN UTILITY ROUTE
// ============================================================================

// GET /admin/users -- admin only: view all registered users
app.get('/admin/users', auth, requireRole('admin'), (req, res) => {
  res.json(db.getAllUsers());
});

// ============================================================================
// 6. SERVER STARTUP
// ============================================================================

const PORT = process.env.PORT || 3000;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Secured Catalogue on http://localhost:${PORT}`);
  });
}

module.exports = app;
