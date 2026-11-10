// db.js -- in-memory data store for CampusEats Secured API
// Stores users with bcrypt-hashed passwords, menu catalogue items, and orders.
const bcrypt = require('bcryptjs');

// Seed users -- passwords hashed once at startup, never stored in plain text
const users = [
  {
    id: 1,
    name: 'Asha Patel',
    email: 'asha@campus.edu',
    role: 'customer',
    hash: bcrypt.hashSync('customer123', 10)
  },
  {
    id: 2,
    name: 'Rahul Sharma',
    email: 'rahul@campus.edu',
    role: 'customer',
    hash: bcrypt.hashSync('rahul123', 10)
  },
  {
    id: 3,
    name: 'MealHub Canteen',
    email: 'mealhub@campus.edu',
    role: 'restaurant',
    hash: bcrypt.hashSync('resto123', 10)
  },
  {
    id: 4,
    name: 'Campus Admin',
    email: 'admin@campus.edu',
    role: 'admin',
    hash: bcrypt.hashSync('admin123', 10)
  }
];

let items = [
  { id: 1, name: 'Veg Thali', price: 90 },
  { id: 2, name: 'Paneer Roll', price: 70 },
  { id: 3, name: 'Masala Dosa', price: 60 },
  { id: 4, name: 'Cold Coffee', price: 40 }
];
let nextItemId = 5;

let orders = [
  {
    id: 101,
    customerId: 1,
    customerEmail: 'asha@campus.edu',
    customerName: 'Asha Patel',
    items: [{ id: 1, name: 'Veg Thali', price: 90, qty: 1 }],
    total: 90,
    status: 'confirmed',
    createdAt: new Date(Date.now() - 3600000).toISOString()
  },
  {
    id: 102,
    customerId: 2,
    customerEmail: 'rahul@campus.edu',
    customerName: 'Rahul Sharma',
    items: [{ id: 2, name: 'Paneer Roll', price: 70, qty: 2 }],
    total: 140,
    status: 'preparing',
    createdAt: new Date(Date.now() - 1800000).toISOString()
  }
];
let nextOrderId = 103;

module.exports = {
  // User operations
  findUserByEmail: (email) => users.find(u => u.email.toLowerCase() === (email || '').toLowerCase().trim()),
  findUserById: (id) => users.find(u => u.id === Number(id)),
  getAllUsers: () => users.map(({ hash, ...safeUser }) => safeUser),

  // Items / Catalogue operations
  getAllItems: () => items,
  getItemById: (id) => items.find(i => i.id === Number(id)),
  addItem: ({ name, price }) => {
    const item = { id: nextItemId++, name, price: Number(price) || 0 };
    items.push(item);
    return item;
  },
  deleteItem: (id) => {
    const index = items.findIndex(i => i.id === Number(id));
    if (index === -1) return false;
    return items.splice(index, 1)[0];
  },

  // Orders operations
  getAllOrders: () => orders,
  getOrdersByCustomerId: (customerId) => orders.filter(o => o.customerId === Number(customerId)),
  getOrderById: (id) => orders.find(o => o.id === Number(id)),
  createOrder: ({ customerId, customerEmail, customerName, orderItems }) => {
    // calculate total from database prices
    let total = 0;
    const enrichedItems = orderItems.map(itemReq => {
      const dbItem = items.find(i => i.id === Number(itemReq.id));
      const unitPrice = dbItem ? dbItem.price : (Number(itemReq.price) || 0);
      const name = dbItem ? dbItem.name : (itemReq.name || 'Custom Item');
      const qty = Math.max(1, Number(itemReq.qty) || 1);
      total += unitPrice * qty;
      return { id: itemReq.id, name, price: unitPrice, qty };
    });

    const newOrder = {
      id: nextOrderId++,
      customerId: Number(customerId),
      customerEmail,
      customerName,
      items: enrichedItems,
      total,
      status: 'placed',
      createdAt: new Date().toISOString()
    };
    orders.push(newOrder);
    return newOrder;
  },
  updateOrderStatus: (id, status) => {
    const order = orders.find(o => o.id === Number(id));
    if (!order) return null;
    order.status = status;
    return order;
  }
};
