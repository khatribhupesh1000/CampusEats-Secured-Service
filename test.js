// test.js -- Comprehensive Automated Test Suite for CampusEats Secured API
// Tests Authentication, RBAC, IDOR Object-Level Security, Validation, and HTTP Status Codes.

const http = require('http');
const fs = require('fs');
const path = require('path');
const app = require('./server');

const PORT = 3099; // Isolated test port
let server;
let baseUrl = `http://localhost:${PORT}`;

// Test counters & logs
let passed = 0;
let failed = 0;
let transcriptLines = [];

function record(text) {
  transcriptLines.push(text.replace(/\x1b\[[0-9;]*m/g, ''));
}

function assert(condition, testName, details = '') {
  if (condition) {
    const msg = `  ✔ PASS ${testName}`;
    console.log(`  \x1b[32m✔ PASS\x1b[0m ${testName}`);
    record(msg);
    passed++;
  } else {
    const msg = `  ✖ FAIL ${testName} ${details ? '(' + details + ')' : ''}`;
    console.error(`  \x1b[31m✖ FAIL\x1b[0m ${testName} ${details ? '(' + details + ')' : ''}`);
    record(msg);
    failed++;
  }
}

async function request(path, options = {}) {
  const url = `${baseUrl}${path}`;
  const headers = options.headers || {};
  if (options.token) {
    headers['Authorization'] = `Bearer ${options.token}`;
  }
  if (options.body && typeof options.body === 'object') {
    headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(options.body);
  }

  const res = await fetch(url, {
    method: options.method || 'GET',
    headers,
    body: options.body
  });

  let data;
  try {
    data = await res.json();
  } catch (e) {
    data = null;
  }

  return { status: res.status, headers: res.headers, data };
}

async function runTests() {
  const header = `=============================================================
  CampusEats Secured API -- Automated Security Verification  
  CS543 Tutorial 9 & Assignment 9B Transcript
  Timestamp: ${new Date().toISOString()}
=============================================================`;
  console.log('\n' + header + '\n');
  record(header + '\n');

  let ashaToken, rahulToken, restoToken, adminToken;

  // --- PART 1: AUTHENTICATION (401 & LOGIN) ---
  console.log('\x1b[1m[1] Authentication & 401 Unauthorized Checks\x1b[0m');
  record('\n[1] Authentication & 401 Unauthorized Checks');

  const noTokenRes = await request('/items');
  assert(noTokenRes.status === 401, 'GET /items without token -> 401 Unauthorized');
  assert(noTokenRes.data && noTokenRes.data.error === 'invalid or missing token', '401 body returns error: "invalid or missing token"');

  const badTokenRes = await request('/items', { token: 'tampered.garbage.signature' });
  assert(badTokenRes.status === 401, 'GET /items with bad token -> 401 Unauthorized');

  const badLoginRes = await request('/login', {
    method: 'POST',
    body: { email: 'asha@campus.edu', password: 'wrongpassword' }
  });
  assert(badLoginRes.status === 401, 'POST /login with wrong password -> 401 Unauthorized');
  assert(badLoginRes.data && badLoginRes.data.error === 'bad login', 'Bad login body returns error: "bad login"');

  // Successful logins
  console.log('\n\x1b[1m[2] Login & JWT Minting (Bcrypt Check)\x1b[0m');
  record('\n[2] Login & JWT Minting (Bcrypt Check)');

  const ashaLogin = await request('/login', {
    method: 'POST',
    body: { email: 'asha@campus.edu', password: 'customer123' }
  });
  assert(ashaLogin.status === 200, 'POST /login as Asha (customer) -> 200 OK');
  assert(ashaLogin.data && typeof ashaLogin.data.token === 'string', 'Asha receives signed JWT string');
  ashaToken = ashaLogin.data?.token;

  const rahulLogin = await request('/login', {
    method: 'POST',
    body: { email: 'rahul@campus.edu', password: 'rahul123' }
  });
  assert(rahulLogin.status === 200, 'POST /login as Rahul (customer 2) -> 200 OK');
  rahulToken = rahulLogin.data?.token;

  const restoLogin = await request('/login', {
    method: 'POST',
    body: { email: 'mealhub@campus.edu', password: 'resto123' }
  });
  assert(restoLogin.status === 200, 'POST /login as MealHub (restaurant) -> 200 OK');
  restoToken = restoLogin.data?.token;

  const adminLogin = await request('/login', {
    method: 'POST',
    body: { email: 'admin@campus.edu', password: 'admin123' }
  });
  assert(adminLogin.status === 200, 'POST /login as Admin -> 200 OK');
  adminToken = adminLogin.data?.token;

  // --- PART 2: CATALOGUE ACCESS & RBAC (403 FORBIDDEN) ---
  console.log('\n\x1b[1m[3] Catalogue & Role-Based Access Control (RBAC)\x1b[0m');
  record('\n[3] Catalogue & Role-Based Access Control (RBAC)');

  const getItemsAsha = await request('/items', { token: ashaToken });
  assert(getItemsAsha.status === 200, 'GET /items with Asha token -> 200 OK');
  assert(Array.isArray(getItemsAsha.data) && getItemsAsha.data.length >= 2, 'GET /items returns dish catalogue');

  // Customer tries to add dish -> 403 Forbidden
  const custAddDish = await request('/items', {
    method: 'POST',
    token: ashaToken,
    body: { name: 'Hack Burger', price: 99 }
  });
  assert(custAddDish.status === 403, 'POST /items by customer Asha -> 403 Forbidden');
  assert(custAddDish.data && custAddDish.data.error === 'forbidden', '403 body returns error: "forbidden"');

  // Restaurant adds dish -> 201 Created
  const restoAddDish = await request('/items', {
    method: 'POST',
    token: restoToken,
    body: { name: 'Masala Dosa', price: 60 }
  });
  assert(restoAddDish.status === 201, 'POST /items by restaurant MealHub -> 201 Created');
  assert(restoAddDish.data && restoAddDish.data.name === 'Masala Dosa', '201 response includes created dish');

  // Admin adds dish -> 201 Created
  const adminAddDish = await request('/items', {
    method: 'POST',
    token: adminToken,
    body: { name: 'Special Biryani', price: 150 }
  });
  assert(adminAddDish.status === 201, 'POST /items by admin -> 201 Created');

  // Validation: Missing name -> 422 Unprocessable Entity
  const invalidDish = await request('/items', {
    method: 'POST',
    token: restoToken,
    body: { price: 50 }
  });
  assert(invalidDish.status === 422, 'POST /items with missing name -> 422 Unprocessable Entity');

  // --- PART 3: OBJECT-LEVEL ACCESS CONTROL & IDOR PREVENTION ---
  console.log('\n\x1b[1m[4] Object-Level Access Control & IDOR Prevention\x1b[0m');
  record('\n[4] Object-Level Access Control & IDOR Prevention');

  // Asha reads own order #101 -> 200 OK
  const ashaOrder101 = await request('/orders/101', { token: ashaToken });
  assert(ashaOrder101.status === 200, 'GET /orders/101 by owner (Asha) -> 200 OK');
  assert(ashaOrder101.data && ashaOrder101.data.customerId === 1, 'Order #101 customerId is 1 (Asha)');

  // Rahul attempts to read Asha's order #101 -> 403 Forbidden! (IDOR prevention)
  const rahulOrder101 = await request('/orders/101', { token: rahulToken });
  assert(rahulOrder101.status === 403, 'GET /orders/101 by different customer (Rahul) -> 403 Forbidden (IDOR PREVENTED)');
  assert(rahulOrder101.data && rahulOrder101.data.error.includes('only view your own orders'), 'Error message explains object ownership check');

  // Admin reads Asha's order #101 -> 200 OK
  const adminOrder101 = await request('/orders/101', { token: adminToken });
  assert(adminOrder101.status === 200, 'GET /orders/101 by Admin -> 200 OK');

  // Restaurant reads Asha's order #101 -> 200 OK
  const restoOrder101 = await request('/orders/101', { token: restoToken });
  assert(restoOrder101.status === 200, 'GET /orders/101 by Restaurant -> 200 OK');

  // Place a new order as Asha
  const newOrder = await request('/orders', {
    method: 'POST',
    token: ashaToken,
    body: { items: [{ id: 1, qty: 2 }] }
  });
  assert(newOrder.status === 201, 'POST /orders as Asha -> 201 Created');
  assert(newOrder.data && newOrder.data.customerId === 1, 'New order is securely stamped with customerId = 1');

  // Asha views orders list -> only gets Asha's orders
  const ashaOrdersList = await request('/orders', { token: ashaToken });
  assert(ashaOrdersList.status === 200, 'GET /orders as Asha -> 200 OK');
  const allBelongToAsha = ashaOrdersList.data.every(o => o.customerId === 1);
  assert(allBelongToAsha, 'GET /orders filters strictly to logged-in customer\'s own orders');

  // Restaurant updates order status -> 200 OK
  const updateStatus = await request('/orders/101/status', {
    method: 'PATCH',
    token: restoToken,
    body: { status: 'delivered' }
  });
  assert(updateStatus.status === 200, 'PATCH /orders/101/status by restaurant -> 200 OK');

  // Customer tries to update order status -> 403 Forbidden
  const custUpdateStatus = await request('/orders/101/status', {
    method: 'PATCH',
    token: ashaToken,
    body: { status: 'delivered' }
  });
  assert(custUpdateStatus.status === 403, 'PATCH /orders/101/status by customer -> 403 Forbidden');

  const summary = `=============================================================
  Tests Complete: ${passed} Passed, ${failed} Failed (${Math.round((passed / (passed + failed)) * 100)}%)
=============================================================`;
  console.log('\n' + summary + '\n');
  record('\n' + summary);

  const transcriptPath = path.join(__dirname, 'transcript.txt');
  fs.writeFileSync(transcriptPath, transcriptLines.join('\n') + '\n');
  console.log(`Transcript saved to: ${transcriptPath}`);

  server.close(() => {
    process.exit(failed === 0 ? 0 : 1);
  });
}

server = app.listen(PORT, async () => {
  try {
    await runTests();
  } catch (err) {
    console.error('Test execution error:', err);
    server.close(() => process.exit(1));
  }
});
