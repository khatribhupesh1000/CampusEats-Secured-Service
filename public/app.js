// app.js -- client logic for CampusEats Secured Service

let currentToken = localStorage.getItem('campuseats_token') || '';
let currentUser = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  if (currentToken) {
    verifySession();
  } else {
    updateAuthUI(null);
    loadItems();
  }
});

// Helper: parse JWT payload without external library
function parseJwt(token) {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(jsonPayload);
  } catch (e) {
    return null;
  }
}

// 1. QUICK LOGIN
function quickLogin(email, password) {
  document.getElementById('loginEmail').value = email;
  document.getElementById('loginPassword').value = password;
  doLogin(email, password);
}

// 2. DO LOGIN (POST /login)
async function doLogin(email, password) {
  const alertEl = document.getElementById('authAlert');
  alertEl.innerHTML = '<div class="alert alert-info">Authenticating with bcrypt check...</div>';

  try {
    const res = await fetch('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });

    const data = await res.json();

    if (res.status === 200 && data.token) {
      currentToken = data.token;
      currentUser = data.user;
      localStorage.setItem('campuseats_token', currentToken);
      alertEl.innerHTML = `<div class="alert alert-success">Logged in successfully as <strong>${currentUser.name}</strong> (${currentUser.role}).</div>`;
      updateAuthUI(currentUser);
      loadItems();
      loadOrders();
    } else {
      alertEl.innerHTML = `<div class="alert alert-danger"><span class="status-code-badge status-401">401</span> ${data.error || 'Authentication failed'}: Invalid email or password.</div>`;
      logout(false);
    }
  } catch (err) {
    alertEl.innerHTML = `<div class="alert alert-danger">Network error: ${err.message}</div>`;
  }
}

document.getElementById('loginForm').addEventListener('submit', (e) => {
  e.preventDefault();
  const email = document.getElementById('loginEmail').value;
  const password = document.getElementById('loginPassword').value;
  doLogin(email, password);
});

// 3. VERIFY SESSION (GET /me)
async function verifySession() {
  try {
    const res = await fetch('/me', {
      headers: { 'Authorization': `Bearer ${currentToken}` }
    });
    if (res.ok) {
      currentUser = await res.json();
      updateAuthUI(currentUser);
      loadItems();
      loadOrders();
    } else {
      logout(false);
    }
  } catch (e) {
    logout(false);
  }
}

// 4. LOGOUT
function logout(clearAlert = true) {
  currentToken = '';
  currentUser = null;
  localStorage.removeItem('campuseats_token');
  updateAuthUI(null);
  if (clearAlert) {
    document.getElementById('authAlert').innerHTML = '<div class="alert alert-info">You have been logged out.</div>';
  }
  loadItems();
  loadOrders();
}

// 5. UPDATE AUTH UI
function updateAuthUI(user) {
  const badge = document.getElementById('roleBadge');
  const tokenContainer = document.getElementById('tokenContainer');
  const rawToken = document.getElementById('rawToken');
  const decodedToken = document.getElementById('decodedToken');

  if (user) {
    badge.className = `role-badge role-${user.role}`;
    badge.textContent = `${user.role.toUpperCase()}: ${user.name || user.email}`;
    tokenContainer.style.display = 'block';
    rawToken.textContent = currentToken;
    const decoded = parseJwt(currentToken);
    decodedToken.innerHTML = `<pre>${JSON.stringify(decoded, null, 2)}</pre>`;
  } else {
    badge.className = 'role-badge role-guest';
    badge.textContent = 'GUEST (NOT LOGGED IN)';
    tokenContainer.style.display = 'none';
    rawToken.textContent = '';
    decodedToken.textContent = '';
  }
}

function toggleTokenView() {
  const decoded = document.getElementById('decodedToken');
  decoded.style.display = decoded.style.display === 'none' ? 'block' : 'none';
}

// 6. READ: GET /items
async function loadItems() {
  const container = document.getElementById('itemsContainer');

  if (!currentToken) {
    container.innerHTML = `
      <div class="alert alert-warning">
        <span class="status-code-badge status-401">401 Unauthorized</span>
        Authentication guard active: <code>Authorization: Bearer &lt;token&gt;</code> is required to view the catalogue. Please log in above!
      </div>`;
    return;
  }

  try {
    const res = await fetch('/items', {
      headers: { 'Authorization': `Bearer ${currentToken}` }
    });

    if (res.status === 401) {
      container.innerHTML = `
        <div class="alert alert-danger">
          <span class="status-code-badge status-401">401</span> Invalid or expired token.
        </div>`;
      return;
    }

    const items = await res.json();
    if (!items || items.length === 0) {
      container.innerHTML = '<div style="color: #64748b;">No dishes found.</div>';
      return;
    }

    container.innerHTML = items.map(item => `
      <div class="dish">
        <div class="dish-info">
          <span class="name">${escapeHtml(item.name)}</span>
          <span class="id-tag">Item #${item.id}</span>
        </div>
        <div class="dish-actions">
          <span class="price">&#8377;${item.price}</span>
          ${
            currentUser && (currentUser.role === 'customer' || currentUser.role === 'admin')
              ? `<button type="button" class="btn-order" onclick="orderSingleItem(${item.id})">Order</button>`
              : ''
          }
          ${
            currentUser && (currentUser.role === 'restaurant' || currentUser.role === 'admin')
              ? `<button type="button" class="btn-danger" style="margin-left: 0.4rem;" onclick="deleteItem(${item.id})">Delete</button>`
              : ''
          }
        </div>
      </div>
    `).join('');
  } catch (err) {
    container.innerHTML = `<div class="alert alert-danger">Error: ${err.message}</div>`;
  }
}

// 7. WRITE: POST /items (ROLE CHECK)
document.getElementById('addDishForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const feedback = document.getElementById('addDishFeedback');
  const name = document.getElementById('dishName').value;
  const price = document.getElementById('dishPrice').value;

  feedback.innerHTML = '<div class="alert alert-info">Sending POST /items request...</div>';

  try {
    const headers = { 'Content-Type': 'application/json' };
    if (currentToken) {
      headers['Authorization'] = `Bearer ${currentToken}`;
    }

    const res = await fetch('/items', {
      method: 'POST',
      headers,
      body: JSON.stringify({ name, price })
    });

    const data = await res.json();

    if (res.status === 201) {
      feedback.innerHTML = `
        <div class="alert alert-success">
          <span class="status-code-badge status-201">201 Created</span>
          Added dish <strong>${escapeHtml(data.name)}</strong> (&#8377;${data.price})!
        </div>`;
      document.getElementById('dishName').value = '';
      document.getElementById('dishPrice').value = '';
      loadItems();
    } else if (res.status === 403) {
      feedback.innerHTML = `
        <div class="alert alert-danger">
          <span class="status-code-badge status-403">403 Forbidden</span>
          <strong>Authorization Rejected:</strong> Your role is <code>${currentUser ? currentUser.role : 'guest'}</code>.
          Only <code>restaurant</code> or <code>admin</code> roles may add dishes to the catalogue!
        </div>`;
    } else if (res.status === 401) {
      feedback.innerHTML = `
        <div class="alert alert-warning">
          <span class="status-code-badge status-401">401 Unauthorized</span>
          ${data.error || 'You must be logged in to perform this action.'}
        </div>`;
    } else if (res.status === 422) {
      feedback.innerHTML = `
        <div class="alert alert-warning">
          <span class="status-code-badge status-422">422 Unprocessable Entity</span>
          ${data.error}
        </div>`;
    } else {
      feedback.innerHTML = `<div class="alert alert-danger">Status ${res.status}: ${JSON.stringify(data)}</div>`;
    }
  } catch (err) {
    feedback.innerHTML = `<div class="alert alert-danger">Request failed: ${err.message}</div>`;
  }
});

// 8. DELETE DISH (DELETE /items/:id)
async function deleteItem(id) {
  if (!confirm(`Delete dish #${id}?`)) return;
  try {
    const res = await fetch(`/items/${id}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${currentToken}` }
    });
    if (res.ok) {
      loadItems();
    } else {
      const err = await res.json();
      alert(`Delete failed (${res.status}): ${err.error || 'forbidden'}`);
    }
  } catch (e) {
    alert(`Error: ${e.message}`);
  }
}

// 9. PLACE ORDER: POST /orders
async function orderSingleItem(itemId) {
  if (!currentToken) {
    alert('Please log in first!');
    return;
  }

  try {
    const res = await fetch('/orders', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${currentToken}`
      },
      body: JSON.stringify({
        items: [{ id: itemId, qty: 1 }]
      })
    });

    const data = await res.json();
    if (res.status === 201) {
      alert(`Order #${data.id} placed successfully! Total: ₹${data.total}`);
      loadOrders();
    } else {
      alert(`Could not place order: ${data.error}`);
    }
  } catch (e) {
    alert(`Error: ${e.message}`);
  }
}

// 10. READ ORDERS: GET /orders (OBJECT-LEVEL CHECK)
async function loadOrders() {
  const container = document.getElementById('ordersContainer');

  if (!currentToken) {
    container.innerHTML = '<div style="font-size: 0.85rem; color: #64748b;">Log in to view orders.</div>';
    return;
  }

  try {
    const res = await fetch('/orders', {
      headers: { 'Authorization': `Bearer ${currentToken}` }
    });

    if (!res.ok) {
      container.innerHTML = `<div class="alert alert-danger">Error fetching orders (${res.status})</div>`;
      return;
    }

    const orders = await res.json();

    if (!orders || orders.length === 0) {
      container.innerHTML = '<div style="font-size: 0.85rem; color: #64748b;">No orders found for this account.</div>';
      return;
    }

    container.innerHTML = orders.map(o => `
      <div class="order-card">
        <div class="order-header">
          <span class="order-title">Order #${o.id} &mdash; ${escapeHtml(o.customerName || 'Customer')} (${escapeHtml(o.customerEmail)})</span>
          <span class="order-status">${escapeHtml(o.status.toUpperCase())}</span>
        </div>
        <div class="order-details">
          <strong>Items:</strong> ${(o.items || []).map(i => `${escapeHtml(i.name)} &times; ${i.qty}`).join(', ')}
        </div>
        <div class="order-footer">
          <span><strong>Total:</strong> &#8377;${o.total} &bull; <small>${new Date(o.createdAt).toLocaleTimeString()}</small></span>
          ${
            currentUser && (currentUser.role === 'restaurant' || currentUser.role === 'admin')
              ? `<select onchange="updateOrderStatus(${o.id}, this.value)" style="max-width: 130px; padding: 0.2rem 0.4rem; font-size: 0.75rem;">
                   <option value="placed" ${o.status === 'placed' ? 'selected' : ''}>Placed</option>
                   <option value="confirmed" ${o.status === 'confirmed' ? 'selected' : ''}>Confirmed</option>
                   <option value="preparing" ${o.status === 'preparing' ? 'selected' : ''}>Preparing</option>
                   <option value="delivered" ${o.status === 'delivered' ? 'selected' : ''}>Delivered</option>
                 </select>`
              : ''
          }
        </div>
      </div>
    `).join('');
  } catch (err) {
    container.innerHTML = `<div class="alert alert-danger">Error: ${err.message}</div>`;
  }
}

// 11. UPDATE ORDER STATUS: PATCH /orders/:id/status
async function updateOrderStatus(orderId, newStatus) {
  try {
    const res = await fetch(`/orders/${orderId}/status`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${currentToken}`
      },
      body: JSON.stringify({ status: newStatus })
    });
    if (res.ok) {
      loadOrders();
    } else {
      const err = await res.json();
      alert(`Status update failed: ${err.error}`);
    }
  } catch (e) {
    alert(`Error: ${e.message}`);
  }
}

// 12. TEST LIVE IDOR PROTECTION: GET /orders/:id
async function testOrderAccess(orderId) {
  const resultEl = document.getElementById('idorResult');
  if (!currentToken) {
    resultEl.innerHTML = '<span style="color: #c0392b;">Please log in first.</span>';
    return;
  }

  resultEl.innerHTML = 'Testing object-level permission...';

  try {
    const res = await fetch(`/orders/${orderId}`, {
      headers: { 'Authorization': `Bearer ${currentToken}` }
    });

    const data = await res.json();

    if (res.status === 200) {
      resultEl.innerHTML = `
        <span class="status-code-badge status-200">200 OK</span>
        Allowed! Viewing Order #${data.id} (${data.customerName}, ₹${data.total})`;
    } else if (res.status === 403) {
      resultEl.innerHTML = `
        <span class="status-code-badge status-403">403 Forbidden</span>
        <strong>BLOCKED!</strong> Object-level guard prevented IDOR! (${data.error})`;
    } else {
      resultEl.innerHTML = `
        <span class="status-code-badge status-${res.status}">${res.status}</span> ${data.error || 'Error'}`;
    }
  } catch (err) {
    resultEl.innerHTML = `<span style="color: #c0392b;">Error: ${err.message}</span>`;
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
