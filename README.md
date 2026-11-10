# CampusEats · Secured Catalogue & Orders API (CS543 Tutorial 9 & Assignment 9B)

The CampusEats service, secured with **defense-in-depth API security**:
1. **Authentication (JWT)**: Login issues a signed, time-limited JSON Web Token (`header.payload.signature`).
2. **Password Hashing (bcrypt)**: Passwords are salt-hashed with `bcryptjs` (cost factor 10) at startup; plain text passwords are never stored.
3. **Role-Based Authorization (RBAC)**: Fine-grained access control for `customer`, `restaurant`, and `admin`.
4. **Superuser Admin Role**: Admin role has universal permission to perform all operations.
5. **Object-Level Authorization (IDOR Defense)**: Ensures a customer can only read or manage their own orders, preventing Insecure Direct Object References (BOLA/IDOR).
6. **Environment Isolation (.env)**: Signing keys and server port are loaded via `dotenv` and git-ignored.
7. **Interactive Web Dashboard**: Live web frontend (`public/index.html`) demonstrating live logins, JWT inspection, RBAC, and IDOR testing.

---

## 👥 Seed Users

Passwords are **bcrypt-hashed** at startup — plain text is never stored in memory or databases.

| User | Email | Password | Role | Capabilities |
| :--- | :--- | :--- | :--- | :--- |
| **Asha Patel** | `asha@campus.edu` | `customer123` | `customer` | Browse menu, place orders, view own orders |
| **Rahul Sharma** | `rahul@campus.edu` | `rahul123` | `customer` | Browse menu, place orders, view own orders |
| **MealHub** | `mealhub@campus.edu` | `resto123` | `restaurant` | Browse menu, add dishes, view all orders, update status |
| **Campus Admin** | `admin@campus.edu` | `admin123` | `admin` | Superuser: do everything (manage menu, view all orders, users) |

---

## 🛡️ Security Architecture & Guards

### 1. `auth(req, res, next)` — Authentication ("Who are you?")
- Reads `Authorization: Bearer <token>` from the HTTP request headers.
- Cryptographically verifies the signature against `JWT_SECRET` and validates token expiry.
- If missing, invalid, or expired $\rightarrow$ **`401 Unauthorized`** (`{ "error": "invalid or missing token" }`).
- If valid, unpacks `req.user = decoded` and calls `next()`.

### 2. `requireRole(...allowed)` — Role-Based Authorization ("Are you allowed?")
- Checks if the user's role in the verified token is permitted.
- `admin` role is granted universal access.
- If user does not have permission $\rightarrow$ **`403 Forbidden`** (`{ "error": "forbidden" }`).

### 3. Object-Level Access Check — IDOR / BOLA Prevention
- When accessing order resources (`GET /orders/:id`):
  * If `req.user.role === 'customer'` and `order.customerId !== req.user.sub` $\rightarrow$ **`403 Forbidden`** (`{ "error": "forbidden: you can only view your own orders" }`).
  * Prevents user A from viewing or modifying user B's orders simply by tampering with the URL parameter.

### 401 vs 403 — The Critical Distinction
- **`401 Unauthorized`**: *"I don't know who you are"* (missing, invalid, or expired token, or wrong login credentials).
- **`403 Forbidden`**: *"I know who you are, but you are not allowed to access this resource"* (role mismatch or object ownership violation).

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
npm install
```

### 2. Configure Environment
```bash
cp .env.example .env
# Edit .env and set your custom JWT_SECRET (or keep default dev secret)
```

### 3. Run the Server
```bash
npm start
# -> Secured Catalogue on http://localhost:3000
```

Open your browser at `http://localhost:3000` to interact with the full web dashboard!

### 4. Run Automated Test Suite
```bash
npm test
# Runs 30 automated security tests and records results in transcript.txt
```

---

## 🛣️ API Endpoints Summary

| Method | Path | Guard | Success | Failure Status | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `POST` | `/login` | Public | `200` + token | `401` | Authenticates with bcrypt, returns JWT |
| `GET` | `/me` | `auth` | `200` + profile | `401` | Returns authenticated user info |
| `GET` | `/items` | `auth` | `200` | `401` | Any logged-in user can view menu |
| `GET` | `/items/:id` | `auth` | `200` | `401`, `404` | Retrieve specific dish |
| `POST` | `/items` | `auth` + `requireRole('restaurant', 'admin')` | `201` | `401`, `403`, `422` | Add a dish (restaurant/admin only) |
| `DELETE`| `/items/:id` | `auth` + `requireRole('restaurant', 'admin')` | `200` | `401`, `403`, `404` | Delete a dish |
| `POST` | `/orders` | `auth` | `201` | `401`, `422` | Customer places an order |
| `GET` | `/orders` | `auth` | `200` | `401` | Customers see own orders; Resto/Admin see all |
| `GET` | `/orders/:id`| `auth` + Object-level check | `200` | `401`, `403`, `404` | Customer can only view own order |
| `PATCH`| `/orders/:id/status` | `auth` + `requireRole('restaurant', 'admin')` | `200` | `401`, `403`, `404`, `422` | Update order status |

---

## 🧪 Testing with cURL

### 1. Unauthenticated Request $\rightarrow$ 401 Unauthorized
```bash
curl -i http://localhost:3000/items
# HTTP/1.1 401 Unauthorized
# {"error":"invalid or missing token"}
```

### 2. Login as Customer (Asha) $\rightarrow$ JWT Token
```bash
ASHA_TOKEN=$(curl -s http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"email":"asha@campus.edu","password":"customer123"}' | sed 's/.*"token":"//;s/".*//')
echo $ASHA_TOKEN
```

### 3. Read Catalogue with Token $\rightarrow$ 200 OK
```bash
curl -i http://localhost:3000/items -H "Authorization: Bearer $ASHA_TOKEN"
# HTTP/1.1 200 OK
```

### 4. Customer tries to add a dish $\rightarrow$ 403 Forbidden
```bash
curl -i -X POST http://localhost:3000/items \
  -H "Authorization: Bearer $ASHA_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Hacker Burger","price":99}'
# HTTP/1.1 403 Forbidden
# {"error":"forbidden"}
```

### 5. Login as Restaurant (MealHub) $\rightarrow$ Add Dish $\rightarrow$ 201 Created
```bash
RESTO_TOKEN=$(curl -s http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"email":"mealhub@campus.edu","password":"resto123"}' | sed 's/.*"token":"//;s/".*//')

curl -i -X POST http://localhost:3000/items \
  -H "Authorization: Bearer $RESTO_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Masala Dosa","price":60}'
# HTTP/1.1 201 Created
```

### 6. Object-Level Authorization / IDOR Test
```bash
# Login as Rahul (Customer 2)
RAHUL_TOKEN=$(curl -s http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"email":"rahul@campus.edu","password":"rahul123"}' | sed 's/.*"token":"//;s/".*//')

# Asha reads her own order #101 -> 200 OK
curl -i http://localhost:3000/orders/101 -H "Authorization: Bearer $ASHA_TOKEN"
# HTTP/1.1 200 OK

# Rahul tries to read Asha's order #101 -> 403 Forbidden!
curl -i http://localhost:3000/orders/101 -H "Authorization: Bearer $RAHUL_TOKEN"
# HTTP/1.1 403 Forbidden
# {"error":"forbidden: you can only view your own orders"}
```

---

## 📋 Security Checklist

- [x] **Passwords Hashed**: Salted one-way hashes via `bcryptjs` (cost factor 10), never plaintext.
- [x] **Secrets Isolated**: Secret keys stored in `.env`, never hardcoded into repositories.
- [x] **Signed JWTs with Expiry**: Sealed with HMAC-SHA256 and configured with 1-hour expiration.
- [x] **Authentication Before Authorization**: Every protected route checks identity (401) before evaluating roles (403).
- [x] **Object-Level Access Control**: IDOR prevention checks resource ownership on specific objects.
- [x] **Clean Status Codes**: 200, 201, 401, 403, 404, 422 mapped properly without leaking internal stack traces.

---

## 👨‍💻 Student Details
- **Student Name**: Bhupesh Kumar
- **Enrollment Number**: 20251651032
- **Course**: CS543 · Web Services
- **Institution**: Indian Institute of Information Technology Vadodara (IIITV)
- **Instructor**: Dr. Pramit Mazumdar
