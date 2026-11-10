# CS543 · Web Services — Tutorial 9 & Assignment 9B Lab Report
**Topic**: Securing the API — Authentication, Role-Based Access Control (RBAC), and Object-Level Authorization (IDOR Defense)  
**Student Name**: Bhupesh Kumar  
**Roll / Enrollment No**: 20251651032  
**Instructor**: Dr. Pramit Mazumdar  
**Institution**: Indian Institute of Information Technology Vadodara (IIITV)  

---

## 1. Executive Summary & Objective

In this assignment and lab, we take the RESTful **CampusEats Catalogue & Ordering Service** and implement robust, defense-in-depth API security. We address authentication ("who are you?"), authorization ("are you allowed?"), superuser delegation (admin privileges), object-level authorization (preventing Insecure Direct Object References — IDOR/BOLA), password security (one-way bcrypt hashing), and environment isolation (`.env` files).

---

## 2. Core Security Architecture & Mechanisms

### 2.1 Password Hashing vs. Plaintext (One-Way Cryptographic Hashing)
- **Problem**: Storing plaintext passwords exposes user credentials to catastrophic leakage during database dumps or unauthorized inspection.
- **Solution**: Passwords are never stored in plaintext. At startup/registration, passwords are processed through `bcryptjs` using a salt work factor of 10 (`bcrypt.hashSync(password, 10)`).
- **Verification**: During login, `bcrypt.compareSync(guess, hash)` hashes the incoming candidate password with the embedded salt and compares the hashes in constant time. This prevents timing attacks and guarantees that an attacker with database access cannot reverse the hash back into the plaintext password.

### 2.2 JSON Web Tokens (JWT) Architecture
Upon successful authentication, the server generates a cryptographically signed JWT using HMAC-SHA256:
$$\text{JWT} = \text{Base64Url}(\text{Header}) \mathbin{\Vert} \text{.} \mathbin{\Vert} \text{Base64Url}(\text{Payload}) \mathbin{\Vert} \text{.} \mathbin{\Vert} \text{Signature}$$
Where:
- **Header**: Algorithm (`HS256`) and Token Type (`JWT`).
- **Payload**: Claims including subject (`sub: user.id`), `email`, `role`, and expiration (`exp = now + 1 hour`).
- **Signature**: Generated via $\text{HMAC-SHA256}(\text{Header} \mathbin{\Vert} \text{.} \mathbin{\Vert} \text{Payload}, \text{SECRET})$.

#### Why Tokens Cannot Be Forged
Because the server holds the `SECRET` in an isolated environment variable (`process.env.JWT_SECRET`), an attacker who tampers with the payload (e.g., modifying `role: "customer"` to `role: "admin"`) will produce an invalid signature. When `jwt.verify(token, SECRET)` executes, the recomputed signature fails to match, throwing an error and resulting in an immediate **`401 Unauthorized`**.

### 2.3 The Two Guards: Authentication vs. Authorization

```text
Incoming Request  ──>  [auth middleware]  ──>  [requireRole middleware]  ──>  [Object-Level Check]  ──>  Handler (200/201)
                            │                               │                            │
                            ├── (Invalid/No Token: 401)     ├── (Role Mismatch: 403)     └── (Not Order Owner: 403)
```

1. **`auth` Guard (Authentication — "Who are you?")**:
   - Parses the HTTP `Authorization` header formatted as `Bearer <token>`.
   - Validates the token's cryptographic integrity and expiration timestamp.
   - Rejects unauthenticated callers with **`401 Unauthorized`**.
2. **`requireRole(...allowed)` Guard (Authorization — "Are you allowed?")**:
   - Evaluates the claims in `req.user.role`.
   - Ensures only designated roles (e.g., `restaurant` or `admin`) can modify the menu catalogue (`POST /items`, `DELETE /items/:id`).
   - Rejects unauthorized users with **`403 Forbidden`**.
3. **Superuser Admin Privileges**:
   - The `admin` role is given universal access across all endpoints (`if (req.user.role === 'admin' || allowed.includes(req.user.role)) return next();`).

### 2.4 Object-Level Access Control (IDOR / BOLA Prevention)
- **The Vulnerability**: Even with valid authentication and role checks, an application can suffer from Broken Object Level Authorization (IDOR) if a customer can request `/orders/102` simply by changing the ID in the URL.
- **The Defense**: For `GET /orders/:id`, after fetching the record, the server compares the resource owner (`order.customerId`) against the authenticated user ID (`req.user.sub`):
  ```javascript
  if (req.user.role === 'customer' && order.customerId !== req.user.sub) {
    return res.status(403).json({ error: 'forbidden: you can only view your own orders' });
  }
  ```
  Additionally, `GET /orders` automatically filters the list so customers only receive their own historical orders.

---

## 3. HTTP Status Codes: The Standard Matrix

| Status Code | Standard Name | CampusEats Trigger Condition |
| :--- | :--- | :--- |
| **`200 OK`** | Success | Request succeeded (e.g. read items, read allowed order, successful status update). |
| **`201 Created`** | Created | New dish added to catalogue by restaurant/admin, or new order created by customer. |
| **`401 Unauthorized`** | Unauthorized | Missing token, malformed/tampered JWT, expired token, or invalid login credentials. |
| **`403 Forbidden`** | Forbidden | Customer trying to add a dish (RBAC), or Customer trying to inspect another customer's order (IDOR). |
| **`404 Not Found`** | Not Found | Requested dish ID (`/items/:id`) or order ID (`/orders/:id`) does not exist. |
| **`422 Unprocessable`**| Validation | Missing required attributes (e.g. dish `name` missing on `POST /items`). |

---

## 4. Verification Evidence & Automated Test Results

The automated test suite (`npm test` / `node test.js`) executes 30 comprehensive assertions across four core test suites:

```text
=============================================================
  CampusEats Secured API -- Automated Security Verification  
  CS543 Tutorial 9 & Assignment 9B Transcript
=============================================================

[1] Authentication & 401 Unauthorized Checks
  ✔ PASS GET /items without token -> 401 Unauthorized
  ✔ PASS 401 body returns error: "invalid or missing token"
  ✔ PASS GET /items with bad token -> 401 Unauthorized
  ✔ PASS POST /login with wrong password -> 401 Unauthorized
  ✔ PASS Bad login body returns error: "bad login"

[2] Login & JWT Minting (Bcrypt Check)
  ✔ PASS POST /login as Asha (customer) -> 200 OK
  ✔ PASS Asha receives signed JWT string
  ✔ PASS POST /login as Rahul (customer 2) -> 200 OK
  ✔ PASS POST /login as MealHub (restaurant) -> 200 OK
  ✔ PASS POST /login as Admin -> 200 OK

[3] Catalogue & Role-Based Access Control (RBAC)
  ✔ PASS GET /items with Asha token -> 200 OK
  ✔ PASS GET /items returns dish catalogue
  ✔ PASS POST /items by customer Asha -> 403 Forbidden
  ✔ PASS 403 body returns error: "forbidden"
  ✔ PASS POST /items by restaurant MealHub -> 201 Created
  ✔ PASS 201 response includes created dish
  ✔ PASS POST /items by admin -> 201 Created
  ✔ PASS POST /items with missing name -> 422 Unprocessable Entity

[4] Object-Level Access Control & IDOR Prevention
  ✔ PASS GET /orders/101 by owner (Asha) -> 200 OK
  ✔ PASS Order #101 customerId is 1 (Asha)
  ✔ PASS GET /orders/101 by different customer (Rahul) -> 403 Forbidden (IDOR PREVENTED)
  ✔ PASS Error message explains object ownership check
  ✔ PASS GET /orders/101 by Admin -> 200 OK
  ✔ PASS GET /orders/101 by Restaurant -> 200 OK
  ✔ PASS POST /orders as Asha -> 201 Created
  ✔ PASS New order is securely stamped with customerId = 1
  ✔ PASS GET /orders as Asha -> 200 OK
  ✔ PASS GET /orders filters strictly to logged-in customer's own orders
  ✔ PASS PATCH /orders/101/status by restaurant -> 200 OK
  ✔ PASS PATCH /orders/101/status by customer -> 403 Forbidden

=============================================================
  Tests Complete: 30 Passed, 0 Failed (100% Success)
=============================================================
```

---

## 5. Security Checklist Review

- [x] **Passwords Hashed**: Seeded with `bcrypt.hashSync(password, 10)`, never saved as plaintext.
- [x] **Secret Isolation**: Kept in `.env` and loaded using `dotenv`. Never checked into version control.
- [x] **Token Lifespan**: Signed with 1-hour expiration (`expiresIn: '1h'`).
- [x] **Authenticate Before Authorize**: Status 401 is always evaluated prior to status 403.
- [x] **Defense-in-Depth**: Role-based access control layered with fine-grained object-level checks.
- [x] **Input Validation**: Clean 422 responses for malformed bodies without exposing system internals or stack traces.
