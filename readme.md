# Auth System (Production Ready)

A complete backend authentication system built using Node.js, Express, Prisma, and PostgreSQL.  
This project implements JWT-based authentication with refresh token rotation, secure password reset via email, and industry-level security practices.

---

## Features

- JWT Authentication (Access + Refresh Tokens)
- Refresh Token Rotation (Secure session management)
- HTTP-only Cookies for refresh tokens
- Password Hashing using bcrypt
- Forgot Password via Email (NodeMailer)
- Password Reset with token expiry
- Rate Limiting (Brute-force protection)
- Auth Middleware (Protected routes)
- Logout (Token invalidation)
- Token cleanup (on password reset)

---

## Authentication Flow

```text
Register/Login
→ Access Token (15 min)
→ Refresh Token (7 days, stored in DB + cookie)

Access Token Expired
→ Refresh Token used
→ New Access + Refresh Token (rotation)

Logout / Password Reset
→ Refresh tokens deleted