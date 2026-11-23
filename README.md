# Express Role-Based Access Portal

A clean Express.js application featuring signup and login with `bcryptjs` and JWT, role-based access control (`user` and `admin`), user profile updates, and admin user management.

## Features

- User signup and login with hashed passwords and JWT authentication
- Role-based access control (`user` and `admin` portals)
- Profile viewing and updating (`GET` & `PATCH /api/user/profile`)
- Admin user management, role switching, and deletion (`GET`, `PATCH`, `DELETE /api/admin/users/:id`)

## Run Locally

```bash
npm install
node server.js