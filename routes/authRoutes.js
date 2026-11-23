const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'simple_express_secret_key';
const ALLOWED_ROLES = ['user', 'admin'];

// In-memory user store (no database)
const users = [];

function createToken(user) {
  return jwt.sign(
    { id: user.id, name: user.name, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: '2h' }
  );
}

function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token =
    authHeader && authHeader.startsWith('Bearer ')
      ? authHeader.split(' ')[1]
      : null;

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Authentication token is missing. Please log in.'
    });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    return next();
  } catch (err) {
    return res.status(403).json({
      success: false,
      message: 'Invalid or expired authentication token.'
    });
  }
}

function allowOnly(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: 'Access denied. Insufficient permissions for this resource.'
      });
    }
    return next();
  };
}

function sanitizeUser(user) {
  const { password, ...safeUser } = user;
  return safeUser;
}

// POST /api/signup
router.post('/signup', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const chosenRole = (role || 'user').toLowerCase().trim();

    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Name, email, and password are required.'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters long.'
      });
    }

    if (!ALLOWED_ROLES.includes(chosenRole)) {
      return res.status(400).json({
        success: false,
        message: 'Role must be either "user" or "admin".'
      });
    }

    const cleanEmail = email.trim().toLowerCase();
    const alreadyExists = users.find((u) => u.email === cleanEmail);
    if (alreadyExists) {
      return res.status(409).json({
        success: false,
        message: 'An account with this email already exists.'
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = {
      id: users.length + 1,
      name: name.trim(),
      email: cleanEmail,
      password: hashedPassword,
      role: chosenRole,
      createdAt: new Date().toISOString()
    };

    users.push(user);
    const token = createToken(user);

    return res.status(201).json({
      success: true,
      message: 'Account created successfully.',
      token,
      user: sanitizeUser(user)
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Internal server error while processing signup.'
    });
  }
});

// POST /api/login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required.'
      });
    }

    const cleanEmail = email.trim().toLowerCase();
    const user = users.find((u) => u.email === cleanEmail);

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password.'
      });
    }

    const token = createToken(user);

    return res.status(200).json({
      success: true,
      message: 'Signed in successfully.',
      token,
      user: sanitizeUser(user)
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Internal server error while processing login.'
    });
  }
});

// GET /api/user/profile (Current logged-in user profile)
router.get('/user/profile', verifyToken, (req, res) => {
  const currentUser = users.find((u) => u.id === req.user.id);
  if (!currentUser) {
    return res.status(404).json({
      success: false,
      message: 'User account not found.'
    });
  }

  return res.json({
    success: true,
    user: sanitizeUser(currentUser)
  });
});

// PATCH /api/user/profile (Update current user's name/email)
router.patch('/user/profile', verifyToken, (req, res) => {
  const currentUser = users.find((u) => u.id === req.user.id);
  if (!currentUser) {
    return res.status(404).json({
      success: false,
      message: 'User account not found.'
    });
  }

  const { name, email } = req.body;

  if (name !== undefined) {
    const cleanName = String(name).trim();
    if (!cleanName) {
      return res.status(400).json({
        success: false,
        message: 'Name cannot be empty.'
      });
    }
    currentUser.name = cleanName;
  }

  if (email !== undefined) {
    const cleanEmail = String(email).trim().toLowerCase();
    if (!cleanEmail) {
      return res.status(400).json({
        success: false,
        message: 'Email cannot be empty.'
      });
    }
    const duplicate = users.find(
      (u) => u.email === cleanEmail && u.id !== currentUser.id
    );
    if (duplicate) {
      return res.status(409).json({
        success: false,
        message: 'This email is already in use by another account.'
      });
    }
    currentUser.email = cleanEmail;
  }

  const updatedToken = createToken(currentUser);

  return res.json({
    success: true,
    message: 'Profile updated successfully.',
    token: updatedToken,
    user: sanitizeUser(currentUser)
  });
});

// GET /api/user/dashboard
router.get('/user/dashboard', verifyToken, (req, res) => {
  const currentUser = users.find((u) => u.id === req.user.id);
  if (!currentUser) {
    return res.status(404).json({
      success: false,
      message: 'User account not found.'
    });
  }

  return res.json({
    success: true,
    user: sanitizeUser(currentUser),
    items: [
      'View and update your profile details',
      'Access workspace features assigned to your role',
      'Sign out securely when your session ends'
    ]
  });
});

// GET /api/admin/users (Admin only)
router.get('/admin/users', verifyToken, allowOnly('admin'), (req, res) => {
  const safeList = users.map(sanitizeUser);
  return res.json({
    success: true,
    totalUsers: safeList.length,
    users: safeList
  });
});

// PATCH /api/admin/users/:id (Admin only: update role)
router.patch('/admin/users/:id', verifyToken, allowOnly('admin'), (req, res) => {
  const userId = Number(req.params.id);
  const nextRole = String(req.body.role || '').toLowerCase().trim();

  if (!ALLOWED_ROLES.includes(nextRole)) {
    return res.status(400).json({
      success: false,
      message: 'Role must be either "user" or "admin".'
    });
  }

  const targetUser = users.find((u) => u.id === userId);
  if (!targetUser) {
    return res.status(404).json({
      success: false,
      message: 'User not found.'
    });
  }

  targetUser.role = nextRole;

  return res.json({
    success: true,
    message: `Updated ${targetUser.name}'s role to "${nextRole}".`,
    user: sanitizeUser(targetUser)
  });
});

// DELETE /api/admin/users/:id (Admin only: delete user)
router.delete('/admin/users/:id', verifyToken, allowOnly('admin'), (req, res) => {
  const userId = Number(req.params.id);
  const index = users.findIndex((u) => u.id === userId);

  if (index === -1) {
    return res.status(404).json({
      success: false,
      message: 'User not found.'
    });
  }

  if (users[index].id === req.user.id) {
    return res.status(400).json({
      success: false,
      message: 'You cannot delete your own active admin account.'
    });
  }

  const [removed] = users.splice(index, 1);

  return res.json({
    success: true,
    message: `Deleted user "${removed.name}" (${removed.email}).`
  });
});

module.exports = router;