const express = require('express');
const app = express();
const PORT = 3000;

app.use(express.json());

// Mock database for users
const users = [
  { id: 1, username: 'admin', password: 'admin123', email: 'admin@example.com', role: 'admin' },
  { id: 2, username: 'artem', password: 'artem123', email: 'artem@example.com', role: 'user' }
];

// Logging middleware (NEW)
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} - IP: ${req.ip}`);
  next();
});

// Health check endpoint (NEW)
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    service: 'DevSec API',
    version: '2.0',
    developer: 'Artem Stariy',
    timestamp: new Date().toISOString()
  });
});

// Home endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'DevSec API with Authentication',
    version: '2.0',
    features: ['authentication', 'logging', 'health-check'],
    developer: 'Artem Stariy (Second Team Member)'
  });
});

// ========== AUTHENTICATION ENDPOINTS ==========

// 1. REGISTER new user
app.post('/api/auth/register', (req, res) => {
  try {
    const { username, password, email } = req.body;
    
    // Validation
    if (!username || !password || !email) {
      return res.status(400).json({
        success: false,
        error: 'Username, password and email are required'
      });
    }
    
    // Check if user exists
    const existingUser = users.find(u => u.username === username || u.email === email);
    if (existingUser) {
      return res.status(409).json({
        success: false,
        error: 'User already exists'
      });
    }
    
    // Create new user
    const newUser = {
      id: users.length + 1,
      username,
      password, // In production: hash with bcrypt
      email,
      role: 'user',
      createdAt: new Date().toISOString(),
      createdBy: 'Artem Auth System'
    };
    
    users.push(newUser);
    
    res.status(201).json({
      success: true,
      message: 'User registered successfully!',
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role,
        createdAt: newUser.createdAt
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Registration failed',
      details: error.message
    });
  }
});

// 2. LOGIN user
app.post('/api/auth/login', (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: 'Username and password are required'
      });
    }
    
    // Find user
    const user = users.find(u => u.username === username && u.password === password);
    
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials'
      });
    }
    
    // Generate token (in production use JWT)
    const token = `artem-auth-${user.id}-${Date.now()}`;
    
    res.json({
      success: true,
      message: 'Login successful!',
      token: token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      },
      expiresIn: '24 hours'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Login failed',
      details: error.message
    });
  }
});

// 3. PROTECTED route - Get user profile
app.get('/api/auth/profile', (req, res) => {
  const token = req.headers.authorization;
  
  if (!token) {
    return res.status(401).json({
      success: false,
      error: 'Authentication token required'
    });
  }
  
  // Simple token validation (in production verify JWT)
  const tokenParts = token.split('-');
  if (tokenParts[0] !== 'artem' && tokenParts[0] !== 'artem-auth') {
    return res.status(403).json({
      success: false,
      error: 'Invalid token format'
    });
  }
  
  const userId = parseInt(tokenParts[2]);
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'User not found'
    });
  }
  
  res.json({
    success: true,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt
    }
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ DevSec API with Authentication running on port ${PORT}`);
  console.log(`👨‍💻 Developer: Artem Stariy`);
  console.log(`🚀 Features: Authentication, Logging, Health Check`);
  console.log(`📅 ${new Date().toISOString()}`);
});
