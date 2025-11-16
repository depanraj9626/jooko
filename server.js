// server.js
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const validator = require('validator');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3001;

// Security middleware
app.use(helmet());
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000'],
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Body parser middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/cyberscan', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('Connected to MongoDB');
}).catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'cyberscan-secret-key-change-in-production';

// Models
const User = mongoose.model('User', new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  avatar: { type: String, default: '' },
  subscription: { type: String, enum: ['free', 'professional', 'enterprise'], default: 'free' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}));

const Scan = mongoose.model('Scan', new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  userId: { type: String, required: true },
  url: { type: String, required: true },
  scanType: { type: String, enum: ['quick', 'standard', 'deep'], required: true },
  status: { type: String, enum: ['pending', 'running', 'completed', 'failed'], default: 'pending' },
  progress: { type: Number, default: 0 },
  vulnerabilities: [{ type: mongoose.Schema.Types.Mixed }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}));

const Report = mongoose.model('Report', new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  scanId: { type: String, required: true },
  userId: { type: String, required: true },
  url: { type: String, required: true },
  scanType: { type: String, enum: ['quick', 'standard', 'deep'], required: true },
  vulnerabilities: [{ type: mongoose.Schema.Types.Mixed }],
  scanDate: { type: Date, required: true },
  reportDate: { type: Date, default: Date.now }
}));

const Setting = mongoose.model('Setting', new mongoose.Schema({
  userId: { type: String, required: true },
  settings: { type: mongoose.Schema.Types.Mixed }
}));

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Helper function to generate vulnerabilities
const generateVulnerabilities = (url, scanType) => {
  const vulnTypes = [
    {
      name: 'SQL Injection',
      severity: 'high',
      description: 'SQL injection vulnerability detected in form parameters',
      solution: 'Use parameterized queries or prepared statements',
      cvss: 8.5,
      location: `${url}/api/endpoint1`
    },
    {
      name: 'Cross-Site Scripting (XSS)',
      severity: 'medium',
      description: 'Reflected XSS vulnerability found in search functionality',
      solution: 'Implement proper input sanitization and output encoding',
      cvss: 6.8,
      location: `${url}/search`
    },
    {
      name: 'Cross-Site Request Forgery (CSRF)',
      severity: 'medium',
      description: 'CSRF protection missing in form submissions',
      solution: 'Implement CSRF tokens in all state-changing requests',
      cvss: 7.2,
      location: `${url}/form`
    },
    {
      name: 'Security Headers Missing',
      severity: 'low',
      description: 'Important security headers like CSP, HSTS are not implemented',
      solution: 'Configure security headers in server configuration',
      cvss: 4.5,
      location: url
    },
    {
      name: 'Insecure Direct Object Reference',
      severity: 'high',
      description: 'Direct object references are accessible without proper authorization',
      solution: 'Implement proper access controls for all resources',
      cvss: 7.5,
      location: `${url}/resources`
    }
  ];

  const count = scanType === 'quick' ? 1 : scanType === 'standard' ? 2 : 3;
  const vulnerabilities = [];

  for (let i = 0; i < count; i++) {
    const randomIndex = Math.floor(Math.random() * vulnTypes.length);
    const vuln = { ...vulnTypes[randomIndex] };
    vuln.id = `vuln-${uuidv4()}`;
    vulnerabilities.push(vuln);
  }

  return vulnerabilities;
};

// Simulate scan execution
const simulateScan = async (scanId, url, scanType) => {
  try {
    // Update scan status to running
    await Scan.findOneAndUpdate(
      { id: scanId },
      { status: 'running', progress: 10, updatedAt: new Date() }
    );

    // Simulate scan progress
    const progressSteps = [25, 50, 75, 90, 100];
    for (let i = 0; i < progressSteps.length; i++) {
      await new Promise(resolve => setTimeout(resolve, 2000)); // 2 second delay
      
      await Scan.findOneAndUpdate(
        { id: scanId },
        { 
          progress: progressSteps[i],
          updatedAt: new Date()
        }
      );
    }

    // Generate vulnerabilities
    const vulnerabilities = generateVulnerabilities(url, scanType);

    // Update scan with results
    await Scan.findOneAndUpdate(
      { id: scanId },
      { 
        status: 'completed',
        progress: 100,
        vulnerabilities,
        updatedAt: new Date()
      }
    );

    // Create report
    const reportId = `report-${uuidv4()}`;
    const scan = await Scan.findOne({ id: scanId });
    
    const newReport = new Report({
      id: reportId,
      scanId,
      userId: scan.userId,
      url,
      scanType,
      vulnerabilities,
      scanDate: scan.createdAt
    });

    await newReport.save();

    console.log(`Scan ${scanId} completed successfully`);
  } catch (error) {
    console.error(`Scan ${scanId} failed:`, error);
    await Scan.findOneAndUpdate(
      { id: scanId },
      { 
        status: 'failed',
        updatedAt: new Date()
      }
    );
  }
};

// API Routes

// Authentication routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    if (!validator.isEmail(email)) {
      return res.status(400).json({ message: 'Invalid email address' });
    }

    if (password.length < 8) {
      return res.status(400).json({ message: 'Password must be at least 8 characters long' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: 'User with this email already exists' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user
    const userId = `user-${uuidv4()}`;
    const newUser = new User({
      id: userId,
      name,
      email,
      password: hashedPassword,
      avatar: `https://ui-avatars.com/api/?name=${encodeURIComponent(name)}&background=1E40AF&color=fff`
    });

    await newUser.save();

    // Create default settings
    const defaultSettings = {
      autoScan: true,
      emailNotifications: true,
      darkMode: true,
      advancedScanning: false,
      twoFactorAuth: false,
      scanCompletionNotif: true,
      vulnerabilityAlerts: true,
      weeklyReports: false
    };

    const newSettings = new Setting({
      userId,
      settings: defaultSettings
    });

    await newSettings.save();

    // Generate JWT token
    const token = jwt.sign(
      { id: userId, email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: userId,
        name,
        email,
        avatar: newUser.avatar,
        subscription: newUser.subscription
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(200).json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        avatar: user.avatar,
        subscription: user.subscription
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// Scan routes
app.post('/api/scans', authenticateToken, async (req, res) => {
  try {
    const { url, scanType } = req.body;

    // Validation
    if (!url || !scanType) {
      return res.status(400).json({ message: 'URL and scan type are required' });
    }

    if (!validator.isURL(url)) {
      return res.status(400).json({ message: 'Invalid URL format' });
    }

    // Check user subscription limits
    const user = await User.findOne({ id: req.user.id });
    const scansThisMonth = await Scan.countDocuments({
      userId: req.user.id,
      createdAt: {
        $gte: new Date(new Date().getFullYear(), new Date().getMonth(), 1)
      }
    });

    if (user.subscription === 'free' && scansThisMonth >= 5) {
      return res.status(403).json({ message: 'You have reached your monthly scan limit. Upgrade your plan for more scans.' });
    }

    // Create new scan
    const scanId = `scan-${uuidv4()}`;
    const newScan = new Scan({
      id: scanId,
      userId: req.user.id,
      url,
      scanType,
      status: 'pending'
    });

    await newScan.save();

    // Start scan simulation in background
    simulateScan(scanId, url, scanType);

    res.status(201).json({
      message: 'Scan started successfully',
      scan: {
        id: scanId,
        url,
        scanType,
        status: 'pending',
        progress: 0
      }
    });
  } catch (error) {
    console.error('Start scan error:', error);
    res.status(500).json({ message: 'Server error when starting scan' });
  }
});

app.get('/api/scans', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    const skip = (page - 1) * limit;

    const scans = await Scan.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Scan.countDocuments({ userId: req.user.id });

    res.status(200).json({
      scans,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get scans error:', error);
    res.status(500).json({ message: 'Server error when fetching scans' });
  }
});

app.get('/api/scans/:id', authenticateToken, async (req, res) => {
  try {
    const scan = await Scan.findOne({ id: req.params.id, userId: req.user.id });

    if (!scan) {
      return res.status(404).json({ message: 'Scan not found' });
    }

    res.status(200).json({ scan });
  } catch (error) {
    console.error('Get scan error:', error);
    res.status(500).json({ message: 'Server error when fetching scan' });
  }
});

// Report routes
app.get('/api/reports', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    const skip = (page - 1) * limit;

    const reports = await Report.find({ userId: req.user.id })
      .sort({ reportDate: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Report.countDocuments({ userId: req.user.id });

    res.status(200).json({
      reports,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get reports error:', error);
    res.status(500).json({ message: 'Server error when fetching reports' });
  }
});

app.get('/api/reports/:id', authenticateToken, async (req, res) => {
  try {
    const report = await Report.findOne({ id: req.params.id, userId: req.user.id });

    if (!report) {
      return res.status(404).json({ message: 'Report not found' });
    }

    res.status(200).json({ report });
  } catch (error) {
    console.error('Get report error:', error);
    res.status(500).json({ message: 'Server error when fetching report' });
  }
});

// Settings routes
app.get('/api/settings', authenticateToken, async (req, res) => {
  try {
    const settings = await Setting.findOne({ userId: req.user.id });

    if (!settings) {
      // Create default settings if not found
      const defaultSettings = {
        autoScan: true,
        emailNotifications: true,
        darkMode: true,
        advancedScanning: false,
        twoFactorAuth: false,
        scanCompletionNotif: true,
        vulnerabilityAlerts: true,
        weeklyReports: false
      };

      const newSettings = new Setting({
        userId: req.user.id,
        settings: defaultSettings
      });

      await newSettings.save();
      return res.status(200).json({ settings: defaultSettings });
    }

    res.status(200).json({ settings: settings.settings });
  } catch (error) {
    console.error('Get settings error:', error);
    res.status(500).json({ message: 'Server error when fetching settings' });
  }
});

app.put('/api/settings', authenticateToken, async (req, res) => {
  try {
    const { settings } = req.body;

    if (!settings) {
      return res.status(400).json({ message: 'Settings are required' });
    }

    const userSettings = await Setting.findOne({ userId: req.user.id });

    if (!userSettings) {
      // Create new settings if not found
      const newSettings = new Setting({
        userId: req.user.id,
        settings
      });

      await newSettings.save();
    } else {
      // Update existing settings
      userSettings.settings = { ...userSettings.settings, ...settings };
      await userSettings.save();
    }

    res.status(200).json({ message: 'Settings updated successfully' });
  } catch (error) {
    console.error('Update settings error:', error);
    res.status(500).json({ message: 'Server error when updating settings' });
  }
});

// Subscription routes
app.post('/api/subscription', authenticateToken, async (req, res) => {
  try {
    const { plan } = req.body;

    if (!plan || !['free', 'professional', 'enterprise'].includes(plan)) {
      return res.status(400).json({ message: 'Invalid subscription plan' });
    }

    // In a real app, you would process payment here
    // For demo purposes, we'll just update the subscription

    await User.findOneAndUpdate(
      { id: req.user.id },
      { 
        subscription: plan,
        updatedAt: new Date()
      }
    );

    res.status(200).json({
      message: 'Subscription updated successfully',
      plan
    });
  } catch (error) {
    console.error('Update subscription error:', error);
    res.status(500).json({ message: 'Server error when updating subscription' });
  }
});

// Dashboard stats
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    const totalScans = await Scan.countDocuments({ userId });
    const completedScans = await Scan.countDocuments({ userId, status: 'completed' });
    const totalReports = await Report.countDocuments({ userId });
    
    const scans = await Scan.find({ userId, status: 'completed' });
    const totalVulnerabilities = scans.reduce((total, scan) => total + (scan.vulnerabilities?.length || 0), 0);
    
    const uniqueSites = await Scan.distinct('url', { userId });
    const successRate = totalScans > 0 ? Math.round((completedScans / totalScans) * 100) : 0;

    res.status(200).json({
      totalScans,
      completedScans,
      totalReports,
      totalVulnerabilities,
      sitesMonitored: uniqueSites.length,
      successRate
    });
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ message: 'Server error when fetching dashboard stats' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Serve static files in production
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, 'public')));
  
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });
}

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});