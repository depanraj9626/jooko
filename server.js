const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// In-memory storage (in production, use a database like MongoDB or PostgreSQL)
let users = [];
let scans = [];
let reports = [];
let verificationCodes = {};
let shareLinks = {};

// Helper functions
const generateToken = (user) => {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
};

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

const generateVerificationCode = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

const generateVulnerabilities = (url, scanType) => {
  const vulnerabilities = [];
  const vulnerabilityTypes = [
    { 
      name: 'SQL Injection', 
      severity: 'high', 
      description: 'SQL injection vulnerability detected in form parameters', 
      solution: 'Use parameterized queries or prepared statements to prevent SQL injection' 
    },
    { 
      name: 'Cross-Site Scripting (XSS)', 
      severity: 'medium', 
      description: 'Reflected XSS vulnerability found in search functionality', 
      solution: 'Sanitize user input and implement proper output encoding' 
    },
    { 
      name: 'Cross-Site Request Forgery (CSRF)', 
      severity: 'medium', 
      description: 'CSRF vulnerability detected in form submission', 
      solution: 'Implement CSRF tokens in all forms' 
    },
    { 
      name: 'Directory Traversal', 
      severity: 'high', 
      description: 'Directory traversal vulnerability in file download feature', 
      solution: 'Validate and sanitize file paths before accessing files' 
    },
    { 
      name: 'File Inclusion', 
      severity: 'high', 
      description: 'Local file inclusion vulnerability detected', 
      solution: 'Avoid including files based on user input' 
    },
    { 
      name: 'Missing Security Headers', 
      severity: 'low', 
      description: 'Security headers like CSP, HSTS are missing', 
      solution: 'Implement security headers in server configuration' 
    }
  ];

  // Generate random vulnerabilities based on scan type
  const count = scanType === 'quick' ? 1 : scanType === 'standard' ? 3 : 5;
  
  for (let i = 0; i < count; i++) {
    const randomIndex = Math.floor(Math.random() * vulnerabilityTypes.length);
    vulnerabilities.push({
      ...vulnerabilityTypes[randomIndex],
      id: `vuln-${Date.now()}-${i}`
    });
  }

  return vulnerabilities;
};

// API Routes

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Auth endpoints
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, mobile, password } = req.body;

    // Validation
    if (!name || !email || !mobile || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if user already exists
    const existingUser = users.find(u => u.email === email);
    if (existingUser) {
      return res.status(400).json({ error: 'User with this email already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = {
      id: `user-${Date.now()}`,
      name,
      email,
      mobile,
      password: hashedPassword,
      emailVerified: false,
      mobileVerified: false,
      createdAt: new Date().toISOString()
    };

    users.push(newUser);

    // Generate verification code
    const verificationCode = generateVerificationCode();
    verificationCodes[email] = {
      code: verificationCode,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000) // 10 minutes
    };

    // Generate token
    const token = generateToken(newUser);

    // In production, send verification email here
    console.log(`Verification code for ${email}: ${verificationCode}`);

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
        emailVerified: newUser.emailVerified,
        mobileVerified: newUser.mobileVerified
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const user = users.find(u => u.email === email);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate token
    const token = generateToken(user);

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        emailVerified: user.emailVerified,
        mobileVerified: user.mobileVerified
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/verify-email', authenticateToken, (req, res) => {
  try {
    const { code } = req.body;
    const userId = req.user.id;
    const user = users.find(u => u.id === userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Check verification code
    const storedCode = verificationCodes[user.email];
    if (!storedCode || storedCode.code !== code) {
      return res.status(400).json({ error: 'Invalid verification code' });
    }

    // Check if code has expired
    if (new Date() > storedCode.expiresAt) {
      return res.status(400).json({ error: 'Verification code has expired' });
    }

    // Mark email as verified
    user.emailVerified = true;
    delete verificationCodes[user.email];

    res.json({
      message: 'Email verified successfully',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        emailVerified: user.emailVerified,
        mobileVerified: user.mobileVerified
      }
    });
  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({ error: 'Email verification failed' });
  }
});

app.post('/api/resend-verification', authenticateToken, (req, res) => {
  try {
    const userId = req.user.id;
    const user = users.find(u => u.id === userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Generate new verification code
    const verificationCode = generateVerificationCode();
    verificationCodes[user.email] = {
      code: verificationCode,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000) // 10 minutes
    };

    // In production, send verification email here
    console.log(`New verification code for ${user.email}: ${verificationCode}`);

    res.json({
      message: 'Verification code sent successfully'
    });
  } catch (error) {
    console.error('Resend verification error:', error);
    res.status(500).json({ error: 'Failed to resend verification code' });
  }
});

app.post('/api/verify-mobile', authenticateToken, (req, res) => {
  try {
    const { code } = req.body;
    const userId = req.user.id;
    const user = users.find(u => u.id === userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // For demo purposes, accept any 6-digit code
    if (!code || code.length !== 6) {
      return res.status(400).json({ error: 'Invalid verification code' });
    }

    // Mark mobile as verified
    user.mobileVerified = true;

    res.json({
      message: 'Mobile verified successfully',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        emailVerified: user.emailVerified,
        mobileVerified: user.mobileVerified
      }
    });
  } catch (error) {
    console.error('Mobile verification error:', error);
    res.status(500).json({ error: 'Mobile verification failed' });
  }
});

// Scan endpoints
app.post('/api/scans', authenticateToken, (req, res) => {
  try {
    const { url, scanType, options } = req.body;
    const userId = req.user.id;

    // Validation
    if (!url || !scanType) {
      return res.status(400).json({ error: 'URL and scan type are required' });
    }

    // Create new scan
    const newScan = {
      id: `scan-${Date.now()}`,
      userId,
      url,
      scanType,
      options: options || {},
      status: 'pending',
      progress: 0,
      vulnerabilities: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    scans.push(newScan);

    // Simulate scan progress
    setTimeout(() => {
      newScan.status = 'running';
      newScan.progress = 25;
      
      setTimeout(() => {
        newScan.progress = 50;
        
        setTimeout(() => {
          newScan.progress = 75;
          
          setTimeout(() => {
            newScan.status = 'completed';
            newScan.progress = 100;
            newScan.vulnerabilities = generateVulnerabilities(url, scanType);
            newScan.updatedAt = new Date().toISOString();
            
            // Create report
            const newReport = {
              id: `report-${Date.now()}`,
              scanId: newScan.id,
              userId,
              url,
              scanType,
              scanDate: newScan.createdAt,
              vulnerabilities: newScan.vulnerabilities,
              createdAt: new Date().toISOString()
            };
            
            reports.push(newReport);
          }, 2000);
        }, 2000);
      }, 2000);
    }, 1000);

    res.status(201).json({
      message: 'Scan started successfully',
      scan: newScan
    });
  } catch (error) {
    console.error('Create scan error:', error);
    res.status(500).json({ error: 'Failed to start scan' });
  }
});

app.get('/api/scans', authenticateToken, (req, res) => {
  try {
    const userId = req.user.id;
    const userScans = scans.filter(scan => scan.userId === userId);
    
    res.json({
      scans: userScans
    });
  } catch (error) {
    console.error('Get scans error:', error);
    res.status(500).json({ error: 'Failed to get scans' });
  }
});

app.get('/api/scans/:scanId', authenticateToken, (req, res) => {
  try {
    const { scanId } = req.params;
    const userId = req.user.id;
    
    const scan = scans.find(s => s.id === scanId && s.userId === userId);
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    
    res.json({
      scan
    });
  } catch (error) {
    console.error('Get scan error:', error);
    res.status(500).json({ error: 'Failed to get scan' });
  }
});

app.delete('/api/scans/:scanId', authenticateToken, (req, res) => {
  try {
    const { scanId } = req.params;
    const userId = req.user.id;
    
    // Find scan
    const scanIndex = scans.findIndex(s => s.id === scanId && s.userId === userId);
    if (scanIndex === -1) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    
    // Delete scan
    scans.splice(scanIndex, 1);
    
    res.json({
      message: 'Scan deleted successfully'
    });
  } catch (error) {
    console.error('Delete scan error:', error);
    res.status(500).json({ error: 'Failed to delete scan' });
  }
});

// Report endpoints
app.get('/api/reports', authenticateToken, (req, res) => {
  try {
    const userId = req.user.id;
    const userReports = reports.filter(report => report.userId === userId);
    
    res.json({
      reports: userReports
    });
  } catch (error) {
    console.error('Get reports error:', error);
    res.status(500).json({ error: 'Failed to get reports' });
  }
});

app.get('/api/reports/:reportId', authenticateToken, (req, res) => {
  try {
    const { reportId } = req.params;
    const userId = req.user.id;
    
    // Find report
    const report = reports.find(r => r.id === reportId && r.userId === userId);
    if (!report) {
      return res.status(404).json({ error: 'Report not found' });
    }
    
    res.json({
      report
    });
  } catch (error) {
    console.error('Get report error:', error);
    res.status(500).json({ error: 'Failed to get report' });
  }
});

app.delete('/api/reports/:reportId', authenticateToken, (req, res) => {
  try {
    const { reportId } = req.params;
    const userId = req.user.id;
    
    // Find report
    const reportIndex = reports.findIndex(r => r.id === reportId && r.userId === userId);
    if (reportIndex === -1) {
      return res.status(404).json({ error: 'Report not found' });
    }
    
    // Delete report
    reports.splice(reportIndex, 1);
    
    res.json({
      message: 'Report deleted successfully'
    });
  } catch (error) {
    console.error('Delete report error:', error);
    res.status(500).json({ error: 'Failed to delete report' });
  }
});

// Dashboard endpoints
app.get('/api/dashboard/stats', authenticateToken, (req, res) => {
  try {
    const userId = req.user.id;
    const userScans = scans.filter(scan => scan.userId === userId);
    const userReports = reports.filter(report => report.userId === userId);
    
    // Calculate stats
    const totalScans = userScans.length;
    const vulnerabilitiesFound = userReports.reduce((total, report) => total + report.vulnerabilities.length, 0);
    const sitesMonitored = new Set(userScans.map(scan => scan.url)).size;
    const completedScans = userScans.filter(scan => scan.status === 'completed').length;
    const scanSuccessRate = totalScans > 0 ? Math.round((completedScans / totalScans) * 100) : 0;
    
    res.json({
      stats: {
        totalScans,
        vulnerabilitiesFound,
        sitesMonitored,
        scanSuccessRate
      }
    });
  } catch (error) {
    console.error('Get dashboard stats error:', error);
    res.status(500).json({ error: 'Failed to get dashboard stats' });
  }
});

// Database download endpoint
app.get('/api/database/download', authenticateToken, (req, res) => {
  try {
    const userId = req.user.id;
    const userScans = scans.filter(scan => scan.userId === userId);
    const userReports = reports.filter(report => report.userId === userId);
    
    // Create database object
    const database = {
      user: {
        id: userId,
        name: users.find(u => u.id === userId)?.name,
        email: users.find(u => u.id === userId)?.email
      },
      scans: userScans,
      reports: userReports,
      exportDate: new Date().toISOString()
    };
    
    // Set headers for file download
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="secured_scan_database.json"');
    
    res.json(database);
  } catch (error) {
    console.error('Database download error:', error);
    res.status(500).json({ error: 'Failed to download database' });
  }
});

// Share report endpoints
app.post('/api/reports/:reportId/share', authenticateToken, (req, res) => {
  try {
    const { reportId } = req.params;
    const { email } = req.body;
    const userId = req.user.id;
    
    // Validation
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    
    // Find report
    const report = reports.find(r => r.id === reportId && r.userId === userId);
    if (!report) {
      return res.status(404).json({ error: 'Report not found' });
    }
    
    // In production, send email with report link
    console.log(`Report ${reportId} shared to ${email}`);
    
    res.json({
      message: `Report shared successfully to ${email}`
    });
  } catch (error) {
    console.error('Share report error:', error);
    res.status(500).json({ error: 'Failed to share report' });
  }
});

app.post('/api/reports/:reportId/share-link', authenticateToken, (req, res) => {
  try {
    const { reportId } = req.params;
    const userId = req.user.id;
    
    // Find report
    const report = reports.find(r => r.id === reportId && r.userId === userId);
    if (!report) {
      return res.status(404).json({ error: 'Report not found' });
    }
    
    // Generate share link
    const shareId = crypto.randomBytes(16).toString('hex');
    const shareLink = `${req.protocol}://${req.get('host')}/shared-report/${shareId}`;
    
    // Store share link
    shareLinks[shareId] = {
      reportId,
      userId,
      createdAt: new Date().toISOString()
    };
    
    res.json({
      shareLink
    });
  } catch (error) {
    console.error('Generate share link error:', error);
    res.status(500).json({ error: 'Failed to generate share link' });
  }
});

// Shared report endpoint (public)
app.get('/shared-report/:shareId', (req, res) => {
  try {
    const { shareId } = req.params;
    
    // Find share link
    const shareLink = shareLinks[shareId];
    if (!shareLink) {
      return res.status(404).json({ error: 'Share link not found or expired' });
    }
    
    // Find report
    const report = reports.find(r => r.id === shareLink.reportId);
    if (!report) {
      return res.status(404).json({ error: 'Report not found' });
    }
    
    res.json({
      report
    });
  } catch (error) {
    console.error('Get shared report error:', error);
    res.status(500).json({ error: 'Failed to get shared report' });
  }
});

// Serve the HTML file for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Open http://localhost:${PORT} in your browser`);
});