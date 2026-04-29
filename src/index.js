const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

dotenv.config();

const app = express();

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Error:', err));

// ==================== MODELS ====================

// User Model
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    apiKey: { type: String, unique: true },
    profilePicture: { type: String, default: null }, // NEW: store base64 image
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    level: { type: Number, default: 1 },
    xp: { type: Number, default: 0 },
    totalScans: { type: Number, default: 0 },
    threatsBlocked: { type: Number, default: 0 },
    reportsSubmitted: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
    lastLogin: Date
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

userSchema.methods.comparePassword = async function(candidate) {
  return await bcrypt.compare(candidate, this.password);
};

const User = mongoose.model('User', userSchema);

// Scan History Model
const scanSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  url: { type: String, required: true },
  isPhishing: { type: Boolean, default: false },
  riskScore: { type: Number, min: 0, max: 100 },
  reasons: [String],
  suspiciousKeywords: [String],
  suspiciousPatterns: [String],
  sslStatus: String,
  recommendations: [String],
  scannedAt: { type: Date, default: Date.now }
});

const ScanHistory = mongoose.model('ScanHistory', scanSchema);

// Report Model
const reportSchema = new mongoose.Schema({
  url: { type: String, required: true },
  reporterId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  reason: { type: String, enum: ['phishing', 'malware', 'scam', 'other'], default: 'phishing' },
  description: String,
  status: { type: String, enum: ['pending', 'verified', 'rejected'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});

const Report = mongoose.model('Report', reportSchema);

// Notification Model
const notificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: String,
  message: String,
  type: { type: String, enum: ['alert', 'info', 'achievement'], default: 'info' },
  isRead: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const Notification = mongoose.model('Notification', notificationSchema);

// ==================== MIDDLEWARE ====================

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(morgan('combined'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests' }
});
app.use(limiter);

// Auth middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) throw new Error();
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) throw new Error();
    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Please authenticate' });
  }
};

const verifyApiKey = async (req, res, next) => {
  const apiKey = req.header('X-API-Key');
  if (!apiKey) return res.status(401).json({ error: 'API key required' });
  
  if (apiKey === process.env.MASTER_API_KEY) {
    req.isMasterKey = true;
    return next();
  }
  
  const user = await User.findOne({ apiKey });
  if (!user) return res.status(401).json({ error: 'Invalid API key' });
  req.user = user;
  next();
};

// ==================== SUSPICIOUS PATTERNS ====================

const suspiciousKeywords = [
  'secure', 'verify', 'account', 'login', 'update', 'confirm',
  'alert', 'suspicious', 'unusual', 'urgent', 'paypal',
  'bank', 'amazon', 'apple', 'netflix', 'microsoft'
];

const suspiciousDomains = [
  'paypa1', 'amaz0n', 'appIe', 'micr0soft',
  '.xyz', '.top', '.club', '.work', '.click', '.tk', '.ml'
];

// ==================== SCAN SERVICE ====================

async function scanUrl(url) {
  const lowerUrl = url.toLowerCase();
  let riskScore = 0;
  const reasons = [];
  const suspiciousKeywordsFound = [];
  const suspiciousPatternsFound = [];
  let sslStatus = "unknown";

  for (const keyword of suspiciousKeywords) {
    if (lowerUrl.includes(keyword)) {
      suspiciousKeywordsFound.push(keyword);
      reasons.push(`Contains suspicious keyword: ${keyword}`);
      riskScore += 10;
    }
  }

  for (const domain of suspiciousDomains) {
    if (lowerUrl.includes(domain)) {
      suspiciousPatternsFound.push(domain);
      reasons.push(`Suspicious domain pattern: ${domain}`);
      riskScore += 20;
    }
  }

  if (lowerUrl.startsWith('http://')) {
    sslStatus = "insecure";
    reasons.push('Uses HTTP (not secure)');
    riskScore += 15;
  } else if (lowerUrl.startsWith('https://')) {
    sslStatus = "secure";
  }

  const ipMatch = lowerUrl.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/);
  if (ipMatch) {
    suspiciousPatternsFound.push(`IP: ${ipMatch[0]}`);
    reasons.push('Uses IP address instead of domain');
    riskScore += 25;
  }

  riskScore = Math.min(riskScore, 100);
  const isPhishing = riskScore >= 50;

  let recommendations = [];
  if (riskScore >= 70) {
    recommendations = ["🚨 DO NOT proceed", "📢 Report this URL", "🔐 Never enter personal information"];
  } else if (riskScore >= 30) {
    recommendations = ["⚠️ Be cautious", "🔍 Verify through official channels", "❌ Don't click suspicious links"];
  } else {
    recommendations = ["✅ Website appears safe", "🛡️ Keep browser updated"];
  }

  return {
    isPhishing, riskScore, reasons,
    suspiciousKeywords: suspiciousKeywordsFound,
    suspiciousPatterns: suspiciousPatternsFound,
    sslStatus, recommendations
  };
}

// ==================== AUTH ROUTES ====================

app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    const existing = await User.findOne({ $or: [{ email }, { username }] });
    if (existing) return res.status(400).json({ error: 'User already exists' });
    
    const user = new User({ username, email, password });
    user.apiKey = 'cyber_' + Math.random().toString(36).substring(2, 15);
    await user.save();
    
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    
    res.json({
      success: true,
      token,
      user: { id: user._id, username, email, apiKey: user.apiKey, level: 1, xp: 0 }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    
    const isValid = await user.comparePassword(password);
    if (!isValid) return res.status(401).json({ error: 'Invalid credentials' });
    
    user.lastLogin = new Date();
    await user.save();
    
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    
    res.json({
      success: true,
      token,
      user: { id: user._id, username: user.username, email: user.email, apiKey: user.apiKey, level: user.level, xp: user.xp }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/auth/profile', authenticate, async (req, res) => {
  res.json({ success: true, user: req.user });
});

// ==================== SCAN ROUTES ====================

app.post('/api/scan', verifyApiKey, async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL required' });
    
    const result = await scanUrl(url);
    
    if (req.user) {
      const scan = new ScanHistory({
        userId: req.user._id,
        url,
        isPhishing: result.isPhishing,
        riskScore: result.riskScore,
        reasons: result.reasons,
        suspiciousKeywords: result.suspiciousKeywords,
        suspiciousPatterns: result.suspiciousPatterns,
        sslStatus: result.sslStatus,
        recommendations: result.recommendations
      });
      await scan.save();
      
      // Update user stats
      await User.findByIdAndUpdate(req.user._id, {
        $inc: { totalScans: 1, threatsBlocked: result.isPhishing ? 1 : 0 }
      });
    }
    
    res.json({ success: true, ...result, url, timestamp: new Date() });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== HISTORY ROUTES ====================

app.get('/api/history', verifyApiKey, async (req, res) => {
  try {
    const scans = await ScanHistory.find({ userId: req.user._id })
      .sort({ scannedAt: -1 })
      .limit(100);
    res.json({ success: true, history: scans });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/history/:id', verifyApiKey, async (req, res) => {
  try {
    if (req.params.id === 'all') {
      await ScanHistory.deleteMany({ userId: req.user._id });
    } else {
      await ScanHistory.findOneAndDelete({ _id: req.params.id, userId: req.user._id });
    }
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== LEADERBOARD ROUTES ====================

app.get('/api/leaderboard', async (req, res) => {
  try {
    const { type = 'xp', limit = 20 } = req.query;
    
    let sortField = {};
    if (type === 'xp') sortField = { xp: -1 };
    else if (type === 'scans') sortField = { totalScans: -1 };
    else if (type === 'threats') sortField = { threatsBlocked: -1 };
    
    const leaderboard = await User.find({ role: 'user' })
      .select('username xp level totalScans threatsBlocked')
      .sort(sortField)
      .limit(parseInt(limit));
    
    const ranked = leaderboard.map((user, i) => ({ rank: i + 1, ...user.toObject() }));
    res.json({ success: true, leaderboard: ranked });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/leaderboard/rank', authenticate, async (req, res) => {
  try {
    const count = await User.countDocuments({ role: 'user', xp: { $gt: req.user.xp } });
    res.json({ success: true, rank: count + 1 });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== THREAT ROUTES ====================

app.post('/api/threats/report', authenticate, async (req, res) => {
  try {
    const { url, reason, description } = req.body;
    if (!url) return res.status(400).json({ error: 'URL required' });
    
    const existing = await Report.findOne({ url, reporterId: req.user._id });
    if (existing) return res.status(400).json({ error: 'Already reported' });
    
    const report = new Report({ url, reporterId: req.user._id, reason, description });
    await report.save();
    
    await User.findByIdAndUpdate(req.user._id, { $inc: { reportsSubmitted: 1, xp: 5 } });
    
    res.json({ success: true, message: 'Report submitted', report });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/threats/stats', async (req, res) => {
  try {
    const stats = {
      totalReports: await Report.countDocuments(),
      verifiedThreats: await Report.countDocuments({ status: 'verified' }),
      pendingReports: await Report.countDocuments({ status: 'pending' }),
      topReporters: await Report.aggregate([
        { $group: { _id: '$reporterId', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 5 }
      ])
    };
    res.json({ success: true, stats });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== NOTIFICATION ROUTES ====================

app.get('/api/notifications', authenticate, async (req, res) => {
  try {
    const notifications = await Notification.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .limit(50);
    const unreadCount = await Notification.countDocuments({ userId: req.user._id, isRead: false });
    res.json({ success: true, notifications, unreadCount });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/notifications/:id/read', authenticate, async (req, res) => {
  try {
    await Notification.findOneAndUpdate({ _id: req.params.id, userId: req.user._id }, { isRead: true });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== HEALTH CHECK ====================

app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date(),
    mongodb: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
    version: '2.0.0'
  });
});


// Change from port 587 to 2525
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 2525,  // ← Change this from 587 to 2525
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// ==================== UPDATE USER PROFILE ====================

// Update username
app.put('/api/user/username', authenticate, async (req, res) => {
    try {
        const { newUsername } = req.body;
        
        if (!newUsername || newUsername.length < 3) {
            return res.status(400).json({ error: 'Username must be at least 3 characters' });
        }
        
        // Check if username already taken
        const existingUser = await User.findOne({ username: newUsername, _id: { $ne: req.user._id } });
        if (existingUser) {
            return res.status(400).json({ error: 'Username already taken' });
        }
        
        req.user.username = newUsername;
        await req.user.save();
        
        res.json({ success: true, username: newUsername });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update password
app.put('/api/user/password', authenticate, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        
        // Verify current password
        const isValid = await req.user.comparePassword(currentPassword);
        if (!isValid) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }
        
        if (!newPassword || newPassword.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }
        
        req.user.password = newPassword;
        await req.user.save();
        
        res.json({ success: true, message: 'Password updated successfully' });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update user stats (XP, Level)
app.put('/api/user/stats', authenticate, async (req, res) => {
    try {
        const { xp, level, totalScans, threatsBlocked } = req.body;
        
        if (xp !== undefined) req.user.xp = xp;
        if (level !== undefined) req.user.level = level;
        if (totalScans !== undefined) req.user.totalScans = totalScans;
        if (threatsBlocked !== undefined) req.user.threatsBlocked = threatsBlocked;
        
        await req.user.save();
        
        res.json({ 
            success: true, 
            user: {
                username: req.user.username,
                email: req.user.email,
                level: req.user.level,
                xp: req.user.xp,
                totalScans: req.user.totalScans,
                threatsBlocked: req.user.threatsBlocked
            }
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get user profile (with stats)
app.get('/api/user/profile', authenticate, async (req, res) => {
    try {
        res.json({
            success: true,
            user: {
                id: req.user._id,
                username: req.user.username,
                email: req.user.email,
                level: req.user.level,
                xp: req.user.xp,
                totalScans: req.user.totalScans,
                threatsBlocked: req.user.threatsBlocked,
                reportsSubmitted: req.user.reportsSubmitted,
                createdAt: req.user.createdAt
            }
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update profile picture (store base64 or URL)
app.put('/api/user/profile-picture', authenticate, async (req, res) => {
    try {
        const { profilePicture } = req.body;
        
        // Store base64 image (max 2MB)
        if (profilePicture && profilePicture.length < 2 * 1024 * 1024) {
            req.user.profilePicture = profilePicture;
            await req.user.save();
            res.json({ success: true, message: 'Profile picture updated' });
        } else {
            res.status(400).json({ error: 'Image too large or invalid' });
        }
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== START SERVER ====================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📡 Health: http://localhost:${PORT}/health`);
  console.log(`🔐 Auth: POST /api/auth/register, /api/auth/login`);
  console.log(`🔍 Scan: POST /api/scan`);
  console.log(`📊 Leaderboard: GET /api/leaderboard`);
});

app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        
        if (!user) {
            return res.status(404).json({ success: false, message: 'Email not found' });
        }
        
        // Generate reset token
        const resetToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        
        // In production, send email here
        console.log(`Password reset token for ${email}: ${resetToken}`);
        
        res.json({ success: true, message: 'Reset link sent to email' });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});