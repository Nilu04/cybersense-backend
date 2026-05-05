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
  profilePicture: { type: String, default: null },
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

// Weekly Challenge Models
const challengeSchema = new mongoose.Schema({
  week: { type: Number, required: true, unique: true },
  title: { type: String, required: true },
  description: String,
  questions: [{
    id: Number,
    text: String,
    options: [String],
    correctAnswer: Number,
    explanation: String,
    points: { type: Number, default: 10 }
  }],
  startDate: Date,
  endDate: Date,
  isActive: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const Challenge = mongoose.model('Challenge', challengeSchema);

const userChallengeSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  week: { type: Number, required: true },
  score: { type: Number, default: 0 },
  totalPoints: { type: Number, default: 0 },
  answers: [{
    questionId: Number,
    selectedAnswer: Number,
    isCorrect: Boolean,
    answeredAt: Date
  }],
  completed: { type: Boolean, default: false },
  completedAt: Date,
  startedAt: { type: Date, default: Date.now }
});

const UserChallenge = mongoose.model('UserChallenge', userChallengeSchema);

// ==================== MIDDLEWARE ====================

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
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

const requireAdmin = async (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
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

// ==================== CREATE DEFAULT CHALLENGE ====================

async function createDefaultChallenge() {
  try {
    const existing = await Challenge.findOne({ week: 1 });
    if (existing) {
      console.log('✅ Default challenge already exists');
      return existing;
    }
    
    const defaultChallenge = {
      week: 1,
      title: "Cybersecurity Basics",
      description: "Test your knowledge about phishing and cybersecurity",
      startDate: new Date(),
      endDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      isActive: true,
      questions: [
        {
          id: 1,
          text: "What is phishing?",
          options: [
            "A type of fishing",
            "A cyber attack where attackers trick you into revealing sensitive information",
            "A security software",
            "A network protocol"
          ],
          correctAnswer: 1,
          points: 10,
          explanation: "Phishing is a cyber attack where criminals create fake websites or emails to steal your personal information."
        },
        {
          id: 2,
          text: "What is a common sign of a phishing email?",
          options: [
            "Professional grammar",
            "Urgent language threatening account closure",
            "Correct sender email address",
            "Personalized greeting with your name"
          ],
          correctAnswer: 1,
          points: 10,
          explanation: "Phishing emails often use urgent language like 'Your account will be closed!' to make you act without thinking."
        },
        {
          id: 3,
          text: "What does HTTPS indicate?",
          options: [
            "The website is secure and encrypted",
            "The website is from India",
            "The website is slow",
            "The website is fake"
          ],
          correctAnswer: 0,
          points: 10,
          explanation: "HTTPS indicates the connection is encrypted and secure. Always look for the padlock icon."
        },
        {
          id: 4,
          text: "What should you do if you receive a suspicious link?",
          options: [
            "Click it immediately to check",
            "Share it with friends",
            "Scan it using CyberSenseAI first",
            "Ignore it completely"
          ],
          correctAnswer: 2,
          points: 10,
          explanation: "Always scan suspicious links using CyberSenseAI before clicking them."
        },
        {
          id: 5,
          text: "What is Two-Factor Authentication (2FA)?",
          options: [
            "Two different passwords",
            "An extra security layer requiring a second verification method",
            "Two different accounts",
            "A type of computer virus"
          ],
          correctAnswer: 1,
          points: 10,
          explanation: "2FA adds an extra layer of security by requiring a second verification method like a code from your phone."
        }
      ]
    };
    
    const challenge = new Challenge(defaultChallenge);
    await challenge.save();
    console.log('✅ Default challenge created successfully!');
    return challenge;
    
  } catch (error) {
    console.error('Error creating default challenge:', error);
    return null;
  }
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
      user: { 
        id: user._id, 
        username, 
        email, 
        apiKey: user.apiKey, 
        level: 1, 
        xp: 0,
        totalScans: 0,
        threatsBlocked: 0
      }
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
      user: { 
        id: user._id, 
        username: user.username, 
        email: user.email, 
        apiKey: user.apiKey, 
        level: user.level, 
        xp: user.xp,
        totalScans: user.totalScans,
        threatsBlocked: user.threatsBlocked
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, message: 'Email required' });
    
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ success: false, message: 'Email not found' });
    
    const resetToken = jwt.sign(
      { userId: user._id, type: 'password-reset' }, 
      process.env.JWT_SECRET, 
      { expiresIn: '1h' }
    );
    
    console.log(`🔐 Password reset token for ${email}: ${resetToken}`);
    
    res.json({ 
      success: true, 
      message: 'If your email is registered, you will receive a password reset link.' 
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ==================== USER PROFILE ROUTES ====================

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
        profilePicture: req.user.profilePicture || null,
        createdAt: req.user.createdAt
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/user/username', authenticate, async (req, res) => {
  try {
    const { newUsername } = req.body;
    if (!newUsername || newUsername.length < 3) {
      return res.status(400).json({ success: false, error: 'Username must be at least 3 characters' });
    }
    
    const existingUser = await User.findOne({ username: newUsername, _id: { $ne: req.user._id } });
    if (existingUser) {
      return res.status(400).json({ success: false, error: 'Username already taken' });
    }
    
    req.user.username = newUsername;
    await req.user.save();
    res.json({ success: true, username: newUsername, message: 'Username updated successfully' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put('/api/user/password', authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const isValid = await req.user.comparePassword(currentPassword);
    if (!isValid) return res.status(401).json({ success: false, error: 'Current password is incorrect' });
    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });
    }
    
    req.user.password = newPassword;
    await req.user.save();
    res.json({ success: true, message: 'Password updated successfully' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put('/api/user/profile-picture', authenticate, async (req, res) => {
  try {
    const { profilePicture } = req.body;
    if (!profilePicture) return res.status(400).json({ success: false, error: 'No image provided' });
    
    req.user.profilePicture = profilePicture;
    await req.user.save();
    res.json({ success: true, message: 'Profile picture updated successfully' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
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
      
      await User.findByIdAndUpdate(req.user._id, {
        $inc: { totalScans: 1, threatsBlocked: result.isPhishing ? 1 : 0 }
      });
    }
    
    res.json({ success: true, ...result, url, timestamp: new Date() });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

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

// ==================== LEADERBOARD ====================

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
      pendingReports: await Report.countDocuments({ status: 'pending' })
    };
    res.json({ success: true, stats });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== WEEKLY CHALLENGE ROUTES ====================

app.get('/api/challenge/current', authenticate, async (req, res) => {
  try {
    const today = new Date();
    let challenge = await Challenge.findOne({ 
      isActive: true,
      startDate: { $lte: today },
      endDate: { $gte: today }
    });
    
    if (!challenge) {
      console.log('No active challenge found, creating default challenge...');
      challenge = await createDefaultChallenge();
    }
    
    if (!challenge) {
      return res.json({ success: true, hasChallenge: false, message: 'No active challenge available' });
    }
    
    const userProgress = await UserChallenge.findOne({ userId: req.user._id, week: challenge.week });
    
    res.json({
      success: true,
      hasChallenge: true,
      challenge: {
        id: challenge._id,
        week: challenge.week,
        title: challenge.title,
        description: challenge.description,
        questions: challenge.questions.map(q => ({
          id: q.id,
          text: q.text,
          options: q.options,
          points: q.points
        })),
        totalPoints: challenge.questions.reduce((sum, q) => sum + q.points, 0),
        startDate: challenge.startDate,
        endDate: challenge.endDate
      },
      userProgress: userProgress || null
    });
  } catch (error) {
    console.error('Challenge error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/challenge/submit', authenticate, async (req, res) => {
  try {
    const { week, questionId, selectedAnswer } = req.body;
    
    const challenge = await Challenge.findOne({ week, isActive: true });
    if (!challenge) return res.status(404).json({ error: 'Challenge not found' });
    
    const question = challenge.questions.find(q => q.id === questionId);
    if (!question) return res.status(404).json({ error: 'Question not found' });
    
    let userProgress = await UserChallenge.findOne({ userId: req.user._id, week: challenge.week });
    if (!userProgress) {
      userProgress = new UserChallenge({
        userId: req.user._id,
        week: challenge.week,
        answers: [],
        score: 0,
        totalPoints: 0
      });
    }
    
    const existingAnswer = userProgress.answers.find(a => a.questionId === questionId);
    if (existingAnswer) return res.status(400).json({ error: 'Question already answered' });
    
    const isCorrect = selectedAnswer === question.correctAnswer;
    const pointsEarned = isCorrect ? question.points : 0;
    
    userProgress.answers.push({
      questionId,
      selectedAnswer,
      isCorrect,
      answeredAt: new Date()
    });
    
    userProgress.score += pointsEarned;
    userProgress.totalPoints += pointsEarned;
    
    if (userProgress.answers.length === challenge.questions.length) {
      userProgress.completed = true;
      userProgress.completedAt = new Date();
      await User.findByIdAndUpdate(req.user._id, { $inc: { xp: userProgress.score, totalScans: 1 } });
    }
    
    await userProgress.save();
    
    res.json({
      success: true,
      isCorrect,
      pointsEarned,
      correctAnswer: isCorrect ? null : question.correctAnswer,
      explanation: isCorrect ? null : question.explanation,
      totalScore: userProgress.score,
      totalPoints: userProgress.totalPoints,
      completed: userProgress.completed
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/challenge/leaderboard/:week', async (req, res) => {
  try {
    const { week } = req.params;
    const leaderboard = await UserChallenge.find({ week, completed: true })
      .sort({ score: -1, completedAt: 1 })
      .limit(50)
      .populate('userId', 'username xp level');
    
    res.json({
      success: true,
      leaderboard: leaderboard.map((entry, index) => ({
        rank: index + 1,
        username: entry.userId.username,
        score: entry.score,
        completedAt: entry.completedAt
      }))
    });
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

// ==================== START SERVER ====================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📡 Health: http://localhost:${PORT}/health`);
  console.log(`🔐 Auth: POST /api/auth/register, /api/auth/login`);
  console.log(`👤 Profile: GET /api/user/profile`);
  console.log(`🔍 Scan: POST /api/scan`);
  console.log(`📊 Leaderboard: GET /api/leaderboard`);
  console.log(`🏆 Challenge: GET /api/challenge/current`);
});