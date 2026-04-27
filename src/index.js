const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const mongoose = require('mongoose');

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB Connected Successfully'))
  .catch(err => console.error('❌ MongoDB Connection Error:', err.message));

// Scan Schema
const scanSchema = new mongoose.Schema({
  url: String,
  isPhishing: Boolean,
  riskScore: Number,
  reasons: [String],
  suspiciousKeywords: [String],
  suspiciousPatterns: [String],
  sslStatus: String,
  recommendations: [String],
  scannedAt: { type: Date, default: Date.now }
});

const Scan = mongoose.model('Scan', scanSchema);

// Suspicious patterns
const suspiciousKeywords = [
  'secure', 'verify', 'account', 'login', 'update', 'confirm',
  'alert', 'suspicious', 'unusual', 'urgent', 'paypal',
  'bank', 'amazon', 'apple', 'netflix', 'microsoft'
];

const suspiciousDomains = [
  'paypa1', 'amaz0n', 'appIe', 'micr0soft',
  '.xyz', '.top', '.club', '.work', '.click', '.tk', '.ml'
];

// ROOT ROUTE - Fixes "Cannot GET /"
app.get('/', (req, res) => {
    res.json({ 
        message: 'CyberSenseAI API is running!',
        version: '1.0.0',
        endpoints: {
            health: 'GET /health',
            scan: 'POST /api/scan',
            history: 'GET /api/history'
        }
    });
});

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'CyberSenseAI API is running',
        timestamp: new Date().toISOString(),
        mongodb: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'
    });
});

// Scan API
app.post('/api/scan', async (req, res) => {
  try {
    const { url } = req.body;
    const apiKey = req.headers['x-api-key'];
    
    if (apiKey !== process.env.MASTER_API_KEY) {
      return res.status(401).json({ error: 'Invalid API key' });
    }
    
    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }
    
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
    
    riskScore = Math.min(riskScore, 100);
    const isPhishing = riskScore >= 50;
    
    let recommendations = [];
    if (riskScore >= 70) {
      recommendations = [
        "🚨 DO NOT proceed",
        "📢 Report this URL",
        "🔐 Never enter personal information"
      ];
    } else if (riskScore >= 30) {
      recommendations = [
        "⚠️ Be extremely cautious",
        "🔍 Verify through official channels",
        "❌ Don't click on suspicious links"
      ];
    } else {
      recommendations = [
        "✅ Website appears safe",
        "🛡️ Keep browser updated"
      ];
    }
    
    const scan = new Scan({
      url, isPhishing, riskScore, reasons,
      suspiciousKeywords: suspiciousKeywordsFound,
      suspiciousPatterns: suspiciousPatternsFound,
      sslStatus, recommendations
    });
    await scan.save();
    
    res.json({
      success: true,
      url,
      isPhishing,
      riskScore,
      reasons,
      suspiciousKeywords: suspiciousKeywordsFound,
      suspiciousPatterns: suspiciousPatternsFound,
      sslStatus,
      recommendations,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get history
app.get('/api/history', async (req, res) => {
  try {
    const apiKey = req.headers['x-api-key'];
    
    if (apiKey !== process.env.MASTER_API_KEY) {
      return res.status(401).json({ error: 'Invalid API key' });
    }
    
    const scans = await Scan.find().sort({ scannedAt: -1 }).limit(100);
    res.json({ success: true, history: scans });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});