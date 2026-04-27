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

// Suspicious patterns for detection
const suspiciousKeywords = [
  'secure', 'verify', 'account', 'login', 'update', 'confirm',
  'alert', 'suspicious', 'unusual', 'urgent', 'paypal',
  'bank', 'amazon', 'apple', 'netflix', 'microsoft'
];

const suspiciousDomains = [
  'paypa1', 'amaz0n', 'appIe', 'micr0soft',
  '.xyz', '.top', '.club', '.work', '.click', '.tk', '.ml'
];

// Scan API Endpoint
app.post('/api/scan', async (req, res) => {
  try {
    const { url } = req.body;
    const apiKey = req.headers['x-api-key'];
    
    // Check API key
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
    
    // Check for suspicious keywords
    for (const keyword of suspiciousKeywords) {
      if (lowerUrl.includes(keyword)) {
        suspiciousKeywordsFound.push(keyword);
        reasons.push(`Contains suspicious keyword: ${keyword}`);
        riskScore += 10;
      }
    }
    
    // Check for suspicious domains
    for (const domain of suspiciousDomains) {
      if (lowerUrl.includes(domain)) {
        suspiciousPatternsFound.push(domain);
        reasons.push(`Suspicious domain pattern: ${domain}`);
        riskScore += 20;
      }
    }
    
    // Check HTTP vs HTTPS
    if (lowerUrl.startsWith('http://')) {
      sslStatus = "insecure";
      reasons.push('Uses HTTP (not secure)');
      riskScore += 15;
    } else if (lowerUrl.startsWith('https://')) {
      sslStatus = "secure";
      reasons.push('Uses HTTPS (secure connection)');
    }
    
    // Check for IP address
    const ipMatch = lowerUrl.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/);
    if (ipMatch) {
      suspiciousPatternsFound.push(`IP Address: ${ipMatch[0]}`);
      reasons.push(`Uses IP address instead of domain name`);
      riskScore += 25;
    }
    
    // Calculate final risk score
    riskScore = Math.min(riskScore, 100);
    const isPhishing = riskScore >= 50;
    
    // Generate recommendations
    let recommendations = [];
    if (riskScore >= 70) {
      recommendations = [
        "🚨 DO NOT proceed to this website",
        "📢 Report this URL to phishing databases",
        "🔐 Never enter personal information",
        "📧 If received via email, report as phishing"
      ];
    } else if (riskScore >= 30) {
      recommendations = [
        "⚠️ Be extremely cautious",
        "🔍 Verify the website through official channels",
        "❌ Don't click on suspicious links",
        "📞 Contact the company directly if unsure"
      ];
    } else {
      recommendations = [
        "✅ Website appears safe",
        "🛡️ Always keep your browser updated",
        "🔒 Use additional security tools for protection"
      ];
    }
    
    // Save to database
    const scan = new Scan({
      url, isPhishing, riskScore, reasons,
      suspiciousKeywords: suspiciousKeywordsFound,
      suspiciousPatterns: suspiciousPatternsFound,
      sslStatus, recommendations
    });
    await scan.save();
    
    console.log(`✅ Scan saved: ${url} - Risk: ${riskScore}%`);
    
    // Return response
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
    console.error('Scan error:', error);
    res.status(500).json({ error: 'Failed to scan URL: ' + error.message });
  }
});

// Get scan history
app.get('/api/history', async (req, res) => {
  try {
    const apiKey = req.headers['x-api-key'];
    
    if (apiKey !== process.env.MASTER_API_KEY) {
      return res.status(401).json({ error: 'Invalid API key' });
    }
    
    const scans = await Scan.find().sort({ scannedAt: -1 }).limit(100);
    console.log(`📜 Retrieved ${scans.length} history records`);
    
    res.json({ success: true, history: scans, count: scans.length });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch history' });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'CyberSenseAI API is running',
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'
  });
});

// Delete scan history
app.delete('/api/history/:id', async (req, res) => {
  try {
    const apiKey = req.headers['x-api-key'];
    
    if (apiKey !== process.env.MASTER_API_KEY) {
      return res.status(401).json({ error: 'Invalid API key' });
    }
    
    const { id } = req.params;
    
    if (id === 'all') {
      await Scan.deleteMany({});
      res.json({ success: true, message: 'All history cleared' });
    } else {
      await Scan.findByIdAndDelete(id);
      res.json({ success: true, message: 'Entry deleted' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete' });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📡 Health check: http://localhost:${PORT}/health`);
  console.log(`🔑 API Key required: X-API-Key: ${process.env.MASTER_API_KEY}`);
});