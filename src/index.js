const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const dotenv = require('dotenv');

dotenv.config();

<<<<<<< HEAD
const connectDB = require('./config/database');
const authRoutes = require('./routes/authRoutes');
const scanRoutes = require('./routes/scanRoutes');
const historyRoutes = require('./routes/historyRoutes');

const app = express();

// Connect to MongoDB
connectDB();

=======
const app = express();

>>>>>>> ec55c1425bf44efed5417e22245d604dba4d0973
// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(morgan('combined'));

<<<<<<< HEAD
// Routes
app.use('/api/auth', authRoutes);
app.use('/api/scan', scanRoutes);
app.use('/api/history', historyRoutes);

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date(), message: 'CyberSenseAI API is running' });
});

// Error handling
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📡 Health check: http://localhost:${PORT}/health`);
=======
// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'CyberSenseAI Backend is Running!',
        timestamp: new Date() 
    });
});

// Scan endpoint
app.post('/api/scan', (req, res) => {
    const { url } = req.body;
    
    if (!url) {
        return res.status(400).json({ error: 'URL is required' });
    }
    
    // Simple phishing detection
    const suspiciousKeywords = ['secure', 'verify', 'login', 'update', 'confirm'];
    const lowerUrl = url.toLowerCase();
    
    let isPhishing = false;
    let reasons = [];
    let riskScore = 0;
    
    for (const keyword of suspiciousKeywords) {
        if (lowerUrl.includes(keyword)) {
            isPhishing = true;
            reasons.push(`Contains suspicious keyword: ${keyword}`);
            riskScore += 15;
        }
    }
    
    if (lowerUrl.startsWith('http://')) {
        reasons.push('Uses HTTP (not secure)');
        riskScore += 10;
    }
    
    res.json({
        success: true,
        url: url,
        isPhishing: isPhishing,
        riskScore: Math.min(riskScore, 100),
        reasons: reasons,
        timestamp: new Date()
    });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📡 Test API: http://localhost:${PORT}/health`);
>>>>>>> ec55c1425bf44efed5417e22245d604dba4d0973
});