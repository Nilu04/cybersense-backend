const rateLimit = require('express-rate-limit');

// General API rate limit
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false
});

// Stricter limit for auth endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Too many login attempts, please try again later.' }
});

// Scan endpoint limit
const scanLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 30, // 30 scans per minute
    message: { error: 'Scan limit reached. Please wait a moment.' }
});

module.exports = { apiLimiter, authLimiter, scanLimiter };