const jwt = require('jsonwebtoken');
const User = require('../models/User');

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
    
    if (!apiKey) {
        return res.status(401).json({ error: 'API key required' });
    }

    if (apiKey === process.env.MASTER_API_KEY) {
        req.isMasterKey = true;
        return next();
    }

    const user = await User.findOne({ apiKey });
    if (!user) {
        return res.status(401).json({ error: 'Invalid API key' });
    }

    req.user = user;
    next();
};

module.exports = { authenticate, verifyApiKey };