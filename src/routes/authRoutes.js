const express = require('express');
const router = express.Router();

// Simple placeholder - you can expand later
router.post('/register', (req, res) => {
    res.json({ message: 'Register endpoint - to be implemented' });
});

router.post('/login', (req, res) => {
    res.json({ message: 'Login endpoint - to be implemented' });
});

module.exports = router;