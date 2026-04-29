const authService = require('../services/authService');
const User = require('../models/User');

exports.register = async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }
        
        const result = await authService.register({ username, email, password });
        
        res.json({
            success: true,
            message: 'Registration successful',
            ...result
        });
        
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
};

exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }
        
        const result = await authService.login(email, password);
        
        res.json({
            success: true,
            message: 'Login successful',
            ...result
        });
        
    } catch (error) {
        res.status(401).json({ error: error.message });
    }
};

exports.getProfile = async (req, res) => {
    try {
        const user = await authService.getUserById(req.user._id);
        
        res.json({
            success: true,
            user
        });
        
    } catch (error) {
        res.status(404).json({ error: error.message });
    }
};

exports.updateProfile = async (req, res) => {
    try {
        const updates = req.body;
        delete updates.password; // Don't allow password update here
        
        const user = await User.findByIdAndUpdate(
            req.user._id,
            { $set: updates },
            { new: true }
        ).select('-password');
        
        res.json({
            success: true,
            user
        });
        
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
};