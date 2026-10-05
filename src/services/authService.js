const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { setCache, getCache } = require('../config/redis');

class AuthService {
    // Register new user
    async register(userData) {
        const { username, email, password } = userData;
        
        // Check if user exists
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            throw new Error('User already exists');
        }
        
        // Create user
        const user = new User({
            username,
            email,
            password
        });
        
        user.generateApiKey();
        await user.save();
        
        // Generate token
        const token = this.generateToken(user._id);
        
        // Cache user data
        await setCache(`user:${user._id}`, {
            id: user._id,
            username: user.username,
            email: user.email,
            level: user.level,
            xp: user.xp
        }, 3600);
        
        return {
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                apiKey: user.apiKey,
                level: user.level,
                xp: user.xp
            }
        };
    }
    
    // Login user
    async login(email, password) {
        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            throw new Error('Invalid credentials');
        }
        
        // Check password
        const isValid = await user.comparePassword(password);
        if (!isValid) {
            throw new Error('Invalid credentials');
        }
        
        // Update last login
        user.lastLogin = new Date();
        await user.save();
        
        // Generate token
        const token = this.generateToken(user._id);
        
        return {
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                apiKey: user.apiKey,
                level: user.level,
                xp: user.xp
            }
        };
    }
    
    // Verify token
    verifyToken(token) {
        try {
            return jwt.verify(token, process.env.JWT_SECRET);
        } catch (error) {
            throw new Error('Invalid token');
        }
    }
    
    // Generate JWT token
    generateToken(userId) {
        return jwt.sign({ userId }, process.env.JWT_SECRET, {
            expiresIn: process.env.JWT_EXPIRES_IN || '7d'
        });
    }
    
    // Get user by ID
    async getUserById(userId) {
        // Try cache first
        const cached = await getCache(`user:${userId}`);
        if (cached) return cached;
        
        const user = await User.findById(userId).select('-password');
        if (!user) throw new Error('User not found');
        
        await setCache(`user:${userId}`, user, 3600);
        return user;
    }
    
    // Update user stats
    async updateStats(userId, stats) {
        const user = await User.findByIdAndUpdate(userId, stats, { new: true });
        await setCache(`user:${userId}`, user, 3600);
        return user;
    }
}

module.exports = new AuthService();