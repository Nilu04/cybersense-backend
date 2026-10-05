const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        minlength: 3,
        maxlength: 30
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    password: {
        type: String,
        required: true,
        minlength: 6
    },
    apiKey: {
        type: String,
        unique: true
    },
    role: {
        type: String,
        enum: ['user', 'admin', 'moderator'],
        default: 'user'
    },
    level: {
        type: Number,
        default: 1
    },
    xp: {
        type: Number,
        default: 0
    },
    totalScans: {
        type: Number,
        default: 0
    },
    threatsBlocked: {
        type: Number,
        default: 0
    },
    reportsSubmitted: {
        type: Number,
        default: 0
    },
    streak: {
        type: Number,
        default: 0
    },
    lastActive: {
        type: Date,
        default: Date.now
    },
    emailVerified: {
        type: Boolean,
        default: false
    },
    notificationPreferences: {
        email: { type: Boolean, default: true },
        push: { type: Boolean, default: true }
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    lastLogin: Date
});

// Hash password before saving
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 10);
    next();
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

// Generate API key
userSchema.methods.generateApiKey = function() {
    const crypto = require('crypto');
    this.apiKey = 'cyber_' + crypto.randomBytes(16).toString('hex');
    return this.apiKey;
};

module.exports = mongoose.model('User', userSchema);