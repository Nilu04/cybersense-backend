const mongoose = require('mongoose');

const scanHistorySchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    url: {
        type: String,
        required: true
    },
    isPhishing: {
        type: Boolean,
        default: false
    },
    riskScore: {
        type: Number,
        min: 0,
        max: 100
    },
    reasons: [String],
    suspiciousKeywords: [String],
    suspiciousPatterns: [String],
    sslStatus: String,
    recommendations: [String],
    status: {
        type: String,
        enum: ['safe', 'suspicious', 'phishing', 'blocked'],
        default: 'safe'
    },
    scannedAt: {
        type: Date,
        default: Date.now
    }
});

scanHistorySchema.index({ userId: 1, scannedAt: -1 });

module.exports = mongoose.model('ScanHistory', scanHistorySchema);