const mongoose = require('mongoose');

const leaderboardSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        unique: true
    },
    username: String,
    totalScans: {
        type: Number,
        default: 0
    },
    threatsBlocked: {
        type: Number,
        default: 0
    },
    xp: {
        type: Number,
        default: 0
    },
    level: {
        type: Number,
        default: 1
    },
    reportsSubmitted: {
        type: Number,
        default: 0
    },
    accuracy: {
        type: Number,
        default: 0
    },
    rank: {
        type: Number,
        default: 0
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

leaderboardSchema.index({ xp: -1 });
leaderboardSchema.index({ threatsBlocked: -1 });

module.exports = mongoose.model('Leaderboard', leaderboardSchema);