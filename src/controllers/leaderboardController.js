const User = require('../models/User');
const { getCache, setCache } = require('../config/redis');

exports.getGlobalLeaderboard = async (req, res) => {
    try {
        const { limit = 50, type = 'xp' } = req.query;
        
        const cached = await getCache(`leaderboard:${type}:${limit}`);
        if (cached) {
            return res.json({ success: true, leaderboard: cached });
        }
        
        let sortField = {};
        switch (type) {
            case 'xp':
                sortField = { xp: -1 };
                break;
            case 'scans':
                sortField = { totalScans: -1 };
                break;
            case 'threats':
                sortField = { threatsBlocked: -1 };
                break;
            case 'reports':
                sortField = { reportsSubmitted: -1 };
                break;
            default:
                sortField = { xp: -1 };
        }
        
        const leaderboard = await User.find({ role: 'user' })
            .select('username xp level totalScans threatsBlocked reportsSubmitted')
            .sort(sortField)
            .limit(parseInt(limit));
        
        // Add rank
        const rankedLeaderboard = leaderboard.map((user, index) => ({
            rank: index + 1,
            ...user.toObject()
        }));
        
        await setCache(`leaderboard:${type}:${limit}`, rankedLeaderboard, 300);
        
        res.json({
            success: true,
            leaderboard: rankedLeaderboard
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

exports.getUserRank = async (req, res) => {
    try {
        const userId = req.user._id;
        
        const count = await User.countDocuments({
            role: 'user',
            xp: { $gt: req.user.xp }
        });
        
        const rank = count + 1;
        
        res.json({
            success: true,
            rank,
            totalUsers: await User.countDocuments({ role: 'user' })
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};