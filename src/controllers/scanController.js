const phishingDetection = require('../services/phishingDetection');
const ScanHistory = require('../models/ScanHistory');
const User = require('../models/User');

const scanUrl = async (req, res) => {
    try {
        const { url } = req.body;
        const userId = req.user?._id;

        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }

        // Perform phishing detection
        const scanResult = await phishingDetection.scanUrl(url);

        // Save to history if user is logged in
        if (userId) {
            const history = new ScanHistory({
                userId,
                url,
                isPhishing: scanResult.isPhishing,
                riskScore: scanResult.riskScore,
                reasons: scanResult.reasons,
                status: scanResult.riskScore >= 70 ? 'phishing' : 
                        scanResult.riskScore >= 30 ? 'suspicious' : 'safe'
            });
            await history.save();

            // Update user stats
            await User.findByIdAndUpdate(userId, {
                $inc: { 
                    totalScans: 1,
                    threatsBlocked: scanResult.isPhishing ? 1 : 0
                }
            });
        }

        res.json({
            success: true,
            url,
            isPhishing: scanResult.isPhishing,
            riskScore: scanResult.riskScore,
            reasons: scanResult.reasons,
            timestamp: new Date()
        });
    } catch (error) {
        console.error('Scan error:', error);
        res.status(500).json({ error: 'Failed to scan URL' });
    }
};

const getScanHistory = async (req, res) => {
    try {
        const history = await ScanHistory.find({ userId: req.user._id })
            .sort({ scannedAt: -1 })
            .limit(50);
        
        res.json({ success: true, history });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch history' });
    }
};

module.exports = { scanUrl, getScanHistory };