const threatService = require('../services/threatService');

exports.reportUrl = async (req, res) => {
    try {
        const { url, reason, description } = req.body;
        
        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }
        
        const report = await threatService.reportUrl(
            req.user._id,
            url,
            reason || 'phishing',
            description || ''
        );
        
        res.json({
            success: true,
            message: 'Report submitted successfully',
            report
        });
        
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
};

exports.getThreatStats = async (req, res) => {
    try {
        const stats = await threatService.getThreatStats();
        
        res.json({
            success: true,
            stats
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

// Admin only
exports.verifyReport = async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }
        
        const { reportId, action } = req.body;
        
        const report = await threatService.verifyReport(reportId, req.user._id, action);
        
        res.json({
            success: true,
            message: `Report ${action}ed successfully`,
            report
        });
        
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
};