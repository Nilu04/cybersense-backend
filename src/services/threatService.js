const Report = require('../models/Report');
const ScanHistory = require('../models/ScanHistory');
const User = require('../models/User');
const { getCache, setCache, deleteCache } = require('../config/redis');
const { sendToQueue } = require('../config/rabbitmq');

class ThreatService {
    // Report a phishing URL
    async reportUrl(userId, url, reason, description) {
        // Check if already reported
        const existing = await Report.findOne({ url, reporterId: userId });
        if (existing) {
            throw new Error('You already reported this URL');
        }
        
        // Create report
        const report = new Report({
            url,
            reporterId: userId,
            reason,
            description,
            status: 'pending'
        });
        
        await report.save();
        
        // Update user stats
        await User.findByIdAndUpdate(userId, {
            $inc: { reportsSubmitted: 1 }
        });
        
        // Check if URL should be auto-blocked
        const reportCount = await Report.countDocuments({ url, status: 'pending' });
        
        if (reportCount >= 5) {
            await this.blockUrl(url);
        }
        
        // Send notification to admins
        await sendToQueue('notification_queue', {
            type: 'new_report',
            data: { url, reportCount, reporterId: userId }
        });
        
        // Clear cache
        await deleteCache(`threats:*`);
        
        return report;
    }
    
    // Block a URL
    async blockUrl(url) {
        await Report.updateMany({ url }, { status: 'blocked', resolvedAt: new Date() });
        
        // Add to blocklist cache
        await setCache(`blocked:${url}`, true, 86400); // 24 hours
        
        // Queue notification to users who scanned this URL
        const scans = await ScanHistory.find({ url }).distinct('userId');
        for (const userId of scans) {
            await sendToQueue('notification_queue', {
                userId,
                type: 'url_blocked',
                data: { url }
            });
        }
    }
    
    // Verify a report (Admin only)
    async verifyReport(reportId, adminId, action) {
        const report = await Report.findById(reportId);
        if (!report) throw new Error('Report not found');
        
        report.status = action === 'verify' ? 'verified' : 'rejected';
        report.verifiedBy = adminId;
        report.resolvedAt = new Date();
        
        if (action === 'verify') {
            await this.blockUrl(report.url);
        }
        
        await report.save();
        
        // Award reporter
        if (action === 'verify') {
            await User.findByIdAndUpdate(report.reporterId, {
                $inc: { xp: 10 }
            });
        }
        
        return report;
    }
    
    // Get threat statistics
    async getThreatStats() {
        const cached = await getCache('threats:stats');
        if (cached) return cached;
        
        const stats = {
            totalReports: await Report.countDocuments(),
            verifiedThreats: await Report.countDocuments({ status: 'verified' }),
            pendingReports: await Report.countDocuments({ status: 'pending' }),
            topReporters: await Report.aggregate([
                { $group: { _id: '$reporterId', count: { $sum: 1 } } },
                { $sort: { count: -1 } },
                { $limit: 10 }
            ]),
            recentThreats: await Report.find({ status: 'verified' })
                .sort({ createdAt: -1 })
                .limit(20)
                .populate('reporterId', 'username')
        };
        
        await setCache('threats:stats', stats, 3600);
        return stats;
    }
}

module.exports = new ThreatService();