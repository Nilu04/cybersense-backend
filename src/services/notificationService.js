const Notification = require('../models/Notification');
const User = require('../models/User');
const nodemailer = require('nodemailer');
const { getCache, setCache } = require('../config/redis');

class NotificationService {
    constructor() {
        this.setupEmailTransporter();
    }
    
    setupEmailTransporter() {
        if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
            this.transporter = nodemailer.createTransport({
                host: process.env.EMAIL_HOST,
                port: process.env.EMAIL_PORT,
                secure: false,
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS
                }
            });
        }
    }
    
    // Create and send notification
    async createNotification(userId, title, message, type, data = {}) {
        // Save to database
        const notification = new Notification({
            userId,
            title,
            message,
            type,
            data
        });
        
        await notification.save();
        
        // Get user preferences
        const user = await User.findById(userId);
        
        // Send email if enabled
        if (user.notificationPreferences?.email && this.transporter) {
            await this.sendEmail(user.email, title, message);
        }
        
        return notification;
    }
    
    // Send email
    async sendEmail(to, subject, text) {
        if (!this.transporter) return;
        
        try {
            await this.transporter.sendMail({
                from: `"CyberSenseAI" <${process.env.EMAIL_USER}>`,
                to,
                subject: `🔐 CyberSenseAI: ${subject}`,
                text,
                html: `<div style="font-family: Arial; padding: 20px;">
                    <h2>🛡️ CyberSenseAI Security Alert</h2>
                    <p>${text}</p>
                    <hr>
                    <p style="font-size: 12px;">Stay safe online!</p>
                </div>`
            });
        } catch (error) {
            console.error('Email send error:', error.message);
        }
    }
    
    // Get user notifications
    async getUserNotifications(userId, limit = 50, offset = 0) {
        const notifications = await Notification.find({ userId })
            .sort({ createdAt: -1 })
            .skip(offset)
            .limit(limit);
        
        const unreadCount = await Notification.countDocuments({ userId, isRead: false });
        
        return { notifications, unreadCount, total: notifications.length };
    }
    
    // Mark notification as read
    async markAsRead(notificationId, userId) {
        await Notification.findOneAndUpdate(
            { _id: notificationId, userId },
            { isRead: true }
        );
    }
    
    // Mark all as read
    async markAllAsRead(userId) {
        await Notification.updateMany({ userId, isRead: false }, { isRead: true });
    }
    
    // Send security alert
    async sendSecurityAlert(userId, url, riskScore) {
        const title = '⚠️ Phishing Alert!';
        const message = `We detected a suspicious URL: ${url}\nRisk Score: ${riskScore}%\nDo not proceed to this website.`;
        
        await this.createNotification(userId, title, message, 'alert', { url, riskScore });
    }
    
    // Send achievement notification
    async sendAchievement(userId, achievementName) {
        const title = '🏆 Achievement Unlocked!';
        const message = `Congratulations! You've earned "${achievementName}" achievement!`;
        
        await this.createNotification(userId, title, message, 'achievement', { achievement: achievementName });
    }
}

module.exports = new NotificationService();