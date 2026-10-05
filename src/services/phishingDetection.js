const axios = require('axios');

class PhishingDetectionService {
    constructor() {
        this.suspiciousKeywords = [
            'secure', 'verify', 'account', 'login', 'update', 'confirm',
            'alert', 'suspicious', 'unusual', 'urgent', 'paypal',
            'bank', 'amazon', 'apple', 'netflix', 'microsoft'
        ];
        
        this.suspiciousDomains = [
            'paypa1', 'amaz0n', 'appIe', 'micr0soft',
            '.xyz', '.top', '.club', '.work', '.click', '.tk', '.ml'
        ];
    }

    async scanUrl(url) {
        const results = {
            isPhishing: false,
            riskScore: 0,
            reasons: [],
            suspiciousKeywords: [],
            suspiciousPatterns: [],
            sslStatus: "unknown",
            recommendations: []
        };

        const lowerUrl = url.toLowerCase();
        
        // Check keywords
        for (const keyword of this.suspiciousKeywords) {
            if (lowerUrl.includes(keyword)) {
                results.suspiciousKeywords.push(keyword);
                results.reasons.push(`• Contains suspicious keyword: ${keyword}`);
                results.riskScore += 10;
            }
        }

        // Check domains
        for (const domain of this.suspiciousDomains) {
            if (lowerUrl.includes(domain)) {
                results.suspiciousPatterns.push(domain);
                results.reasons.push(`• Suspicious domain pattern: ${domain}`);
                results.riskScore += 20;
            }
        }

        // Check HTTP
        if (lowerUrl.startsWith('http://')) {
            results.sslStatus = "insecure";
            results.reasons.push('• Uses HTTP (not secure)');
            results.riskScore += 15;
        } else if (lowerUrl.startsWith('https://')) {
            results.sslStatus = "secure";
        }

        // Check IP address
        const ipMatch = lowerUrl.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/);
        if (ipMatch) {
            results.suspiciousPatterns.push(`IP Address: ${ipMatch[0]}`);
            results.reasons.push(`• Uses IP address instead of domain name`);
            results.riskScore += 25;
        }

        // Recommendations
        if (results.riskScore >= 70) {
            results.recommendations = [
                "🚨 DO NOT proceed to this website",
                "📢 Report this URL to phishing databases",
                "🔐 Never enter personal information"
            ];
        } else if (results.riskScore >= 30) {
            results.recommendations = [
                "⚠️ Be extremely cautious",
                "🔍 Verify the website through official channels",
                "❌ Don't click on suspicious links"
            ];
        } else {
            results.recommendations = [
                "✅ Website appears safe",
                "🛡️ Always keep your browser updated"
            ];
        }
        
        results.riskScore = Math.min(results.riskScore, 100);
        results.isPhishing = results.riskScore >= 50;

        return results;
    }
}

module.exports = new PhishingDetectionService();