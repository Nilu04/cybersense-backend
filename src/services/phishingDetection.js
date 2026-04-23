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

    async scanUrl(url, apiKey) {
        const results = {
            isPhishing: false,
            riskScore: 0,
            reasons: []
        };

        // 1. Local pattern matching
        const localResult = this.localScan(url);
        results.reasons.push(...localResult.reasons);
        
        if (localResult.isPhishing) {
            results.isPhishing = true;
            results.riskScore += 60;
        }

        // 2. Google Safe Browsing API (if API key available)
        if (process.env.GOOGLE_SAFE_BROWSING_API_KEY) {
            const googleResult = await this.googleSafeBrowsingScan(url);
            if (googleResult.isPhishing) {
                results.isPhishing = true;
                results.riskScore += 30;
                results.reasons.push('• Flagged by Google Safe Browsing');
            }
        }

        // Calculate final risk score
        results.riskScore = Math.min(results.riskScore + localResult.riskScore, 100);
        
        return results;
    }

    localScan(url) {
        const lowerUrl = url.toLowerCase();
        const reasons = [];
        let riskScore = 0;

        // Check for suspicious keywords
        for (const keyword of this.suspiciousKeywords) {
            if (lowerUrl.includes(keyword)) {
                reasons.push(`• Contains suspicious keyword: ${keyword}`);
                riskScore += 10;
            }
        }

        // Check for suspicious domains
        for (const domain of this.suspiciousDomains) {
            if (lowerUrl.includes(domain)) {
                reasons.push(`• Suspicious domain pattern: ${domain}`);
                riskScore += 20;
            }
        }

        // Check for HTTP
        if (lowerUrl.startsWith('http://')) {
            reasons.push('• Uses HTTP (not secure)');
            riskScore += 15;
        }

        // Check for IP address
        if (lowerUrl.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) {
            reasons.push('• Uses IP address instead of domain name');
            riskScore += 25;
        }

        return {
            isPhishing: riskScore >= 50,
            riskScore: Math.min(riskScore, 100),
            reasons
        };
    }

    async googleSafeBrowsingScan(url) {
        try {
            const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
            const response = await axios.post(
                `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
                {
                    client: {
                        clientId: "cybersenseai",
                        clientVersion: "1.0.0"
                    },
                    threatInfo: {
                        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                        platformTypes: ["ANY_PLATFORM"],
                        threatEntryTypes: ["URL"],
                        threatEntries: [{ url: url }]
                    }
                }
            );
            
            return {
                isPhishing: response.data.matches && response.data.matches.length > 0
            };
        } catch (error) {
            console.error('Google Safe Browsing API error:', error.message);
            return { isPhishing: false };
        }
    }
}

module.exports = new PhishingDetectionService();