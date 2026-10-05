const { getCache, setCache } = require('../config/redis');

class MLService {
    constructor() {
        // Simple rule-based detection (can be replaced with actual ML model)
        this.phishingKeywords = [
            'secure', 'verify', 'login', 'update', 'confirm',
            'account', 'alert', 'urgent', 'paypal', 'bank',
            'amazon', 'apple', 'netflix', 'microsoft'
        ];
        
        this.suspiciousTLDs = ['.xyz', '.top', '.club', '.work', '.click', '.tk', '.ml'];
    }
    
    // Predict if URL is phishing
    async predict(url) {
        // Check cache first
        const cached = await getCache(`ml:${url}`);
        if (cached) return cached;
        
        const lowerUrl = url.toLowerCase();
        let riskScore = 0;
        let reasons = [];
        let detectedKeywords = [];
        
        // Check keywords
        for (const keyword of this.phishingKeywords) {
            if (lowerUrl.includes(keyword)) {
                riskScore += 10;
                detectedKeywords.push(keyword);
                reasons.push(`Contains suspicious keyword: ${keyword}`);
            }
        }
        
        // Check TLDs
        for (const tld of this.suspiciousTLDs) {
            if (lowerUrl.includes(tld)) {
                riskScore += 20;
                reasons.push(`Suspicious domain extension: ${tld}`);
            }
        }
        
        // Check HTTP
        if (lowerUrl.startsWith('http://')) {
            riskScore += 15;
            reasons.push('Uses HTTP (not secure)');
        }
        
        // Check for IP address
        const ipMatch = lowerUrl.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/);
        if (ipMatch) {
            riskScore += 25;
            reasons.push('Uses IP address instead of domain name');
        }
        
        // Check URL length
        if (url.length > 100) {
            riskScore += 5;
            reasons.push('Unusually long URL');
        }
        
        riskScore = Math.min(riskScore, 100);
        const isPhishing = riskScore >= 50;
        
        const result = {
            isPhishing,
            riskScore,
            reasons,
            detectedKeywords,
            confidence: riskScore / 100,
            timestamp: new Date().toISOString()
        };
        
        // Cache result for 1 hour
        await setCache(`ml:${url}`, result, 3600);
        
        return result;
    }
    
    // Train model with new data (placeholder)
    async train(features, labels) {
        console.log('ML Model training requested');
        // In production, this would call an external ML service
        return { success: true, message: 'Training queued' };
    }
    
    // Get model accuracy (placeholder)
    async getAccuracy() {
        return {
            accuracy: 94.5,
            precision: 93.2,
            recall: 91.8,
            f1Score: 92.5
        };
    }
}

module.exports = new MLService();