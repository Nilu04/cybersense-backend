const redis = require('redis');

let redisClient = null;

const connectRedis = async () => {
    try {
        redisClient = redis.createClient({
            url: process.env.REDIS_URL || 'redis://localhost:6379'
        });
        
        redisClient.on('error', (err) => console.log('Redis Client Error', err));
        redisClient.on('connect', () => console.log('✅ Redis Connected'));
        
        await redisClient.connect();
        return redisClient;
        
    } catch (error) {
        console.log('⚠️ Redis not available, using memory cache');
        return null;
    }
};

// Cache helper functions
const getCache = async (key) => {
    if (!redisClient) return null;
    const data = await redisClient.get(key);
    return data ? JSON.parse(data) : null;
};

const setCache = async (key, data, ttl = 3600) => {
    if (!redisClient) return;
    await redisClient.setEx(key, ttl, JSON.stringify(data));
};

const deleteCache = async (pattern) => {
    if (!redisClient) return;
    const keys = await redisClient.keys(pattern);
    if (keys.length) await redisClient.del(keys);
};

module.exports = { connectRedis, getCache, setCache, deleteCache };