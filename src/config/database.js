const mongoose = require('mongoose');

const connectDB = async () => {
    try {
        const conn = await mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });

        console.log(`✅ MongoDB Connected: ${conn.connection.host}`);
        console.log(`📊 Database Name: ${conn.connection.name}`);

        // Create indexes after connection
        await createIndexes();

    } catch (error) {
        console.error('❌ MongoDB Connection Error:', error.message);
        process.exit(1);
    }
};

// Create indexes function
const createIndexes = async () => {
    try {
        const User = mongoose.model('User');
        const ScanHistory = mongoose.model('ScanHistory');

        await User.collection.createIndex({ email: 1 }, { unique: true });
        await User.collection.createIndex({ apiKey: 1 });
        await ScanHistory.collection.createIndex({ userId: 1, scannedAt: -1 });
        await ScanHistory.collection.createIndex({ url: 1 });

        console.log('✅ Database indexes created');
    } catch (err) {
        console.error('❌ Index creation error:', err.message);
    }
};

// Monitor connection events
mongoose.connection.on('connected', () => {
    console.log('🔌 Mongoose connected to MongoDB');
});

mongoose.connection.on('error', (err) => {
    console.error('❌ Mongoose connection error:', err);
});

mongoose.connection.on('disconnected', () => {
    console.log('⚠️ Mongoose disconnected');
});

module.exports = connectDB;