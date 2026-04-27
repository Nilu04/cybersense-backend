const mongoose = require('mongoose');

const uri = 'mongodb+srv://cybersense_user:CyberSense2026@cybersenseai.1uxxd9u.mongodb.net/?retryWrites=true&w=majority';

console.log('🔄 Testing MongoDB connection...');

mongoose.connect(uri)
  .then(() => {
    console.log('✅ SUCCESS! Connected to MongoDB!');
    console.log('📊 Host:', mongoose.connection.host);
    process.exit(0);
  })
  .catch(err => {
    console.log('❌ FAILED:', err.message);
    process.exit(1);
  });