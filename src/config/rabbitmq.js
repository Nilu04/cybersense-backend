const amqp = require('amqplib');

let connection = null;
let channel = null;

const connectRabbitMQ = async () => {
    try {
        connection = await amqp.connect(process.env.RABBITMQ_URL || 'amqp://localhost:5672');
        channel = await connection.createChannel();
        
        // Create queues
        await channel.assertQueue('scan_queue', { durable: true });
        await channel.assertQueue('notification_queue', { durable: true });
        await channel.assertQueue('ml_queue', { durable: true });
        await channel.assertQueue('email_queue', { durable: true });
        
        console.log('✅ RabbitMQ Connected');
        return channel;
        
    } catch (error) {
        console.log('⚠️ RabbitMQ not available, using direct processing');
        return null;
    }
};

// Send message to queue
const sendToQueue = async (queue, message) => {
    if (!channel) {
        console.log('RabbitMQ not available, processing directly');
        return null;
    }
    channel.sendToQueue(queue, Buffer.from(JSON.stringify(message)), { persistent: true });
};

// Consume messages from queue
const consumeQueue = async (queue, callback) => {
    if (!channel) return;
    channel.consume(queue, async (msg) => {
        if (msg) {
            const data = JSON.parse(msg.content.toString());
            await callback(data);
            channel.ack(msg);
        }
    });
};

module.exports = { connectRabbitMQ, sendToQueue, consumeQueue };