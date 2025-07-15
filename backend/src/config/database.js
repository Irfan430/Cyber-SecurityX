/**
 * MongoDB Database Configuration
 * Handles connection to MongoDB with error handling and reconnection logic
 */

const mongoose = require('mongoose');
const { logger } = require('./logger');

// MongoDB connection options
const mongoOptions = {
  // Use new URL parser
  useNewUrlParser: true,
  useUnifiedTopology: true,
  
  // Connection pool settings
  maxPoolSize: 10, // Maintain up to 10 socket connections
  serverSelectionTimeoutMS: 5000, // Keep trying to send operations for 5 seconds
  socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
  bufferMaxEntries: 0, // Disable mongoose buffering
  
  // Authentication settings
  authSource: 'admin',
  
  // SSL settings for production
  ssl: process.env.NODE_ENV === 'production',
  sslValidate: process.env.NODE_ENV === 'production',
  
  // Replica set settings (if applicable)
  retryWrites: true,
  writeConcern: {
    w: 'majority',
    j: true
  }
};

/**
 * Connect to MongoDB
 */
const connectDB = async () => {
  try {
    // MongoDB connection URI
    const mongoURI = process.env.MONGODB_URI || 'mongodb://localhost:27017/cybersec_platform';
    
    logger.info('🔗 Connecting to MongoDB...');
    
    // Connect to MongoDB
    const conn = await mongoose.connect(mongoURI, mongoOptions);
    
    logger.info(`✅ MongoDB Connected: ${conn.connection.host}:${conn.connection.port}`);
    logger.info(`📊 Database: ${conn.connection.name}`);
    
    // Handle connection events
    mongoose.connection.on('connected', () => {
      logger.info('📡 Mongoose connected to MongoDB');
    });
    
    mongoose.connection.on('error', (err) => {
      logger.error('❌ Mongoose connection error:', err);
    });
    
    mongoose.connection.on('disconnected', () => {
      logger.warn('⚠️ Mongoose disconnected from MongoDB');
    });
    
    // Handle application termination
    process.on('SIGINT', async () => {
      try {
        await mongoose.connection.close();
        logger.info('🔒 Mongoose connection closed through app termination');
        process.exit(0);
      } catch (err) {
        logger.error('❌ Error closing mongoose connection:', err);
        process.exit(1);
      }
    });
    
  } catch (error) {
    logger.error('❌ MongoDB connection failed:', error);
    
    // Exit process with failure
    process.exit(1);
  }
};

/**
 * Get database connection status
 */
const getConnectionStatus = () => {
  const states = {
    0: 'disconnected',
    1: 'connected',
    2: 'connecting',
    3: 'disconnecting',
    99: 'uninitialized'
  };
  
  return {
    state: states[mongoose.connection.readyState],
    host: mongoose.connection.host,
    port: mongoose.connection.port,
    name: mongoose.connection.name,
    collections: Object.keys(mongoose.connection.collections)
  };
};

/**
 * Database health check
 */
const healthCheck = async () => {
  try {
    const adminDb = mongoose.connection.db.admin();
    const result = await adminDb.ping();
    
    return {
      status: 'healthy',
      ping: result,
      connection: getConnectionStatus(),
      timestamp: new Date().toISOString()
    };
  } catch (error) {
    logger.error('❌ Database health check failed:', error);
    return {
      status: 'unhealthy',
      error: error.message,
      connection: getConnectionStatus(),
      timestamp: new Date().toISOString()
    };
  }
};

/**
 * Create database indexes for performance
 */
const createIndexes = async () => {
  try {
    logger.info('📊 Creating database indexes...');
    
    // User indexes
    await mongoose.connection.collection('users').createIndex({ email: 1 }, { unique: true });
    await mongoose.connection.collection('users').createIndex({ organization: 1 });
    await mongoose.connection.collection('users').createIndex({ role: 1 });
    await mongoose.connection.collection('users').createIndex({ createdAt: -1 });
    
    // Target indexes
    await mongoose.connection.collection('targets').createIndex({ userId: 1 });
    await mongoose.connection.collection('targets').createIndex({ type: 1 });
    await mongoose.connection.collection('targets').createIndex({ value: 1 });
    await mongoose.connection.collection('targets').createIndex({ 'tags': 1 });
    
    // Scan indexes
    await mongoose.connection.collection('scans').createIndex({ userId: 1 });
    await mongoose.connection.collection('scans').createIndex({ targetId: 1 });
    await mongoose.connection.collection('scans').createIndex({ status: 1 });
    await mongoose.connection.collection('scans').createIndex({ createdAt: -1 });
    await mongoose.connection.collection('scans').createIndex({ 'results.riskScore': -1 });
    
    // Report indexes
    await mongoose.connection.collection('reports').createIndex({ userId: 1 });
    await mongoose.connection.collection('reports').createIndex({ scanId: 1 });
    await mongoose.connection.collection('reports').createIndex({ createdAt: -1 });
    
    // Billing indexes
    await mongoose.connection.collection('subscriptions').createIndex({ userId: 1 }, { unique: true });
    await mongoose.connection.collection('subscriptions').createIndex({ status: 1 });
    await mongoose.connection.collection('subscriptions').createIndex({ expiresAt: 1 });
    
    logger.info('✅ Database indexes created successfully');
  } catch (error) {
    logger.error('❌ Error creating database indexes:', error);
  }
};

module.exports = {
  connectDB,
  getConnectionStatus,
  healthCheck,
  createIndexes
};