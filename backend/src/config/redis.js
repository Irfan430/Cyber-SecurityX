/**
 * Redis Configuration
 * Handles connection to Redis for caching, sessions, and job queues
 */

const Redis = require('ioredis');
const { logger } = require('./logger');

// Redis configuration options
const redisOptions = {
  host: process.env.REDIS_HOST || 'localhost',
  port: process.env.REDIS_PORT || 6379,
  password: process.env.REDIS_PASSWORD || '',
  db: process.env.REDIS_DB || 0,
  
  // Connection settings
  connectTimeout: 10000,
  commandTimeout: 5000,
  retryDelayOnFailover: 100,
  maxRetriesPerRequest: 3,
  
  // Reconnection settings
  retryDelayOnClusterDown: 300,
  retryDelayOnRequestTimeout: 300,
  maxRetriesPerRequest: null,
  
  // Pooling settings
  family: 4,
  keepAlive: true,
  
  // TLS for production
  ...(process.env.NODE_ENV === 'production' && process.env.REDIS_TLS === 'true' ? {
    tls: {
      rejectUnauthorized: false
    }
  } : {}),
  
  // Retry strategy
  retryStrategy: (times) => {
    const delay = Math.min(times * 50, 2000);
    logger.warn(`🔄 Redis retry attempt ${times}, delay: ${delay}ms`);
    return delay;
  }
};

// Create Redis clients
let redisClient = null;
let redisSubscriber = null;
let redisPublisher = null;

/**
 * Connect to Redis
 */
const connectRedis = async () => {
  try {
    logger.info('🔗 Connecting to Redis...');
    
    // Parse Redis URL if provided
    if (process.env.REDIS_URL) {
      redisClient = new Redis(process.env.REDIS_URL, {
        ...redisOptions,
        maxRetriesPerRequest: 3
      });
    } else {
      redisClient = new Redis(redisOptions);
    }
    
    // Create separate clients for pub/sub
    redisSubscriber = redisClient.duplicate();
    redisPublisher = redisClient.duplicate();
    
    // Event handlers for main client
    redisClient.on('connect', () => {
      logger.info('✅ Redis client connected');
    });
    
    redisClient.on('ready', () => {
      logger.info('🚀 Redis client ready');
    });
    
    redisClient.on('error', (err) => {
      logger.error('❌ Redis client error:', err);
    });
    
    redisClient.on('close', () => {
      logger.warn('⚠️ Redis client connection closed');
    });
    
    redisClient.on('reconnecting', (ms) => {
      logger.info(`🔄 Redis client reconnecting in ${ms}ms`);
    });
    
    // Event handlers for subscriber
    redisSubscriber.on('connect', () => {
      logger.info('✅ Redis subscriber connected');
    });
    
    redisSubscriber.on('error', (err) => {
      logger.error('❌ Redis subscriber error:', err);
    });
    
    // Event handlers for publisher
    redisPublisher.on('connect', () => {
      logger.info('✅ Redis publisher connected');
    });
    
    redisPublisher.on('error', (err) => {
      logger.error('❌ Redis publisher error:', err);
    });
    
    // Test connection
    await redisClient.ping();
    logger.info('🏓 Redis ping successful');
    
    // Initialize Redis data structures
    await initializeRedisStructures();
    
  } catch (error) {
    logger.error('❌ Redis connection failed:', error);
    throw error;
  }
};

/**
 * Initialize Redis data structures
 */
const initializeRedisStructures = async () => {
  try {
    // Set up default keys with expiration
    await redisClient.setex('app:startup', 3600, new Date().toISOString());
    
    // Initialize scan queues
    await redisClient.del('scan:queue:pending');
    await redisClient.del('scan:queue:processing');
    
    // Initialize rate limiting counters
    const rateLimitKey = 'rate_limit:global';
    await redisClient.setex(rateLimitKey, 3600, '0');
    
    logger.info('📊 Redis data structures initialized');
  } catch (error) {
    logger.error('❌ Error initializing Redis structures:', error);
  }
};

/**
 * Get Redis client instances
 */
const getRedisClients = () => {
  return {
    client: redisClient,
    subscriber: redisSubscriber,
    publisher: redisPublisher
  };
};

/**
 * Redis health check
 */
const healthCheck = async () => {
  try {
    const start = Date.now();
    await redisClient.ping();
    const responseTime = Date.now() - start;
    
    const info = await redisClient.info('server');
    const memoryInfo = await redisClient.info('memory');
    
    return {
      status: 'healthy',
      responseTime: `${responseTime}ms`,
      info: {
        server: info,
        memory: memoryInfo
      },
      timestamp: new Date().toISOString()
    };
  } catch (error) {
    logger.error('❌ Redis health check failed:', error);
    return {
      status: 'unhealthy',
      error: error.message,
      timestamp: new Date().toISOString()
    };
  }
};

/**
 * Cache helper functions
 */
const cache = {
  /**
   * Get value from cache
   */
  get: async (key) => {
    try {
      const value = await redisClient.get(key);
      return value ? JSON.parse(value) : null;
    } catch (error) {
      logger.error(`❌ Cache get error for key ${key}:`, error);
      return null;
    }
  },

  /**
   * Set value in cache with optional expiration
   */
  set: async (key, value, expirationInSeconds = 3600) => {
    try {
      const serializedValue = JSON.stringify(value);
      await redisClient.setex(key, expirationInSeconds, serializedValue);
      return true;
    } catch (error) {
      logger.error(`❌ Cache set error for key ${key}:`, error);
      return false;
    }
  },

  /**
   * Delete value from cache
   */
  del: async (key) => {
    try {
      await redisClient.del(key);
      return true;
    } catch (error) {
      logger.error(`❌ Cache delete error for key ${key}:`, error);
      return false;
    }
  },

  /**
   * Check if key exists
   */
  exists: async (key) => {
    try {
      const result = await redisClient.exists(key);
      return result === 1;
    } catch (error) {
      logger.error(`❌ Cache exists error for key ${key}:`, error);
      return false;
    }
  },

  /**
   * Set expiration for key
   */
  expire: async (key, seconds) => {
    try {
      await redisClient.expire(key, seconds);
      return true;
    } catch (error) {
      logger.error(`❌ Cache expire error for key ${key}:`, error);
      return false;
    }
  }
};

/**
 * Queue helper functions for scan jobs
 */
const queue = {
  /**
   * Add job to queue
   */
  add: async (queueName, jobData, priority = 0) => {
    try {
      const job = {
        id: require('uuid').v4(),
        data: jobData,
        priority,
        createdAt: new Date().toISOString(),
        status: 'pending'
      };
      
      await redisClient.zadd(`queue:${queueName}`, priority, JSON.stringify(job));
      await redisPublisher.publish(`queue:${queueName}:new`, JSON.stringify(job));
      
      return job.id;
    } catch (error) {
      logger.error(`❌ Queue add error for ${queueName}:`, error);
      throw error;
    }
  },

  /**
   * Get next job from queue
   */
  get: async (queueName) => {
    try {
      const result = await redisClient.zpopmax(`queue:${queueName}`);
      if (result.length === 0) return null;
      
      const job = JSON.parse(result[0]);
      job.status = 'processing';
      job.startedAt = new Date().toISOString();
      
      // Move to processing queue
      await redisClient.setex(`processing:${job.id}`, 3600, JSON.stringify(job));
      
      return job;
    } catch (error) {
      logger.error(`❌ Queue get error for ${queueName}:`, error);
      return null;
    }
  },

  /**
   * Complete job
   */
  complete: async (jobId, result = null) => {
    try {
      await redisClient.del(`processing:${jobId}`);
      if (result) {
        await redisClient.setex(`completed:${jobId}`, 86400, JSON.stringify(result));
      }
      return true;
    } catch (error) {
      logger.error(`❌ Queue complete error for job ${jobId}:`, error);
      return false;
    }
  },

  /**
   * Fail job
   */
  fail: async (jobId, error) => {
    try {
      const failedJob = {
        jobId,
        error: error.message,
        failedAt: new Date().toISOString()
      };
      
      await redisClient.del(`processing:${jobId}`);
      await redisClient.setex(`failed:${jobId}`, 86400, JSON.stringify(failedJob));
      
      return true;
    } catch (err) {
      logger.error(`❌ Queue fail error for job ${jobId}:`, err);
      return false;
    }
  }
};

/**
 * Graceful shutdown
 */
const shutdown = async () => {
  try {
    logger.info('🔒 Closing Redis connections...');
    
    if (redisClient) await redisClient.quit();
    if (redisSubscriber) await redisSubscriber.quit();
    if (redisPublisher) await redisPublisher.quit();
    
    logger.info('✅ Redis connections closed');
  } catch (error) {
    logger.error('❌ Error closing Redis connections:', error);
  }
};

// Handle process termination
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

module.exports = {
  connectRedis,
  getRedisClients,
  healthCheck,
  cache,
  queue,
  shutdown
};