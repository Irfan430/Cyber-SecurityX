/**
 * AI-Powered Cybersecurity Risk Simulation Platform
 * Backend API Service
 * Author: IRFAN AHMMED
 */

require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');

// Import custom modules
const logger = require('./config/logger');
const connectDB = require('./config/database');
const connectRedis = require('./config/redis');
const { errorHandler, notFound } = require('./middleware/errorMiddleware');
const { securityMiddleware } = require('./middleware/security');
const socketHandler = require('./services/socketService');

// Import routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const targetRoutes = require('./routes/targets');
const scanRoutes = require('./routes/scans');
const reportRoutes = require('./routes/reports');
const dashboardRoutes = require('./routes/dashboard');
const billingRoutes = require('./routes/billing');
const alertRoutes = require('./routes/alerts');
const trainingRoutes = require('./routes/training');
const webhookRoutes = require('./routes/webhooks');

// Initialize Express app
const app = express();
const server = http.createServer(app);

// Socket.IO setup with CORS
const io = socketIo(server, {
  cors: {
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    methods: ["GET", "POST"],
    credentials: true
  }
});

// Connect to databases
connectDB();
connectRedis();

// Security middleware
app.use(helmet({
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(limiter);

// CORS configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:3000",
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Sanitize user input
app.use(mongoSanitize());

// Compression middleware
app.use(compression());

// Logging middleware
app.use(morgan('combined', {
  stream: {
    write: (message) => logger.info(message.trim())
  }
}));

// Custom security middleware
app.use(securityMiddleware);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV,
    version: process.env.npm_package_version || '1.0.0'
  });
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/targets', targetRoutes);
app.use('/api/scans', scanRoutes);
app.use('/api/reports', reportRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/billing', billingRoutes);
app.use('/api/alerts', alertRoutes);
app.use('/api/training', trainingRoutes);
app.use('/api/webhooks', webhookRoutes);

// Socket.IO handler
socketHandler(io);

// Error handling middleware
app.use(notFound);
app.use(errorHandler);

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  server.close(() => {
    logger.info('Process terminated');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  server.close(() => {
    logger.info('Process terminated');
    process.exit(0);
  });
});

// Uncaught exception handler
process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception:', err);
  process.exit(1);
});

// Unhandled rejection handler
process.on('unhandledRejection', (err) => {
  logger.error('Unhandled Rejection:', err);
  server.close(() => {
    process.exit(1);
  });
});

// Start server
const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  logger.info(`🚀 Cybersecurity Platform Backend running on port ${PORT}`);
  logger.info(`📊 Environment: ${process.env.NODE_ENV}`);
  logger.info(`🔗 Socket.IO enabled for real-time communication`);
});

module.exports = { app, server, io };