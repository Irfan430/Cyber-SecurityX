/**
 * User Model
 * Multi-tenant user system with role-based access control
 */

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const userSchema = new mongoose.Schema({
  // Basic Information
  id: {
    type: String,
    default: uuidv4,
    unique: true,
    index: true
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    index: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: true,
    trim: true,
    minlength: [3, 'Username must be at least 3 characters'],
    maxlength: [30, 'Username cannot exceed 30 characters'],
    match: [/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, underscores, and hyphens']
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters'],
    select: false // Don't include password in queries by default
  },
  
  // Profile Information
  firstName: {
    type: String,
    required: [true, 'First name is required'],
    trim: true,
    maxlength: [50, 'First name cannot exceed 50 characters']
  },
  lastName: {
    type: String,
    required: [true, 'Last name is required'],
    trim: true,
    maxlength: [50, 'Last name cannot exceed 50 characters']
  },
  avatar: {
    type: String,
    default: null
  },
  phone: {
    type: String,
    trim: true,
    match: [/^[\+]?[1-9][\d]{0,15}$/, 'Please enter a valid phone number']
  },
  
  // Organization & Role Management
  organization: {
    type: String,
    required: [true, 'Organization is required'],
    trim: true,
    maxlength: [100, 'Organization name cannot exceed 100 characters'],
    index: true
  },
  organizationId: {
    type: String,
    required: true,
    index: true
  },
  role: {
    type: String,
    required: true,
    enum: ['admin', 'manager', 'viewer'],
    default: 'viewer',
    index: true
  },
  permissions: [{
    type: String,
    enum: [
      'users:read', 'users:write', 'users:delete',
      'targets:read', 'targets:write', 'targets:delete',
      'scans:read', 'scans:write', 'scans:delete',
      'reports:read', 'reports:write', 'reports:delete',
      'billing:read', 'billing:write',
      'settings:read', 'settings:write',
      'analytics:read'
    ]
  }],
  
  // Security Settings
  isActive: {
    type: Boolean,
    default: true,
    index: true
  },
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  isTwoFactorEnabled: {
    type: Boolean,
    default: false
  },
  twoFactorSecret: {
    type: String,
    select: false
  },
  
  // Authentication Tokens
  refreshTokens: [{
    token: String,
    createdAt: {
      type: Date,
      default: Date.now,
      expires: 2592000 // 30 days
    },
    userAgent: String,
    ipAddress: String
  }],
  
  // Password Reset
  resetPasswordToken: {
    type: String,
    select: false
  },
  resetPasswordExpires: {
    type: Date,
    select: false
  },
  
  // Email Verification
  emailVerificationToken: {
    type: String,
    select: false
  },
  emailVerificationExpires: {
    type: Date,
    select: false
  },
  
  // Security Tracking
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: {
    type: Date
  },
  lastLogin: {
    type: Date
  },
  lastLoginIP: {
    type: String
  },
  loginHistory: [{
    timestamp: {
      type: Date,
      default: Date.now
    },
    ipAddress: String,
    userAgent: String,
    success: Boolean,
    failureReason: String
  }],
  
  // Preferences
  preferences: {
    language: {
      type: String,
      default: 'en',
      enum: ['en', 'es', 'fr', 'de', 'it', 'pt', 'ru', 'zh', 'ja', 'ko']
    },
    timezone: {
      type: String,
      default: 'UTC'
    },
    emailNotifications: {
      scanCompleted: { type: Boolean, default: true },
      vulnerabilityFound: { type: Boolean, default: true },
      systemAlerts: { type: Boolean, default: true },
      weeklyReports: { type: Boolean, default: false }
    },
    dashboardLayout: {
      type: String,
      default: 'default',
      enum: ['default', 'compact', 'detailed']
    }
  },
  
  // Subscription & Billing
  subscription: {
    plan: {
      type: String,
      enum: ['free', 'basic', 'premium', 'enterprise'],
      default: 'free'
    },
    status: {
      type: String,
      enum: ['active', 'inactive', 'cancelled', 'past_due'],
      default: 'active'
    },
    stripeCustomerId: String,
    stripeSubscriptionId: String,
    currentPeriodStart: Date,
    currentPeriodEnd: Date,
    cancelAtPeriodEnd: {
      type: Boolean,
      default: false
    }
  },
  
  // Usage Tracking
  usage: {
    scansThisMonth: {
      type: Number,
      default: 0
    },
    targetsCount: {
      type: Number,
      default: 0
    },
    reportsGenerated: {
      type: Number,
      default: 0
    },
    lastScanDate: Date
  },
  
  // API Access
  apiKey: {
    type: String,
    unique: true,
    sparse: true,
    select: false
  },
  apiKeyCreatedAt: {
    type: Date,
    select: false
  },
  
  // Metadata
  tags: [{
    type: String,
    trim: true
  }],
  notes: {
    type: String,
    maxlength: [500, 'Notes cannot exceed 500 characters']
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance
userSchema.index({ email: 1 });
userSchema.index({ organization: 1, role: 1 });
userSchema.index({ organizationId: 1 });
userSchema.index({ isActive: 1 });
userSchema.index({ 'subscription.plan': 1 });
userSchema.index({ createdAt: -1 });

// Virtual for full name
userSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`;
});

// Virtual for account lock status
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
  // Only hash the password if it has been modified (or is new)
  if (!this.isModified('password')) return next();
  
  try {
    // Hash password with cost of 12
    const rounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
    this.password = await bcrypt.hash(this.password, rounds);
    next();
  } catch (error) {
    next(error);
  }
});

// Pre-save middleware to set organization ID
userSchema.pre('save', function(next) {
  if (!this.organizationId && this.organization) {
    this.organizationId = this.organization.toLowerCase().replace(/[^a-z0-9]/g, '-');
  }
  next();
});

// Pre-save middleware to set permissions based on role
userSchema.pre('save', function(next) {
  if (this.isModified('role')) {
    switch (this.role) {
      case 'admin':
        this.permissions = [
          'users:read', 'users:write', 'users:delete',
          'targets:read', 'targets:write', 'targets:delete',
          'scans:read', 'scans:write', 'scans:delete',
          'reports:read', 'reports:write', 'reports:delete',
          'billing:read', 'billing:write',
          'settings:read', 'settings:write',
          'analytics:read'
        ];
        break;
      case 'manager':
        this.permissions = [
          'users:read',
          'targets:read', 'targets:write', 'targets:delete',
          'scans:read', 'scans:write', 'scans:delete',
          'reports:read', 'reports:write', 'reports:delete',
          'billing:read',
          'settings:read',
          'analytics:read'
        ];
        break;
      case 'viewer':
        this.permissions = [
          'targets:read',
          'scans:read',
          'reports:read',
          'analytics:read'
        ];
        break;
      default:
        this.permissions = [];
    }
  }
  next();
});

// Instance method to check password
userSchema.methods.checkPassword = async function(candidatePassword) {
  try {
    return await bcrypt.compare(candidatePassword, this.password);
  } catch (error) {
    throw new Error('Password comparison failed');
  }
};

// Instance method to generate JWT token
userSchema.methods.generateToken = function() {
  const payload = {
    id: this._id,
    email: this.email,
    role: this.role,
    organization: this.organization,
    organizationId: this.organizationId
  };
  
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '7d'
  });
};

// Instance method to generate refresh token
userSchema.methods.generateRefreshToken = function(userAgent, ipAddress) {
  const refreshToken = jwt.sign(
    { id: this._id, type: 'refresh' },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );
  
  this.refreshTokens.push({
    token: refreshToken,
    userAgent,
    ipAddress
  });
  
  // Keep only last 5 refresh tokens
  if (this.refreshTokens.length > 5) {
    this.refreshTokens = this.refreshTokens.slice(-5);
  }
  
  return refreshToken;
};

// Instance method to handle login attempts
userSchema.methods.incLoginAttempts = async function() {
  // If we have a previous lock that has expired, restart at 1
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockUntil: 1 },
      $set: { loginAttempts: 1 }
    });
  }
  
  const updates = { $inc: { loginAttempts: 1 } };
  
  // Lock account after 5 failed attempts for 2 hours
  if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + 2 * 60 * 60 * 1000 }; // 2 hours
  }
  
  return this.updateOne(updates);
};

// Instance method to reset login attempts
userSchema.methods.resetLoginAttempts = function() {
  return this.updateOne({
    $unset: { loginAttempts: 1, lockUntil: 1 }
  });
};

// Instance method to generate API key
userSchema.methods.generateApiKey = function() {
  const apiKey = `cybersec_${uuidv4().replace(/-/g, '')}`;
  this.apiKey = apiKey;
  this.apiKeyCreatedAt = new Date();
  return apiKey;
};

// Instance method to check permissions
userSchema.methods.hasPermission = function(permission) {
  return this.permissions.includes(permission);
};

// Instance method to check if user belongs to organization
userSchema.methods.belongsToOrganization = function(organizationId) {
  return this.organizationId === organizationId;
};

// Static method to find by email
userSchema.statics.findByEmail = function(email) {
  return this.findOne({ email: email.toLowerCase() });
};

// Static method to find by organization
userSchema.statics.findByOrganization = function(organizationId) {
  return this.find({ organizationId, isActive: true });
};

// Static method to find admins
userSchema.statics.findAdmins = function() {
  return this.find({ role: 'admin', isActive: true });
};

// Remove expired refresh tokens before saving
userSchema.pre('save', function(next) {
  this.refreshTokens = this.refreshTokens.filter(
    token => token.createdAt.getTime() + 30 * 24 * 60 * 60 * 1000 > Date.now()
  );
  next();
});

const User = mongoose.model('User', userSchema);

module.exports = User;