/**
 * Target Model
 * Manages scan targets (domains, IPs, subnets) with validation and metadata
 */

const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');

const targetSchema = new mongoose.Schema({
  // Basic Information
  id: {
    type: String,
    default: uuidv4,
    unique: true,
    index: true
  },
  
  // Target Details
  name: {
    type: String,
    required: [true, 'Target name is required'],
    trim: true,
    maxlength: [100, 'Target name cannot exceed 100 characters']
  },
  
  description: {
    type: String,
    trim: true,
    maxlength: [500, 'Description cannot exceed 500 characters']
  },
  
  type: {
    type: String,
    required: [true, 'Target type is required'],
    enum: ['domain', 'ip', 'subnet', 'url'],
    index: true
  },
  
  value: {
    type: String,
    required: [true, 'Target value is required'],
    trim: true,
    index: true,
    validate: {
      validator: function(v) {
        switch (this.type) {
          case 'domain':
            // Domain validation
            return /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(v);
          case 'ip':
            // IPv4/IPv6 validation
            return /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(v) ||
                   /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/.test(v);
          case 'subnet':
            // CIDR notation validation
            return /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|[1-2][0-9]|3[0-2])$/.test(v);
          case 'url':
            // URL validation
            try {
              new URL(v);
              return true;
            } catch {
              return false;
            }
          default:
            return false;
        }
      },
      message: 'Invalid target value format for the specified type'
    }
  },
  
  // Ownership and Access Control
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  organizationId: {
    type: String,
    required: true,
    index: true
  },
  
  // Configuration
  isActive: {
    type: Boolean,
    default: true,
    index: true
  },
  
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'medium',
    index: true
  },
  
  // Scan Configuration
  scanConfig: {
    // Port scanning configuration
    ports: {
      type: String,
      default: 'top-1000', // 'top-1000', 'all', 'custom', or specific ports like '80,443,8080'
      validate: {
        validator: function(v) {
          return ['top-1000', 'all', 'custom'].includes(v) || 
                 /^(\d+(-\d+)?,?)+$/.test(v); // Custom port ranges/lists
        },
        message: 'Invalid port configuration'
      }
    },
    
    customPorts: [{
      type: Number,
      min: 1,
      max: 65535
    }],
    
    // Scan types to perform
    scanTypes: [{
      type: String,
      enum: ['port_scan', 'service_detection', 'os_detection', 'vuln_scan', 'web_scan', 'ssl_scan'],
      default: ['port_scan', 'service_detection']
    }],
    
    // Timing and performance
    timing: {
      type: String,
      enum: ['paranoid', 'sneaky', 'polite', 'normal', 'aggressive', 'insane'],
      default: 'normal'
    },
    
    // Maximum scan duration in minutes
    maxDuration: {
      type: Number,
      default: 60,
      min: 1,
      max: 1440 // 24 hours
    },
    
    // Concurrent scans limit
    maxConcurrent: {
      type: Number,
      default: 5,
      min: 1,
      max: 20
    }
  },
  
  // Network Information (populated during scans)
  networkInfo: {
    resolvedIPs: [{
      ip: String,
      type: {
        type: String,
        enum: ['A', 'AAAA', 'CNAME', 'MX', 'PTR']
      },
      ttl: Number,
      lastResolved: {
        type: Date,
        default: Date.now
      }
    }],
    
    reverseDNS: String,
    
    geolocation: {
      country: String,
      region: String,
      city: String,
      latitude: Number,
      longitude: Number,
      organization: String,
      isp: String
    },
    
    whoisInfo: {
      registrar: String,
      registrationDate: Date,
      expirationDate: Date,
      nameservers: [String],
      contacts: [{
        type: {
          type: String,
          enum: ['registrant', 'admin', 'tech', 'billing']
        },
        name: String,
        organization: String,
        email: String,
        phone: String
      }]
    }
  },
  
  // Scan History Summary
  scanSummary: {
    totalScans: {
      type: Number,
      default: 0
    },
    lastScanDate: Date,
    lastScanId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Scan'
    },
    averageRiskScore: {
      type: Number,
      default: 0,
      min: 0,
      max: 10
    },
    highestRiskScore: {
      type: Number,
      default: 0,
      min: 0,
      max: 10
    },
    openPorts: [{
      port: Number,
      service: String,
      version: String,
      lastSeen: Date
    }],
    vulnerabilities: [{
      cve: String,
      severity: {
        type: String,
        enum: ['low', 'medium', 'high', 'critical']
      },
      score: Number,
      firstFound: Date,
      lastSeen: Date,
      status: {
        type: String,
        enum: ['open', 'patched', 'mitigated', 'false_positive'],
        default: 'open'
      }
    }]
  },
  
  // Categorization and Organization
  tags: [{
    type: String,
    trim: true,
    maxlength: [50, 'Tag cannot exceed 50 characters']
  }],
  
  category: {
    type: String,
    enum: ['web', 'infrastructure', 'database', 'email', 'dns', 'cdn', 'api', 'iot', 'cloud', 'other'],
    default: 'other'
  },
  
  environment: {
    type: String,
    enum: ['production', 'staging', 'development', 'testing', 'sandbox'],
    default: 'production'
  },
  
  // Business Context
  businessImpact: {
    type: String,
    enum: ['critical', 'high', 'medium', 'low'],
    default: 'medium'
  },
  
  owner: {
    name: String,
    email: String,
    department: String
  },
  
  // Compliance and Governance
  complianceFrameworks: [{
    type: String,
    enum: ['PCI-DSS', 'HIPAA', 'SOX', 'GDPR', 'ISO27001', 'NIST', 'SOC2']
  }],
  
  dataClassification: {
    type: String,
    enum: ['public', 'internal', 'confidential', 'restricted'],
    default: 'internal'
  },
  
  // Scheduling
  scanSchedule: {
    enabled: {
      type: Boolean,
      default: false
    },
    frequency: {
      type: String,
      enum: ['daily', 'weekly', 'monthly', 'quarterly'],
      default: 'weekly'
    },
    nextScan: Date,
    lastScheduledScan: Date
  },
  
  // Notifications
  notifications: {
    enabled: {
      type: Boolean,
      default: true
    },
    channels: [{
      type: String,
      enum: ['email', 'slack', 'telegram', 'webhook']
    }],
    conditions: [{
      type: String,
      enum: ['scan_complete', 'vulnerability_found', 'risk_increase', 'new_service', 'port_change']
    }]
  },
  
  // Access Control
  visibility: {
    type: String,
    enum: ['private', 'team', 'organization'],
    default: 'team'
  },
  
  sharedWith: [{
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    permissions: [{
      type: String,
      enum: ['read', 'scan', 'modify', 'delete']
    }],
    sharedAt: {
      type: Date,
      default: Date.now
    }
  }],
  
  // Metadata
  notes: {
    type: String,
    maxlength: [1000, 'Notes cannot exceed 1000 characters']
  },
  
  externalId: {
    type: String,
    trim: true
  },
  
  source: {
    type: String,
    enum: ['manual', 'import', 'api', 'discovery', 'integration'],
    default: 'manual'
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance
targetSchema.index({ userId: 1, organizationId: 1 });
targetSchema.index({ type: 1, value: 1 });
targetSchema.index({ isActive: 1 });
targetSchema.index({ priority: 1 });
targetSchema.index({ 'scanSummary.lastScanDate': -1 });
targetSchema.index({ 'scanSummary.averageRiskScore': -1 });
targetSchema.index({ tags: 1 });
targetSchema.index({ category: 1 });
targetSchema.index({ environment: 1 });
targetSchema.index({ createdAt: -1 });

// Compound indexes
targetSchema.index({ organizationId: 1, isActive: 1, priority: -1 });
targetSchema.index({ userId: 1, type: 1, isActive: 1 });

// Virtual for full target identifier
targetSchema.virtual('identifier').get(function() {
  return `${this.type}:${this.value}`;
});

// Virtual for risk level based on average risk score
targetSchema.virtual('riskLevel').get(function() {
  const score = this.scanSummary.averageRiskScore;
  if (score >= 8) return 'critical';
  if (score >= 6) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
});

// Virtual for scan status
targetSchema.virtual('scanStatus').get(function() {
  if (!this.scanSummary.lastScanDate) return 'never_scanned';
  
  const daysSinceLastScan = (Date.now() - this.scanSummary.lastScanDate) / (1000 * 60 * 60 * 24);
  
  if (daysSinceLastScan > 30) return 'outdated';
  if (daysSinceLastScan > 7) return 'needs_scan';
  return 'up_to_date';
});

// Pre-save middleware to normalize value
targetSchema.pre('save', function(next) {
  if (this.isModified('value')) {
    switch (this.type) {
      case 'domain':
        this.value = this.value.toLowerCase();
        break;
      case 'ip':
      case 'subnet':
        // IP normalization could be added here
        break;
      case 'url':
        try {
          const url = new URL(this.value);
          this.value = url.toString();
        } catch (e) {
          // URL is invalid, validation will catch this
        }
        break;
    }
  }
  next();
});

// Pre-save middleware to set next scan date
targetSchema.pre('save', function(next) {
  if (this.scanSchedule.enabled && this.isModified('scanSchedule.frequency')) {
    const now = new Date();
    switch (this.scanSchedule.frequency) {
      case 'daily':
        this.scanSchedule.nextScan = new Date(now.getTime() + 24 * 60 * 60 * 1000);
        break;
      case 'weekly':
        this.scanSchedule.nextScan = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
        break;
      case 'monthly':
        this.scanSchedule.nextScan = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
        break;
      case 'quarterly':
        this.scanSchedule.nextScan = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000);
        break;
    }
  }
  next();
});

// Instance method to check if user has access
targetSchema.methods.hasAccess = function(userId, permission = 'read') {
  // Owner has all permissions
  if (this.userId.toString() === userId.toString()) {
    return true;
  }
  
  // Check shared permissions
  const sharedPermission = this.sharedWith.find(
    share => share.userId.toString() === userId.toString()
  );
  
  return sharedPermission && sharedPermission.permissions.includes(permission);
};

// Instance method to update scan summary
targetSchema.methods.updateScanSummary = function(scanResult) {
  this.scanSummary.totalScans += 1;
  this.scanSummary.lastScanDate = new Date();
  this.scanSummary.lastScanId = scanResult._id;
  
  if (scanResult.riskScore > this.scanSummary.highestRiskScore) {
    this.scanSummary.highestRiskScore = scanResult.riskScore;
  }
  
  // Calculate new average risk score
  const currentAvg = this.scanSummary.averageRiskScore || 0;
  const totalScans = this.scanSummary.totalScans;
  this.scanSummary.averageRiskScore = 
    ((currentAvg * (totalScans - 1)) + scanResult.riskScore) / totalScans;
  
  return this.save();
};

// Instance method to add vulnerability
targetSchema.methods.addVulnerability = function(vulnerability) {
  const existingVuln = this.scanSummary.vulnerabilities.find(
    v => v.cve === vulnerability.cve
  );
  
  if (existingVuln) {
    existingVuln.lastSeen = new Date();
    existingVuln.score = vulnerability.score;
    existingVuln.severity = vulnerability.severity;
  } else {
    this.scanSummary.vulnerabilities.push({
      cve: vulnerability.cve,
      severity: vulnerability.severity,
      score: vulnerability.score,
      firstFound: new Date(),
      lastSeen: new Date(),
      status: 'open'
    });
  }
  
  return this.save();
};

// Static method to find targets for organization
targetSchema.statics.findByOrganization = function(organizationId, options = {}) {
  const query = { organizationId, isActive: true };
  
  if (options.type) query.type = options.type;
  if (options.priority) query.priority = options.priority;
  if (options.category) query.category = options.category;
  if (options.tags) query.tags = { $in: options.tags };
  
  return this.find(query);
};

// Static method to find targets requiring scans
targetSchema.statics.findRequiringScans = function() {
  const now = new Date();
  return this.find({
    isActive: true,
    'scanSchedule.enabled': true,
    'scanSchedule.nextScan': { $lte: now }
  });
};

// Static method to search targets
targetSchema.statics.search = function(organizationId, searchTerm) {
  const regex = new RegExp(searchTerm, 'i');
  return this.find({
    organizationId,
    isActive: true,
    $or: [
      { name: regex },
      { value: regex },
      { description: regex },
      { tags: regex }
    ]
  });
};

const Target = mongoose.model('Target', targetSchema);

module.exports = Target;