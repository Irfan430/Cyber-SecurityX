/**
 * Scan Model
 * Stores vulnerability scan results and security findings
 */

const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');

const scanSchema = new mongoose.Schema({
  // Basic Information
  id: {
    type: String,
    default: uuidv4,
    unique: true,
    index: true
  },
  
  // Relationships
  targetId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Target',
    required: true,
    index: true
  },
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
  
  // Scan Configuration
  type: {
    type: String,
    enum: ['port_scan', 'vulnerability_scan', 'web_scan', 'ssl_scan', 'comprehensive'],
    default: 'comprehensive',
    index: true
  },
  
  scanProfile: {
    type: String,
    enum: ['quick', 'standard', 'deep', 'custom'],
    default: 'standard'
  },
  
  // Scan Status and Timing
  status: {
    type: String,
    enum: ['queued', 'running', 'completed', 'failed', 'cancelled', 'timeout'],
    default: 'queued',
    index: true
  },
  
  startedAt: Date,
  completedAt: Date,
  duration: {
    type: Number, // Duration in seconds
    index: true
  },
  
  // Progress Tracking
  progress: {
    percentage: {
      type: Number,
      default: 0,
      min: 0,
      max: 100
    },
    currentPhase: {
      type: String,
      enum: ['initializing', 'discovery', 'port_scanning', 'service_detection', 'vulnerability_detection', 'web_scanning', 'analysis', 'reporting'],
      default: 'initializing'
    },
    phases: [{
      name: String,
      status: {
        type: String,
        enum: ['pending', 'running', 'completed', 'failed', 'skipped']
      },
      startedAt: Date,
      completedAt: Date,
      duration: Number,
      details: String
    }]
  },
  
  // Scan Configuration Details
  config: {
    ports: {
      type: String,
      default: 'top-1000'
    },
    timing: {
      type: String,
      enum: ['paranoid', 'sneaky', 'polite', 'normal', 'aggressive', 'insane'],
      default: 'normal'
    },
    enabledChecks: [{
      type: String,
      enum: ['port_scan', 'service_detection', 'os_detection', 'vuln_scan', 'web_scan', 'ssl_scan', 'brute_force']
    }],
    options: {
      skipPing: { type: Boolean, default: false },
      fragmentPackets: { type: Boolean, default: false },
      randomizeHosts: { type: Boolean, default: false },
      maxRetries: { type: Number, default: 3 },
      timeout: { type: Number, default: 300 } // seconds
    }
  },
  
  // Target Information (snapshot at scan time)
  targetSnapshot: {
    value: String,
    type: String,
    resolvedIPs: [String],
    reverseDNS: String
  },
  
  // Scan Results
  results: {
    // Overall Risk Assessment
    riskScore: {
      type: Number,
      min: 0,
      max: 10,
      default: 0,
      index: true
    },
    riskLevel: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical'],
      default: 'low',
      index: true
    },
    
    // Summary Statistics
    summary: {
      totalPorts: { type: Number, default: 0 },
      openPorts: { type: Number, default: 0 },
      closedPorts: { type: Number, default: 0 },
      filteredPorts: { type: Number, default: 0 },
      vulnerabilities: {
        critical: { type: Number, default: 0 },
        high: { type: Number, default: 0 },
        medium: { type: Number, default: 0 },
        low: { type: Number, default: 0 },
        info: { type: Number, default: 0 }
      },
      services: { type: Number, default: 0 },
      osMatches: { type: Number, default: 0 }
    },
    
    // Host Information
    hostInfo: {
      hostname: String,
      operatingSystem: {
        name: String,
        version: String,
        confidence: Number,
        cpe: String
      },
      uptime: Number,
      lastSeen: Date,
      macAddress: String,
      vendor: String
    },
    
    // Open Ports and Services
    ports: [{
      port: {
        type: Number,
        required: true
      },
      protocol: {
        type: String,
        enum: ['tcp', 'udp'],
        default: 'tcp'
      },
      state: {
        type: String,
        enum: ['open', 'closed', 'filtered', 'unfiltered', 'open|filtered', 'closed|filtered'],
        default: 'closed'
      },
      service: {
        name: String,
        product: String,
        version: String,
        extraInfo: String,
        confidence: Number,
        cpe: String
      },
      scripts: [{
        id: String,
        output: String,
        elements: mongoose.Schema.Types.Mixed
      }]
    }],
    
    // Vulnerabilities Found
    vulnerabilities: [{
      id: String,
      cve: String,
      cwe: String,
      name: {
        type: String,
        required: true
      },
      description: String,
      severity: {
        type: String,
        enum: ['critical', 'high', 'medium', 'low', 'info'],
        required: true
      },
      cvssScore: {
        type: Number,
        min: 0,
        max: 10
      },
      cvssVector: String,
      port: Number,
      protocol: String,
      service: String,
      proof: String,
      solution: String,
      references: [String],
      tags: [String],
      exploitable: {
        type: Boolean,
        default: false
      },
      exploitAvailable: {
        type: Boolean,
        default: false
      },
      patchAvailable: {
        type: Boolean,
        default: false
      },
      firstSeen: {
        type: Date,
        default: Date.now
      },
      lastSeen: {
        type: Date,
        default: Date.now
      },
      status: {
        type: String,
        enum: ['open', 'confirmed', 'false_positive', 'fixed', 'mitigated'],
        default: 'open'
      }
    }],
    
    // Web Application Findings (if web scan enabled)
    webFindings: {
      technologies: [{
        name: String,
        version: String,
        confidence: Number,
        categories: [String]
      }],
      headers: [{
        name: String,
        value: String,
        security: {
          risk: {
            type: String,
            enum: ['low', 'medium', 'high', 'critical']
          },
          description: String
        }
      }],
      cookies: [{
        name: String,
        secure: Boolean,
        httpOnly: Boolean,
        sameSite: String,
        domain: String,
        path: String,
        expires: Date
      }],
      forms: [{
        action: String,
        method: String,
        inputs: [{
          name: String,
          type: String,
          required: Boolean
        }],
        csrf: Boolean,
        validation: Boolean
      }],
      directories: [String],
      files: [String],
      subdomains: [String]
    },
    
    // SSL/TLS Analysis
    sslAnalysis: {
      certificate: {
        subject: String,
        issuer: String,
        validFrom: Date,
        validTo: Date,
        serialNumber: String,
        fingerprint: String,
        algorithm: String,
        keySize: Number,
        selfSigned: Boolean,
        expired: Boolean,
        validForHost: Boolean
      },
      protocols: [{
        version: String,
        enabled: Boolean,
        secure: Boolean
      }],
      ciphers: [{
        name: String,
        strength: String,
        keyExchange: String,
        authentication: String,
        encryption: String,
        mac: String
      }],
      vulnerabilities: [{
        name: String,
        severity: String,
        description: String,
        affected: Boolean
      }]
    },
    
    // Brute Force Results
    bruteForceResults: [{
      service: String,
      port: Number,
      protocol: String,
      credentials: [{
        username: String,
        password: String,
        success: Boolean,
        responseTime: Number
      }],
      totalAttempts: Number,
      successfulAttempts: Number,
      duration: Number,
      detection: {
        accountLockout: Boolean,
        rateLimiting: Boolean,
        captcha: Boolean,
        delayMechanism: Boolean
      }
    }]
  },
  
  // AI/ML Analysis
  aiAnalysis: {
    processed: {
      type: Boolean,
      default: false
    },
    riskPrediction: {
      probability: Number,
      confidence: Number,
      factors: [String],
      nextScanRecommendation: Date
    },
    anomalies: [{
      type: String,
      description: String,
      severity: String,
      confidence: Number,
      baseline: mongoose.Schema.Types.Mixed,
      current: mongoose.Schema.Types.Mixed
    }],
    recommendations: [{
      priority: {
        type: String,
        enum: ['low', 'medium', 'high', 'critical']
      },
      category: String,
      title: String,
      description: String,
      actionRequired: String,
      estimatedEffort: String,
      businessImpact: String
    }],
    threatIntelligence: [{
      indicator: String,
      type: String,
      source: String,
      confidence: Number,
      firstSeen: Date,
      lastSeen: Date,
      context: String
    }]
  },
  
  // Scan Execution Details
  executionDetails: {
    engine: {
      type: String,
      default: 'nmap'
    },
    version: String,
    command: String,
    exitCode: Number,
    stdout: String,
    stderr: String,
    workerId: String,
    nodeId: String,
    queueTime: Number, // Time spent in queue (seconds)
    resourceUsage: {
      maxMemory: Number,
      avgCpu: Number,
      networkIO: Number
    }
  },
  
  // Quality and Validation
  quality: {
    completeness: {
      type: Number,
      min: 0,
      max: 100,
      default: 0
    },
    accuracy: {
      type: Number,
      min: 0,
      max: 100,
      default: 0
    },
    confidence: {
      type: Number,
      min: 0,
      max: 100,
      default: 0
    },
    issues: [String],
    warnings: [String]
  },
  
  // Metadata
  source: {
    type: String,
    enum: ['manual', 'scheduled', 'api', 'automation', 'ci_cd'],
    default: 'manual'
  },
  
  tags: [String],
  
  notes: {
    type: String,
    maxlength: 2000
  },
  
  // External References
  externalId: String,
  parentScanId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Scan'
  },
  
  // Archived/Retention
  archived: {
    type: Boolean,
    default: false,
    index: true
  },
  archiveReason: String,
  retentionDate: Date
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance
scanSchema.index({ targetId: 1, createdAt: -1 });
scanSchema.index({ userId: 1, status: 1 });
scanSchema.index({ organizationId: 1, createdAt: -1 });
scanSchema.index({ status: 1, createdAt: 1 });
scanSchema.index({ 'results.riskScore': -1 });
scanSchema.index({ 'results.riskLevel': 1 });
scanSchema.index({ completedAt: -1 });
scanSchema.index({ 'results.vulnerabilities.severity': 1 });
scanSchema.index({ type: 1, status: 1 });

// Compound indexes
scanSchema.index({ organizationId: 1, status: 1, createdAt: -1 });
scanSchema.index({ targetId: 1, status: 1, 'results.riskScore': -1 });

// Virtual for scan duration in human readable format
scanSchema.virtual('durationFormatted').get(function() {
  if (!this.duration) return 'N/A';
  
  const hours = Math.floor(this.duration / 3600);
  const minutes = Math.floor((this.duration % 3600) / 60);
  const seconds = this.duration % 60;
  
  if (hours > 0) return `${hours}h ${minutes}m ${seconds}s`;
  if (minutes > 0) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
});

// Virtual for vulnerability count
scanSchema.virtual('vulnerabilityCount').get(function() {
  if (!this.results.vulnerabilities) return 0;
  return this.results.vulnerabilities.length;
});

// Virtual for critical vulnerability count
scanSchema.virtual('criticalVulnCount').get(function() {
  if (!this.results.vulnerabilities) return 0;
  return this.results.vulnerabilities.filter(v => v.severity === 'critical').length;
});

// Virtual for scan efficiency
scanSchema.virtual('efficiency').get(function() {
  if (!this.duration || !this.results.summary.totalPorts) return 0;
  return Math.round(this.results.summary.totalPorts / this.duration * 100) / 100;
});

// Pre-save middleware to calculate duration
scanSchema.pre('save', function(next) {
  if (this.startedAt && this.completedAt) {
    this.duration = Math.round((this.completedAt - this.startedAt) / 1000);
  }
  next();
});

// Pre-save middleware to update progress when status changes
scanSchema.pre('save', function(next) {
  if (this.isModified('status')) {
    switch (this.status) {
      case 'running':
        if (!this.startedAt) this.startedAt = new Date();
        this.progress.percentage = 5;
        break;
      case 'completed':
        this.completedAt = new Date();
        this.progress.percentage = 100;
        break;
      case 'failed':
      case 'cancelled':
      case 'timeout':
        this.completedAt = new Date();
        break;
    }
  }
  next();
});

// Pre-save middleware to calculate risk score
scanSchema.pre('save', function(next) {
  if (this.isModified('results.vulnerabilities') || this.isNew) {
    let riskScore = 0;
    
    if (this.results.vulnerabilities && this.results.vulnerabilities.length > 0) {
      const severityWeights = {
        critical: 10,
        high: 7,
        medium: 4,
        low: 2,
        info: 0.5
      };
      
      let totalScore = 0;
      let vulnCount = 0;
      
      this.results.vulnerabilities.forEach(vuln => {
        if (vuln.status === 'open' || vuln.status === 'confirmed') {
          totalScore += severityWeights[vuln.severity] || 0;
          vulnCount++;
        }
      });
      
      if (vulnCount > 0) {
        // Calculate weighted average with diminishing returns
        riskScore = Math.min(10, totalScore / Math.sqrt(vulnCount));
      }
    }
    
    this.results.riskScore = Math.round(riskScore * 10) / 10;
    
    // Set risk level based on score
    if (riskScore >= 8) this.results.riskLevel = 'critical';
    else if (riskScore >= 6) this.results.riskLevel = 'high';
    else if (riskScore >= 3) this.results.riskLevel = 'medium';
    else this.results.riskLevel = 'low';
  }
  next();
});

// Instance method to update progress
scanSchema.methods.updateProgress = function(percentage, phase) {
  this.progress.percentage = Math.min(100, Math.max(0, percentage));
  if (phase) this.progress.currentPhase = phase;
  return this.save();
};

// Instance method to add vulnerability
scanSchema.methods.addVulnerability = function(vuln) {
  this.results.vulnerabilities.push(vuln);
  
  // Update summary
  if (vuln.severity && this.results.summary.vulnerabilities[vuln.severity] !== undefined) {
    this.results.summary.vulnerabilities[vuln.severity]++;
  }
  
  return this.save();
};

// Instance method to mark as completed
scanSchema.methods.markCompleted = function() {
  this.status = 'completed';
  this.completedAt = new Date();
  this.progress.percentage = 100;
  return this.save();
};

// Instance method to mark as failed
scanSchema.methods.markFailed = function(error) {
  this.status = 'failed';
  this.completedAt = new Date();
  if (error) {
    this.executionDetails.stderr = error.message;
  }
  return this.save();
};

// Instance method to check if scan is in progress
scanSchema.methods.isInProgress = function() {
  return ['queued', 'running'].includes(this.status);
};

// Instance method to check if scan is completed
scanSchema.methods.isCompleted = function() {
  return this.status === 'completed';
};

// Instance method to check if scan has failed
scanSchema.methods.hasFailed = function() {
  return ['failed', 'cancelled', 'timeout'].includes(this.status);
};

// Static method to find recent scans
scanSchema.statics.findRecent = function(organizationId, limit = 10) {
  return this.find({ organizationId })
    .sort({ createdAt: -1 })
    .limit(limit)
    .populate('targetId', 'name value type')
    .populate('userId', 'firstName lastName email');
};

// Static method to find scans by risk level
scanSchema.statics.findByRiskLevel = function(organizationId, riskLevel) {
  return this.find({ 
    organizationId, 
    'results.riskLevel': riskLevel,
    status: 'completed'
  }).sort({ 'results.riskScore': -1 });
};

// Static method to get scan statistics
scanSchema.statics.getStatistics = async function(organizationId, timeframe = 30) {
  const startDate = new Date(Date.now() - timeframe * 24 * 60 * 60 * 1000);
  
  const stats = await this.aggregate([
    {
      $match: {
        organizationId,
        createdAt: { $gte: startDate },
        status: 'completed'
      }
    },
    {
      $group: {
        _id: null,
        totalScans: { $sum: 1 },
        avgRiskScore: { $avg: '$results.riskScore' },
        maxRiskScore: { $max: '$results.riskScore' },
        avgDuration: { $avg: '$duration' },
        totalVulnerabilities: { $sum: { $size: '$results.vulnerabilities' } },
        riskLevels: {
          $push: '$results.riskLevel'
        }
      }
    }
  ]);
  
  return stats[0] || {
    totalScans: 0,
    avgRiskScore: 0,
    maxRiskScore: 0,
    avgDuration: 0,
    totalVulnerabilities: 0,
    riskLevels: []
  };
};

// Static method to find vulnerable targets
scanSchema.statics.findVulnerableTargets = function(organizationId, minRiskScore = 5) {
  return this.find({
    organizationId,
    status: 'completed',
    'results.riskScore': { $gte: minRiskScore }
  })
  .populate('targetId')
  .sort({ 'results.riskScore': -1 });
};

const Scan = mongoose.model('Scan', scanSchema);

module.exports = Scan;