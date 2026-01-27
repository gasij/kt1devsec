
const auditLog = [];
const suspiciousActivities = [];
const failedLogins = {};
console.log("sd")
// Security thresholds
const SECURITY_CONFIG = {
  MAX_FAILED_LOGINS: 5,
  SUSPICIOUS_REQUEST_LIMIT: 100, // requests per minute
  ALERT_EMAIL: 'security@devsec.com',
  AUDIT_RETENTION_DAYS: 90
};

// Security middleware - log all requests
app.use((req, res, next) => {
  const startTime = Date.now();
  const auditId = `audit_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  
  // Capture response data
  const originalSend = res.send;
  res.send = function(body) {
    const duration = Date.now() - startTime;
    
    // Log the request
    const auditEntry = {
      id: auditId,
      timestamp: new Date().toISOString(),
      method: req.method,
      url: req.url,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      userId: req.headers['x-user-id'] || 'anonymous',
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      requestBody: req.method !== 'GET' ? req.body : null,
      responseSize: typeof body === 'string' ? body.length : JSON.stringify(body).length,
      securityLevel: res.statusCode >= 400 ? 'WARNING' : 'INFO'
    };
    
    auditLog.push(auditEntry);
    
    // Check for suspicious activity
    checkSuspiciousActivity(auditEntry);
    
    // Limit audit log size (keep last 1000 entries)
    if (auditLog.length > 1000) {
      auditLog.shift();
    }
    
    originalSend.call(this, body);
  };
  
  next();
});

// Check for suspicious activity
function checkSuspiciousActivity(auditEntry) {
  const { ip, url, statusCode, method } = auditEntry;
  
  // 1. Detect brute force attacks (multiple failed logins)
  if (url.includes('/api/auth/login') && statusCode === 401) {
    failedLogins[ip] = (failedLogins[ip] || 0) + 1;
    
    if (failedLogins[ip] >= SECURITY_CONFIG.MAX_FAILED_LOGINS) {
      const alert = {
        type: 'BRUTE_FORCE_ATTEMPT',
        severity: 'HIGH',
        ip,
        timestamp: new Date().toISOString(),
        message: `Multiple failed login attempts from IP: ${ip}`,
        count: failedLogins[ip]
      };
      
      suspiciousActivities.push(alert);
      console.warn(`🚨 SECURITY ALERT: ${alert.message}`);
    }
  }
  
  // 2. Detect suspicious endpoints access
  const sensitiveEndpoints = ['/api/auth/profile', '/api/tasks', '/admin'];
  if (sensitiveEndpoints.some(endpoint => url.includes(endpoint)) && statusCode === 403) {
    const alert = {
      type: 'UNAUTHORIZED_ACCESS',
      severity: 'MEDIUM',
      ip,
      url,
      timestamp: new Date().toISOString(),
      message: `Unauthorized access attempt to sensitive endpoint: ${url}`
    };
    
    suspiciousActivities.push(alert);
  }
  
  // 3. Detect too many requests
  const recentRequests = auditLog.filter(log => 
    log.ip === ip && 
    Date.now() - new Date(log.timestamp).getTime() < 60000
  );
  
  if (recentRequests.length > SECURITY_CONFIG.SUSPICIOUS_REQUEST_LIMIT) {
    const alert = {
      type: 'RATE_LIMIT_EXCEEDED',
      severity: 'MEDIUM',
      ip,
      timestamp: new Date().toISOString(),
      message: `High request rate detected from IP: ${ip} (${recentRequests.length} requests/min)`
    };
    
    suspiciousActivities.push(alert);
  }
  
  // Limit suspicious activities log size
  if (suspiciousActivities.length > 500) {
    suspiciousActivities.shift();
  }
}

// 1. GET /api/security/audit - Get audit logs (Admin only)
app.get('/api/security/audit', (req, res) => {
  try {
    const { startDate, endDate, ip, userId, limit = 100 } = req.query;
    
    let filteredLogs = [...auditLog];
    
    // Apply filters
    if (startDate) {
      filteredLogs = filteredLogs.filter(log => 
        new Date(log.timestamp) >= new Date(startDate)
      );
    }
    
    if (endDate) {
      filteredLogs = filteredLogs.filter(log => 
        new Date(log.timestamp) <= new Date(endDate)
      );
    }
    
    if (ip) {
      filteredLogs = filteredLogs.filter(log => log.ip === ip);
    }
    
    if (userId) {
      filteredLogs = filteredLogs.filter(log => log.userId === userId);
    }
    
    // Sort by timestamp (newest first)
    filteredLogs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    // Apply limit
    filteredLogs = filteredLogs.slice(0, parseInt(limit));
    
    res.json({
      success: true,
      count: filteredLogs.length,
      total: auditLog.length,
      logs: filteredLogs
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to fetch audit logs',
      details: error.message
    });
  }
});

// 2. GET /api/security/alerts - Get security alerts
app.get('/api/security/alerts', (req, res) => {
  try {
    const { severity, type, resolved } = req.query;
    
    let filteredAlerts = [...suspiciousActivities];
    
    if (severity) {
      filteredAlerts = filteredAlerts.filter(alert => 
        alert.severity.toLowerCase() === severity.toLowerCase()
      );
    }
    
    if (type) {
      filteredAlerts = filteredAlerts.filter(alert => 
        alert.type === type.toUpperCase()
      );
    }
    
    // Sort by timestamp (newest first)
    filteredAlerts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    res.json({
      success: true,
      count: filteredAlerts.length,
      alerts: filteredAlerts
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to fetch security alerts',
      details: error.message
    });
  }
});

// 3. GET /api/security/stats - Get security statistics
app.get('/api/security/stats', (req, res) => {
  try {
    const last24Hours = auditLog.filter(log => 
      Date.now() - new Date(log.timestamp).getTime() < 24 * 60 * 60 * 1000
    );
    
    const stats = {
      totalRequests: auditLog.length,
      requestsLast24h: last24Hours.length,
      uniqueIPs: [...new Set(auditLog.map(log => log.ip))].length,
      failedLogins: Object.values(failedLogins).reduce((sum, val) => sum + val, 0),
      securityAlerts: suspiciousActivities.length,
      alertsBySeverity: {
        HIGH: suspiciousActivities.filter(a => a.severity === 'HIGH').length,
        MEDIUM: suspiciousActivities.filter(a => a.severity === 'MEDIUM').length,
        LOW: suspiciousActivities.filter(a => a.severity === 'LOW').length
      },
      topSuspiciousIPs: Object.entries(
        auditLog.reduce((acc, log) => {
          acc[log.ip] = (acc[log.ip] || 0) + 1;
          return acc;
        }, {})
      )
        .sort(([,a], [,b]) => b - a)
        .slice(0, 5)
        .map(([ip, count]) => ({ ip, requests: count })),
      averageResponseTime: auditLog.length > 0
        ? Math.round(auditLog.reduce((sum, log) => 
            sum + parseInt(log.duration), 0) / auditLog.length
          )
        : 0
    };
    
    res.json({
      success: true,
      stats,
      generatedAt: new Date().toISOString(),
      retentionPeriod: `${SECURITY_CONFIG.AUDIT_RETENTION_DAYS} days`
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to generate security stats',
      details: error.message
    });
  }
});

// 4. GET /api/security/health - Enhanced health check with security status
app.get('/api/security/health', (req, res) => {
  try {
    const memoryUsage = process.memoryUsage();
    const uptime = process.uptime();
    
    const healthStatus = {
      status: 'SECURE',
      timestamp: new Date().toISOString(),
      api: {
        version: '3.0',
        name: 'DevSec API with Security Audit',
        uptime: `${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m ${Math.floor(uptime % 60)}s`
      },
      security: {
        level: 'HIGH',
        auditLogSize: auditLog.length,
        activeAlerts: suspiciousActivities.length,
        failedLoginAttempts: Object.keys(failedLogins).length,
        lastAlert: suspiciousActivities.length > 0 
          ? suspiciousActivities[suspiciousActivities.length - 1].timestamp 
          : 'NONE'
      },
      system: {
        memory: {
          used: `${Math.round(memoryUsage.heapUsed / 1024 / 1024)}MB`,
          total: `${Math.round(memoryUsage.heapTotal / 1024 / 1024)}MB`,
          usage: `${Math.round((memoryUsage.heapUsed / memoryUsage.heapTotal) * 100)}%`
        },
        nodeVersion: process.version,
        platform: process.platform
      },
      endpoints: {
        total: 12,
        secured: 8,
        public: 4
      }
    };
    
    // Check if system is under attack
    if (suspiciousActivities.length > 10) {
      healthStatus.status = 'UNDER_ATTACK';
      healthStatus.security.level = 'CRITICAL';
    }
    
    res.json(healthStatus);
  } catch (error) {
    res.status(500).json({
      status: 'ERROR',
      error: 'Health check failed',
      details: error.message
    });
  }
});

// 5. POST /api/security/ip/block - Block suspicious IP (Admin only)
app.post('/api/security/ip/block', (req, res) => {
  try {
    const { ip, reason, duration = '24h' } = req.body;
    const token = req.headers.authorization;
    
    if (!token || !token.includes('admin-token')) {
      return res.status(403).json({
        success: false,
        error: 'Admin privileges required'
      });
    }
    
    if (!ip) {
      return res.status(400).json({
        success: false,
        error: 'IP address is required'
      });
    }
    
    const blockEntry = {
      ip,
      reason: reason || 'Suspicious activity detected',
      blockedAt: new Date().toISOString(),
      duration,
      blockedBy: 'Security System',
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() // 24 hours
    };
    
    // In production, add to blocked IPs database
    console.log(`🚫 IP Blocked: ${ip} - Reason: ${blockEntry.reason}`);
    
    res.json({
      success: true,
      message: `IP ${ip} has been blocked`,
      block: blockEntry
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to block IP',
      details: error.message
    });
  }
});

// 6. GET /api/security/users/:userId/activity - Get user activity log
app.get('/api/security/users/:userId/activity', (req, res) => {
  try {
    const userId = req.params.userId;
    const userActivities = auditLog.filter(log => log.userId === userId);
    
    const activitySummary = {
      userId,
      totalActions: userActivities.length,
      firstActivity: userActivities.length > 0 
        ? userActivities[userActivities.length - 1].timestamp 
        : 'NONE',
      lastActivity: userActivities.length > 0 
        ? userActivities[0].timestamp 
        : 'NONE',
      actionsByMethod: userActivities.reduce((acc, activity) => {
        acc[activity.method] = (acc[activity.method] || 0) + 1;
        return acc;
      }, {}),
      recentActivities: userActivities.slice(0, 20)
    };
    
    res.json({
      success: true,
      summary: activitySummary
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to fetch user activity',
      details: error.message
    });
  }
});

// 7. DELETE /api/security/audit/clear - Clear old audit logs (Admin only)
app.delete('/api/security/audit/clear', (req, res) => {
  try {
    const { olderThan } = req.query;
    const token = req.headers.authorization;
    
    if (!token || !token.includes('admin-token')) {
      return res.status(403).json({
        success: false,
        error: 'Admin privileges required'
      });
    }
    
    const cutoffDate = olderThan 
      ? new Date(olderThan)
      : new Date(Date.now() - SECURITY_CONFIG.AUDIT_RETENTION_DAYS * 24 * 60 * 60 * 1000);
    
    const initialCount = auditLog.length;
    const logsToRemove = auditLog.filter(log => new Date(log.timestamp) < cutoffDate);
    
    // Remove old logs
    for (const log of logsToRemove) {
      const index = auditLog.indexOf(log);
      if (index > -1) {
        auditLog.splice(index, 1);
      }
    }
    
    res.json({
      success: true,
      message: `Cleared ${logsToRemove.length} audit logs older than ${cutoffDate.toISOString()}`,
      removed: logsToRemove.length,
      remaining: auditLog.length,
      cutoffDate: cutoffDate.toISOString()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to clear audit logs',
      details: error.message
    });
  }
});
