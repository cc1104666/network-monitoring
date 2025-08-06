package main

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// ThreatDetector detects security threats
type ThreatDetector struct {
	threats []Threat
	alerts  []AlertInfo
	mu      sync.RWMutex
}

// NewThreatDetector creates a new threat detector
func NewThreatDetector() *ThreatDetector {
	return &ThreatDetector{
		threats: make([]Threat, 0),
		alerts:  make([]AlertInfo, 0),
	}
}

// AnalyzeHTTPRequest analyzes an HTTP request for threats
func (t *ThreatDetector) AnalyzeHTTPRequest(req HTTPRequest) (bool, *Threat) {
	// Check for suspicious patterns
	suspiciousPatterns := []string{
		"../", "..\\", "/etc/passwd", "/etc/shadow", "cmd.exe", "powershell",
		"<script", "javascript:", "onload=", "onerror=", "eval(",
		"union select", "drop table", "insert into", "delete from",
		"wp-admin", "phpmyadmin", "admin.php", "login.php",
		".env", "config.php", "database.yml", "secrets.json",
	}

	var threatType string
	var description string
	severity := "low"

	path := strings.ToLower(req.Path)
	userAgent := strings.ToLower(req.UserAgent)

	// Check for path traversal
	for _, pattern := range suspiciousPatterns[:4] {
		if strings.Contains(path, pattern) {
			threatType = "path_traversal"
			description = fmt.Sprintf("Path traversal attempt detected: %s", pattern)
			severity = "high"
			break
		}
	}

	// Check for XSS
	if threatType == "" {
		for _, pattern := range suspiciousPatterns[4:9] {
			if strings.Contains(path, pattern) || strings.Contains(userAgent, pattern) {
				threatType = "xss"
				description = fmt.Sprintf("XSS attempt detected: %s", pattern)
				severity = "medium"
				break
			}
		}
	}

	// Check for SQL injection
	if threatType == "" {
		for _, pattern := range suspiciousPatterns[9:13] {
			if strings.Contains(path, pattern) {
				threatType = "sql_injection"
				description = fmt.Sprintf("SQL injection attempt detected: %s", pattern)
				severity = "critical"
				break
			}
		}
	}

	// Check for admin panel access
	if threatType == "" {
		for _, pattern := range suspiciousPatterns[13:17] {
			if strings.Contains(path, pattern) {
				threatType = "admin_access"
				description = fmt.Sprintf("Admin panel access attempt: %s", pattern)
				severity = "medium"
				break
			}
		}
	}

	// Check for sensitive file access
	if threatType == "" {
		for _, pattern := range suspiciousPatterns[17:] {
			if strings.Contains(path, pattern) {
				threatType = "sensitive_file"
				description = fmt.Sprintf("Sensitive file access attempt: %s", pattern)
				severity = "high"
				break
			}
		}
	}

	// Check for suspicious user agents
	if threatType == "" {
		suspiciousAgents := []string{"sqlmap", "nikto", "nmap", "masscan", "zap", "burp"}
		for _, agent := range suspiciousAgents {
			if strings.Contains(userAgent, agent) {
				threatType = "scanner"
				description = fmt.Sprintf("Security scanner detected: %s", agent)
				severity = "high"
				break
			}
		}
	}

	// Check for brute force (multiple failed attempts)
	if req.StatusCode == 401 || req.StatusCode == 403 {
		threatType = "brute_force"
		description = "Potential brute force attack detected"
		severity = "medium"
	}

	if threatType != "" {
		threat := &Threat{
			ID:          fmt.Sprintf("threat_%d", time.Now().UnixNano()),
			Type:        threatType,
			Severity:    severity,
			Source:      req.IP,
			Target:      req.Path,
			Description: description,
			Timestamp:   time.Now(),
			Status:      "active",
		}

		t.mu.Lock()
		t.threats = append([]Threat{*threat}, t.threats...)
		if len(t.threats) > 100 {
			t.threats = t.threats[:100]
		}

		// Create corresponding alert
		alert := AlertInfo{
			ID:           fmt.Sprintf("alert_%d", time.Now().UnixNano()),
			Type:         "security",
			Message:      fmt.Sprintf("Security threat detected from %s: %s", req.IP, description),
			Severity:     severity,
			Timestamp:    time.Now(),
			Acknowledged: false,
		}
		t.alerts = append([]AlertInfo{alert}, t.alerts...)
		if len(t.alerts) > 50 {
			t.alerts = t.alerts[:50]
		}
		t.mu.Unlock()

		return true, threat
	}

	return false, nil
}

// GetThreats returns all detected threats
func (t *ThreatDetector) GetThreats() []Threat {
	t.mu.RLock()
	defer t.mu.RUnlock()
	
	// Return a copy to avoid race conditions
	result := make([]Threat, len(t.threats))
	copy(result, t.threats)
	return result
}

// GetAlerts returns all alerts
func (t *ThreatDetector) GetAlerts() []AlertInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()
	
	// Return a copy to avoid race conditions
	result := make([]AlertInfo, len(t.alerts))
	copy(result, t.alerts)
	return result
}

// AddThreat manually adds a threat (for testing or external sources)
func (t *ThreatDetector) AddThreat(threat Threat) {
	t.mu.Lock()
	defer t.mu.Unlock()
	
	t.threats = append([]Threat{threat}, t.threats...)
	if len(t.threats) > 100 {
		t.threats = t.threats[:100]
	}
}

// AddAlert manually adds an alert
func (t *ThreatDetector) AddAlert(alert AlertInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()
	
	t.alerts = append([]AlertInfo{alert}, t.alerts...)
	if len(t.alerts) > 50 {
		t.alerts = t.alerts[:50]
	}
}
