package main

import (
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"
)

// ThreatDetector handles threat detection and analysis
type ThreatDetector struct {
	threats []Threat
	alerts  []Alert
	mu      sync.RWMutex
}

// NewThreatDetector creates a new threat detector
func NewThreatDetector() *ThreatDetector {
	return &ThreatDetector{
		threats: make([]Threat, 0),
		alerts:  make([]Alert, 0),
	}
}

// AnalyzeHTTPRequest analyzes an HTTP request for threats
func (td *ThreatDetector) AnalyzeHTTPRequest(req HTTPRequest) (bool, *Threat) {
	td.mu.Lock()
	defer td.mu.Unlock()

	// Check for common attack patterns
	if td.isSQLInjection(req.Path) {
		threat := td.createThreat("sql_injection", "high", req.IP, req.Path, "SQL injection attempt detected")
		td.threats = append(td.threats, threat)
		td.createAlert("security", fmt.Sprintf("SQL injection from %s", req.IP), "high")
		return true, &threat
	}

	if td.isXSSAttempt(req.Path) {
		threat := td.createThreat("xss", "medium", req.IP, req.Path, "XSS attempt detected")
		td.threats = append(td.threats, threat)
		td.createAlert("security", fmt.Sprintf("XSS attempt from %s", req.IP), "medium")
		return true, &threat
	}

	if td.isPathTraversal(req.Path) {
		threat := td.createThreat("path_traversal", "high", req.IP, req.Path, "Path traversal attempt detected")
		td.threats = append(td.threats, threat)
		td.createAlert("security", fmt.Sprintf("Path traversal from %s", req.IP), "high")
		return true, &threat
	}

	if td.isSuspiciousUserAgent(req.UserAgent) {
		threat := td.createThreat("scanning_tool", "low", req.IP, req.Path, "Suspicious user agent detected")
		td.threats = append(td.threats, threat)
		td.createAlert("security", fmt.Sprintf("Scanning tool detected from %s", req.IP), "low")
		return true, &threat
	}

	return false, nil
}

// GetThreats returns all detected threats
func (td *ThreatDetector) GetThreats() []Threat {
	td.mu.RLock()
	defer td.mu.RUnlock()
	
	// Return a copy to avoid race conditions
	threats := make([]Threat, len(td.threats))
	copy(threats, td.threats)
	return threats
}

// GetAlerts returns all alerts
func (td *ThreatDetector) GetAlerts() []Alert {
	td.mu.RLock()
	defer td.mu.RUnlock()
	
	// Return a copy to avoid race conditions
	alerts := make([]Alert, len(td.alerts))
	copy(alerts, td.alerts)
	return alerts
}

// GenerateMockThreats generates some mock threats for demonstration
func (td *ThreatDetector) GenerateMockThreats() {
	td.mu.Lock()
	defer td.mu.Unlock()

	mockThreats := []Threat{
		{
			ID:          fmt.Sprintf("threat-%d", time.Now().Unix()),
			Type:        "sql_injection",
			Severity:    "high",
			Source:      "192.168.1.100",
			Target:      "/api/users",
			Description: "SQL injection attempt detected in user query",
			Timestamp:   time.Now().Add(-5 * time.Minute),
			Status:      "active",
		},
		{
			ID:          fmt.Sprintf("threat-%d", time.Now().Unix()+1),
			Type:        "brute_force",
			Severity:    "medium",
			Source:      "10.0.0.50",
			Target:      "/login",
			Description: "Multiple failed login attempts detected",
			Timestamp:   time.Now().Add(-10 * time.Minute),
			Status:      "active",
		},
		{
			ID:          fmt.Sprintf("threat-%d", time.Now().Unix()+2),
			Type:        "xss",
			Severity:    "medium",
			Source:      "203.0.113.45",
			Target:      "/search",
			Description: "Cross-site scripting attempt in search parameter",
			Timestamp:   time.Now().Add(-15 * time.Minute),
			Status:      "mitigated",
		},
	}

	td.threats = append(td.threats, mockThreats...)

	// Generate mock alerts
	mockAlerts := []Alert{
		{
			ID:           fmt.Sprintf("alert-%d", time.Now().Unix()),
			Type:         "security",
			Message:      "High number of failed login attempts detected",
			Severity:     "high",
			Timestamp:    time.Now().Add(-2 * time.Minute),
			Acknowledged: false,
		},
		{
			ID:           fmt.Sprintf("alert-%d", time.Now().Unix()+1),
			Type:         "performance",
			Message:      "CPU usage above 80% for extended period",
			Severity:     "warning",
			Timestamp:    time.Now().Add(-8 * time.Minute),
			Acknowledged: true,
		},
	}

	td.alerts = append(td.alerts, mockAlerts...)
}

// ClearOldThreats removes threats older than the specified duration
func (td *ThreatDetector) ClearOldThreats(maxAge time.Duration) {
	td.mu.Lock()
	defer td.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	var filteredThreats []Threat

	for _, threat := range td.threats {
		if threat.Timestamp.After(cutoff) {
			filteredThreats = append(filteredThreats, threat)
		}
	}

	td.threats = filteredThreats
}

// Helper methods for threat detection
func (td *ThreatDetector) isSQLInjection(path string) bool {
	sqlPatterns := []string{
		"'", "\"", ";", "--", "/*", "*/", "xp_", "sp_", "union", "select", "insert", "delete", "update", "drop", "create", "alter", "exec", "execute",
	}
	
	lowerPath := strings.ToLower(path)
	for _, pattern := range sqlPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

func (td *ThreatDetector) isXSSAttempt(path string) bool {
	xssPatterns := []string{
		"<script", "</script>", "javascript:", "onload=", "onerror=", "onclick=", "onmouseover=", "alert(", "document.cookie", "window.location",
	}
	
	lowerPath := strings.ToLower(path)
	for _, pattern := range xssPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

func (td *ThreatDetector) isPathTraversal(path string) bool {
	traversalPatterns := []string{
		"../", "..\\", "....//", "....\\\\", "%2e%2e%2f", "%2e%2e%5c", "..%2f", "..%5c",
	}
	
	lowerPath := strings.ToLower(path)
	for _, pattern := range traversalPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

func (td *ThreatDetector) isSuspiciousUserAgent(userAgent string) bool {
	suspiciousAgents := []string{
		"sqlmap", "nmap", "nikto", "dirb", "gobuster", "wfuzz", "burp", "zap", "nessus", "openvas",
	}
	
	lowerAgent := strings.ToLower(userAgent)
	for _, agent := range suspiciousAgents {
		if strings.Contains(lowerAgent, agent) {
			return true
		}
	}
	return false
}

func (td *ThreatDetector) createThreat(threatType, severity, source, target, description string) Threat {
	return Threat{
		ID:          fmt.Sprintf("threat-%d-%d", time.Now().Unix(), rand.Intn(1000)),
		Type:        threatType,
		Severity:    severity,
		Source:      source,
		Target:      target,
		Description: description,
		Timestamp:   time.Now(),
		Status:      "active",
	}
}

func (td *ThreatDetector) createAlert(alertType, message, severity string) {
	alert := Alert{
		ID:           fmt.Sprintf("alert-%d-%d", time.Now().Unix(), rand.Intn(1000)),
		Type:         alertType,
		Message:      message,
		Severity:     severity,
		Timestamp:    time.Now(),
		Acknowledged: false,
	}
	
	td.alerts = append(td.alerts, alert)
}
