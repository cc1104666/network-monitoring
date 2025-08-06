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

// AnalyzeHTTPRequest analyzes HTTP requests for threats
func (t *ThreatDetector) AnalyzeHTTPRequest(req HTTPRequest) (bool, *Threat) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Check for suspicious patterns
	suspiciousPatterns := []string{
		"../", "..\\", "/etc/passwd", "/etc/shadow", "cmd.exe", "powershell",
		"<script", "javascript:", "onload=", "onerror=", "eval(", "alert(",
		"union select", "drop table", "insert into", "delete from",
		"wp-admin", "admin.php", "login.php", "config.php",
		".env", "backup", "dump", "sql",
	}

	threatType := ""
	severity := "low"
	description := ""

	path := strings.ToLower(req.Path)
	userAgent := strings.ToLower(req.UserAgent)

	// Path traversal detection
	for _, pattern := range suspiciousPatterns[:4] {
		if strings.Contains(path, pattern) {
			threatType = "path_traversal"
			severity = "high"
			description = fmt.Sprintf("Path traversal attempt detected: %s", pattern)
			break
		}
	}

	// XSS detection
	if threatType == "" {
		for _, pattern := range suspiciousPatterns[4:10] {
			if strings.Contains(path, pattern) || strings.Contains(userAgent, pattern) {
				threatType = "xss"
				severity = "medium"
				description = fmt.Sprintf("XSS attempt detected: %s", pattern)
				break
			}
		}
	}

	// SQL injection detection
	if threatType == "" {
		for _, pattern := range suspiciousPatterns[10:14] {
			if strings.Contains(path, pattern) {
				threatType = "sql_injection"
				severity = "high"
				description = fmt.Sprintf("SQL injection attempt detected: %s", pattern)
				break
			}
		}
	}

	// Admin panel scanning
	if threatType == "" {
		for _, pattern := range suspiciousPatterns[14:18] {
			if strings.Contains(path, pattern) {
				threatType = "admin_scan"
				severity = "medium"
				description = fmt.Sprintf("Admin panel scanning detected: %s", pattern)
				break
			}
		}
	}

	// Sensitive file access
	if threatType == "" {
		for _, pattern := range suspiciousPatterns[18:] {
			if strings.Contains(path, pattern) {
				threatType = "sensitive_file_access"
				severity = "medium"
				description = fmt.Sprintf("Sensitive file access attempt: %s", pattern)
				break
			}
		}
	}

	// Suspicious user agents
	suspiciousAgents := []string{"sqlmap", "nikto", "nmap", "masscan", "zap", "burp"}
	for _, agent := range suspiciousAgents {
		if strings.Contains(userAgent, agent) {
			threatType = "scanner"
			severity = "high"
			description = fmt.Sprintf("Security scanner detected: %s", agent)
			break
		}
	}

	// Rate limiting - simple implementation
	if req.StatusCode == 404 && len(req.Path) > 50 {
		threatType = "brute_force"
		severity = "medium"
		description = "Potential brute force attack detected"
	}

	if threatType != "" {
		threat := Threat{
			ID:          fmt.Sprintf("threat-%d", time.Now().UnixNano()),
			Type:        threatType,
			Severity:    severity,
			Source:      req.IP,
			Target:      req.Path,
			Description: description,
			Timestamp:   req.Timestamp,
			Status:      "active",
		}

		t.threats = append(t.threats, threat)

		// Create corresponding alert
		alert := AlertInfo{
			ID:           fmt.Sprintf("alert-%d", time.Now().UnixNano()),
			Type:         "security",
			Message:      fmt.Sprintf("Security threat from %s: %s", req.IP, description),
			Severity:     severity,
			Timestamp:    time.Now(),
			Acknowledged: false,
		}
		t.alerts = append(t.alerts, alert)

		// Keep only last 100 threats and alerts
		if len(t.threats) > 100 {
			t.threats = t.threats[len(t.threats)-100:]
		}
		if len(t.alerts) > 100 {
			t.alerts = t.alerts[len(t.alerts)-100:]
		}

		return true, &threat
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

// ClearOldThreats removes threats older than the specified duration
func (t *ThreatDetector) ClearOldThreats(maxAge time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	
	// Filter threats
	var newThreats []Threat
	for _, threat := range t.threats {
		if threat.Timestamp.After(cutoff) {
			newThreats = append(newThreats, threat)
		}
	}
	t.threats = newThreats

	// Filter alerts
	var newAlerts []AlertInfo
	for _, alert := range t.alerts {
		if alert.Timestamp.After(cutoff) {
			newAlerts = append(newAlerts, alert)
		}
	}
	t.alerts = newAlerts
}

// GenerateMockThreats generates some mock threats for demonstration
func (t *ThreatDetector) GenerateMockThreats() {
	t.mu.Lock()
	defer t.mu.Unlock()

	mockThreats := []Threat{
		{
			ID:          "threat-demo-1",
			Type:        "sql_injection",
			Severity:    "high",
			Source:      "192.168.1.100",
			Target:      "/login.php",
			Description: "SQL injection attempt detected in login form",
			Timestamp:   time.Now().Add(-5 * time.Minute),
			Status:      "active",
		},
		{
			ID:          "threat-demo-2",
			Type:        "xss",
			Severity:    "medium",
			Source:      "10.0.0.50",
			Target:      "/search",
			Description: "Cross-site scripting attempt in search parameter",
			Timestamp:   time.Now().Add(-10 * time.Minute),
			Status:      "active",
		},
		{
			ID:          "threat-demo-3",
			Type:        "brute_force",
			Severity:    "high",
			Source:      "203.0.113.45",
			Target:      "/admin",
			Description: "Multiple failed login attempts detected",
			Timestamp:   time.Now().Add(-15 * time.Minute),
			Status:      "blocked",
		},
	}

	t.threats = append(t.threats, mockThreats...)

	// Generate corresponding alerts
	for _, threat := range mockThreats {
		alert := AlertInfo{
			ID:           fmt.Sprintf("alert-%s", threat.ID),
			Type:         "security",
			Message:      fmt.Sprintf("Security threat from %s: %s", threat.Source, threat.Description),
			Severity:     threat.Severity,
			Timestamp:    threat.Timestamp,
			Acknowledged: false,
		}
		t.alerts = append(t.alerts, alert)
	}
}

// AddThreat adds a new threat
func (t *ThreatDetector) AddThreat(threat Threat) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.threats = append(t.threats, threat)

	// Create corresponding alert
	alert := AlertInfo{
		ID:           fmt.Sprintf("alert-%d", time.Now().UnixNano()),
		Type:         "security",
		Message:      fmt.Sprintf("New threat detected: %s", threat.Description),
		Severity:     threat.Severity,
		Timestamp:    time.Now(),
		Acknowledged: false,
	}
	t.alerts = append(t.alerts, alert)
}

// GenerateRandomThreat generates a random threat for testing
func (t *ThreatDetector) GenerateRandomThreat() {
	threatTypes := []string{"sql_injection", "xss", "brute_force", "ddos", "malware"}
	severities := []string{"low", "medium", "high", "critical"}
	sources := []string{"192.168.1.100", "10.0.0.50", "203.0.113.45", "198.51.100.25"}
	targets := []string{"/login", "/admin", "/api/users", "/upload", "/search"}

	threat := Threat{
		ID:          fmt.Sprintf("threat-random-%d", time.Now().UnixNano()),
		Type:        threatTypes[rand.Intn(len(threatTypes))],
		Severity:    severities[rand.Intn(len(severities))],
		Source:      sources[rand.Intn(len(sources))],
		Target:      targets[rand.Intn(len(targets))],
		Description: "Randomly generated threat for testing",
		Timestamp:   time.Now(),
		Status:      "active",
	}

	t.AddThreat(threat)
}
