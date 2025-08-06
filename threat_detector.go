package main

import (
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"
)

// ThreatDetector analyzes HTTP requests for potential security threats
type ThreatDetector struct {
	threats []Threat
	alerts  []Alert
}

// NewThreatDetector creates a new threat detector
func NewThreatDetector() *ThreatDetector {
	return &ThreatDetector{
		threats: make([]Threat, 0),
		alerts:  make([]Alert, 0),
	}
}

// AnalyzeRequest analyzes an HTTP request for potential threats
func (td *ThreatDetector) AnalyzeRequest(req HTTPRequest) []Threat {
	var threats []Threat

	// SQL Injection detection
	if td.detectSQLInjection(req.Path) {
		threat := Threat{
			ID:          fmt.Sprintf("threat-%d", time.Now().UnixNano()),
			Type:        "sql_injection",
			Severity:    "high",
			Source:      req.IP,
			Target:      req.Path,
			Description: fmt.Sprintf("Potential SQL injection attempt from %s on path %s", req.IP, req.Path),
			Timestamp:   time.Now(),
			Status:      "active",
		}
		threats = append(threats, threat)
		td.threats = append(td.threats, threat)
		log.Printf("🚨 SQL Injection detected: %s -> %s", req.IP, req.Path)
	}

	// XSS detection
	if td.detectXSS(req.Path) {
		threat := Threat{
			ID:          fmt.Sprintf("threat-%d", time.Now().UnixNano()),
			Type:        "xss",
			Severity:    "medium",
			Source:      req.IP,
			Target:      req.Path,
			Description: fmt.Sprintf("Potential XSS attempt from %s on path %s", req.IP, req.Path),
			Timestamp:   time.Now(),
			Status:      "active",
		}
		threats = append(threats, threat)
		td.threats = append(td.threats, threat)
		log.Printf("🚨 XSS detected: %s -> %s", req.IP, req.Path)
	}

	// Path traversal detection
	if td.detectPathTraversal(req.Path) {
		threat := Threat{
			ID:          fmt.Sprintf("threat-%d", time.Now().UnixNano()),
			Type:        "path_traversal",
			Severity:    "high",
			Source:      req.IP,
			Target:      req.Path,
			Description: fmt.Sprintf("Potential path traversal attempt from %s on path %s", req.IP, req.Path),
			Timestamp:   time.Now(),
			Status:      "active",
		}
		threats = append(threats, threat)
		td.threats = append(td.threats, threat)
		log.Printf("🚨 Path Traversal detected: %s -> %s", req.IP, req.Path)
	}

	// Brute force detection (based on status code and user agent)
	if td.detectBruteForce(req) {
		threat := Threat{
			ID:          fmt.Sprintf("threat-%d", time.Now().UnixNano()),
			Type:        "brute_force",
			Severity:    "medium",
			Source:      req.IP,
			Target:      req.Path,
			Description: fmt.Sprintf("Potential brute force attempt from %s", req.IP),
			Timestamp:   time.Now(),
			Status:      "active",
		}
		threats = append(threats, threat)
		td.threats = append(td.threats, threat)
		log.Printf("🚨 Brute Force detected: %s", req.IP)
	}

	// Scanning tool detection
	if td.detectScanningTool(req.UserAgent) {
		threat := Threat{
			ID:          fmt.Sprintf("threat-%d", time.Now().UnixNano()),
			Type:        "scanning_tool",
			Severity:    "low",
			Source:      req.IP,
			Target:      req.Path,
			Description: fmt.Sprintf("Scanning tool detected from %s: %s", req.IP, req.UserAgent),
			Timestamp:   time.Now(),
			Status:      "active",
		}
		threats = append(threats, threat)
		td.threats = append(td.threats, threat)
		log.Printf("🚨 Scanning Tool detected: %s (%s)", req.IP, req.UserAgent)
	}

	return threats
}

// detectSQLInjection checks for SQL injection patterns
func (td *ThreatDetector) detectSQLInjection(path string) bool {
	sqlPatterns := []string{
		"'", "\"", ";", "--", "/*", "*/", "xp_", "sp_",
		"union", "select", "insert", "delete", "update",
		"drop", "create", "alter", "exec", "execute",
		"script", "javascript", "vbscript", "onload",
		"onerror", "onclick", "alert", "confirm",
	}

	lowerPath := strings.ToLower(path)
	for _, pattern := range sqlPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

// detectXSS checks for XSS patterns
func (td *ThreatDetector) detectXSS(path string) bool {
	xssPatterns := []string{
		"<script", "</script>", "javascript:", "vbscript:",
		"onload=", "onerror=", "onclick=", "onmouseover=",
		"alert(", "confirm(", "prompt(", "document.cookie",
		"document.write", "innerHTML", "eval(",
	}

	lowerPath := strings.ToLower(path)
	for _, pattern := range xssPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

// detectPathTraversal checks for path traversal patterns
func (td *ThreatDetector) detectPathTraversal(path string) bool {
	traversalPatterns := []string{
		"../", "..\\", "....//", "....\\\\",
		"%2e%2e%2f", "%2e%2e%5c", "%252e%252e%252f",
		"..%2f", "..%5c", "%2e%2e/", "%2e%2e\\",
	}

	lowerPath := strings.ToLower(path)
	for _, pattern := range traversalPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

// detectBruteForce checks for brute force patterns
func (td *ThreatDetector) detectBruteForce(req HTTPRequest) bool {
	// Simple heuristic: multiple failed login attempts
	if req.StatusCode == 401 || req.StatusCode == 403 {
		if strings.Contains(strings.ToLower(req.Path), "login") ||
			strings.Contains(strings.ToLower(req.Path), "auth") ||
			strings.Contains(strings.ToLower(req.Path), "signin") {
			return true
		}
	}
	return false
}

// detectScanningTool checks for known scanning tool user agents
func (td *ThreatDetector) detectScanningTool(userAgent string) bool {
	scanningTools := []string{
		"nmap", "nikto", "sqlmap", "dirb", "dirbuster",
		"gobuster", "wfuzz", "burp", "zap", "acunetix",
		"nessus", "openvas", "w3af", "skipfish", "arachni",
		"curl", "wget", "python-requests", "go-http-client",
	}

	lowerUA := strings.ToLower(userAgent)
	for _, tool := range scanningTools {
		if strings.Contains(lowerUA, tool) {
			return true
		}
	}
	return false
}

// GetThreats returns all detected threats
func (td *ThreatDetector) GetThreats() []Threat {
	return td.threats
}

// GetAlerts returns all alerts
func (td *ThreatDetector) GetAlerts() []Alert {
	return td.alerts
}

// GenerateMockThreats generates mock threats for demonstration
func (td *ThreatDetector) GenerateMockThreats() {
	mockThreats := []Threat{
		{
			ID:          fmt.Sprintf("threat-%d", time.Now().UnixNano()),
			Type:        "sql_injection",
			Severity:    "high",
			Source:      "192.168.1.100",
			Target:      "/login.php?id=1' OR '1'='1",
			Description: "SQL injection attempt detected on login form",
			Timestamp:   time.Now().Add(-time.Minute * 5),
			Status:      "active",
		},
		{
			ID:          fmt.Sprintf("threat-%d", time.Now().UnixNano()+1),
			Type:        "xss",
			Severity:    "medium",
			Source:      "10.0.0.50",
			Target:      "/search?q=<script>alert('xss')</script>",
			Description: "Cross-site scripting attempt in search parameter",
			Timestamp:   time.Now().Add(-time.Minute * 3),
			Status:      "active",
		},
		{
			ID:          fmt.Sprintf("threat-%d", time.Now().UnixNano()+2),
			Type:        "brute_force",
			Severity:    "medium",
			Source:      "203.0.113.45",
			Target:      "/admin/login",
			Description: "Multiple failed login attempts detected",
			Timestamp:   time.Now().Add(-time.Minute * 1),
			Status:      "active",
		},
		{
			ID:          fmt.Sprintf("threat-%d", time.Now().UnixNano()+3),
			Type:        "scanning_tool",
			Severity:    "low",
			Source:      "198.51.100.25",
			Target:      "/",
			Description: "Automated scanning tool detected (Nikto)",
			Timestamp:   time.Now().Add(-time.Second * 30),
			Status:      "active",
		},
	}

	td.threats = append(td.threats, mockThreats...)

	// Generate corresponding alerts
	for _, threat := range mockThreats {
		alert := Alert{
			ID:           fmt.Sprintf("alert-%d", time.Now().UnixNano()+rand.Int63n(1000)),
			Type:         "security",
			Message:      fmt.Sprintf("Security threat detected: %s from %s", threat.Type, threat.Source),
			Severity:     threat.Severity,
			Timestamp:    threat.Timestamp,
			Acknowledged: false,
		}
		td.alerts = append(td.alerts, alert)
	}

	log.Printf("✅ Generated %d mock threats and %d alerts", len(mockThreats), len(mockThreats))
}

// ClearOldThreats removes threats older than specified duration
func (td *ThreatDetector) ClearOldThreats(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	var activeThreats []Threat

	for _, threat := range td.threats {
		if threat.Timestamp.After(cutoff) {
			activeThreats = append(activeThreats, threat)
		}
	}

	removed := len(td.threats) - len(activeThreats)
	td.threats = activeThreats

	if removed > 0 {
		log.Printf("🧹 Cleaned up %d old threats", removed)
	}
}

// GetThreatStats returns threat statistics
func (td *ThreatDetector) GetThreatStats() map[string]int {
	stats := make(map[string]int)
	
	for _, threat := range td.threats {
		stats[threat.Type]++
		stats["total"]++
		
		switch threat.Severity {
		case "low":
			stats["low_severity"]++
		case "medium":
			stats["medium_severity"]++
		case "high":
			stats["high_severity"]++
		case "critical":
			stats["critical_severity"]++
		}
	}
	
	return stats
}
