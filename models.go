package main

import (
	"time"
)

// SystemMetrics represents system performance metrics
type SystemMetrics struct {
	ServerID   string       `json:"server_id"`
	ServerName string       `json:"server_name"`
	ServerIP   string       `json:"server_ip"`
	Timestamp  time.Time    `json:"timestamp"`
	CPU        float64      `json:"cpu"`
	Memory     float64      `json:"memory"`
	Disk       float64      `json:"disk"`
	Network    NetworkStats `json:"network"`
	Status     string       `json:"status"`
}

// NetworkStats holds network IO counters
type NetworkStats struct {
	BytesSent   uint64 `json:"bytes_sent"`
	BytesRecv   uint64 `json:"bytes_recv"`
	PacketsSent uint64 `json:"packets_sent"`
	PacketsRecv uint64 `json:"packets_recv"`
}

// NetworkConnection represents an active network connection
type NetworkConnection struct {
	Protocol    string    `json:"protocol"`
	LocalAddr   string    `json:"local_addr"`
	RemoteAddr  string    `json:"remote_addr"`
	State       string    `json:"state"`
	Port        uint32    `json:"port"`
	ProcessName string    `json:"process_name"`
	PID         int32     `json:"pid"`
	Timestamp   time.Time `json:"timestamp"`
}

// ProcessInfo holds information about a running process
type ProcessInfo struct {
	PID       int32     `json:"pid"`
	Name      string    `json:"name"`
	CPUUsage  float64   `json:"cpu_usage"`
	Memory    float32   `json:"memory"`
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

// Threat represents a detected security threat
type Threat struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Source      string    `json:"source"`
	Target      string    `json:"target"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	Status      string    `json:"status"`
}

// Alert represents a notification-worthy event
type Alert struct {
	ID           string    `json:"id"`
	Type         string    `json:"type"`
	Message      string    `json:"message"`
	Severity     string    `json:"severity"`
	Timestamp    time.Time `json:"timestamp"`
	Acknowledged bool      `json:"acknowledged"`
}

// SystemInfo holds static information about the host system
type SystemInfo struct {
	Hostname        string `json:"hostname"`
	OS              string `json:"os"`
	Platform        string `json:"platform"`
	Uptime          uint64 `json:"uptime"`
	CPUModel        string `json:"cpu_model"`
	CPUCores        int    `json:"cpu_cores"`
	TotalMemory     uint64 `json:"total_memory"`
	RealDataEnabled bool   `json:"real_data_enabled"`
}

// HTTPRequest represents an HTTP request for threat analysis
type HTTPRequest struct {
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	IP         string    `json:"ip"`
	UserAgent  string    `json:"user_agent"`
	StatusCode int       `json:"status_code"`
	Size       int64     `json:"size"`
	Timestamp  time.Time `json:"timestamp"`
}

// WebSocketMessage represents a WebSocket message
type WebSocketMessage struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

// ServerStatus represents server status information
type ServerStatus struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	IP       string    `json:"ip"`
	Status   string    `json:"status"`
	Uptime   uint64    `json:"uptime"`
	LastSeen time.Time `json:"last_seen"`
}

// EndpointStats represents endpoint statistics
type EndpointStats struct {
	Path         string    `json:"path"`
	Method       string    `json:"method"`
	RequestCount int64     `json:"request_count"`
	ErrorCount   int64     `json:"error_count"`
	AvgResponse  float64   `json:"avg_response_time"`
	LastAccess   time.Time `json:"last_access"`
}

// RequestDetail represents detailed request information
type RequestDetail struct {
	ID         string            `json:"id"`
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	IP         string            `json:"ip"`
	UserAgent  string            `json:"user_agent"`
	Headers    map[string]string `json:"headers"`
	StatusCode int               `json:"status_code"`
	Size       int64             `json:"size"`
	Duration   time.Duration     `json:"duration"`
	Timestamp  time.Time         `json:"timestamp"`
}

// ThreatLevel represents threat severity levels
type ThreatLevel string

const (
	ThreatLevelLow      ThreatLevel = "low"
	ThreatLevelMedium   ThreatLevel = "medium"
	ThreatLevelHigh     ThreatLevel = "high"
	ThreatLevelCritical ThreatLevel = "critical"
)

// ThreatType represents different types of threats
type ThreatType string

const (
	ThreatTypeSQLInjection     ThreatType = "sql_injection"
	ThreatTypeXSS              ThreatType = "xss"
	ThreatTypePathTraversal    ThreatType = "path_traversal"
	ThreatTypeBruteForce       ThreatType = "brute_force"
	ThreatTypeCommandInjection ThreatType = "command_injection"
	ThreatTypeUnauthorized     ThreatType = "unauthorized_access"
	ThreatTypeSuspicious       ThreatType = "suspicious_activity"
	ThreatTypeScanning         ThreatType = "scanning_tool"
)

// AlertType represents different types of alerts
type AlertType string

const (
	AlertTypeSecurity    AlertType = "security"
	AlertTypePerformance AlertType = "performance"
	AlertTypeSystem      AlertType = "system"
	AlertTypeNetwork     AlertType = "network"
)

// SystemStatus represents overall system status
type SystemStatus string

const (
	SystemStatusHealthy  SystemStatus = "healthy"
	SystemStatusWarning  SystemStatus = "warning"
	SystemStatusCritical SystemStatus = "critical"
	SystemStatusDown     SystemStatus = "down"
)
