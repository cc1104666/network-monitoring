package main

import (
	"time"
)

// SystemMetrics represents system performance metrics
type SystemMetrics struct {
	ServerID     string         `json:"server_id"`
	ServerName   string         `json:"server_name"`
	ServerIP     string         `json:"server_ip"`
	Timestamp    string         `json:"timestamp"`
	CPU          float64        `json:"cpu"`
	Memory       float64        `json:"memory"`
	Disk         float64        `json:"disk"`
	Network      NetworkMetrics `json:"network"`
	Status       string         `json:"status"`
	LoadAverage  []float64      `json:"load_average"`
	ProcessCount int            `json:"process_count"`
}

// NetworkMetrics represents network statistics
type NetworkMetrics struct {
	BytesSent    uint64 `json:"bytes_sent"`
	BytesRecv    uint64 `json:"bytes_recv"`
	PacketsSent  uint64 `json:"packets_sent"`
	PacketsRecv  uint64 `json:"packets_recv"`
	Connections  int    `json:"connections"`
}

// NetworkConnection represents a network connection
type NetworkConnection struct {
	Protocol    string `json:"protocol"`
	LocalAddr   string `json:"local_addr"`
	RemoteAddr  string `json:"remote_addr"`
	State       string `json:"state"`
	Port        int    `json:"port"`
	ProcessName string `json:"process_name"`
	PID         int    `json:"pid"`
	Timestamp   string `json:"timestamp"`
}

// ProcessInfo represents process information
type ProcessInfo struct {
	PID         int     `json:"pid"`
	Name        string  `json:"name"`
	CPUPercent  float64 `json:"cpu_percent"`
	MemoryMB    float64 `json:"memory_mb"`
	Status      string  `json:"status"`
	CreateTime  string  `json:"create_time"`
}

// Threat represents a security threat
type Threat struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Source      string                 `json:"source"`
	Target      string                 `json:"target"`
	Description string                 `json:"description"`
	Timestamp   string                 `json:"timestamp"`
	Status      string                 `json:"status"`
	Details     map[string]interface{} `json:"details"`
}

// AlertInfo represents system alerts
type AlertInfo struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`
	Message      string                 `json:"message"`
	Severity     string                 `json:"severity"`
	Source       string                 `json:"source"`
	Timestamp    string                 `json:"timestamp"`
	Acknowledged bool                   `json:"acknowledged"`
	Details      map[string]interface{} `json:"details"`
}

// SystemInfo represents basic system information
type SystemInfo struct {
	Hostname           string    `json:"hostname"`
	Uptime            string    `json:"uptime"`
	LoadAverage       []float64 `json:"load_average"`
	MemoryUsage       float64   `json:"memory_usage"`
	DiskUsage         float64   `json:"disk_usage"`
	NetworkInterfaces []string  `json:"network_interfaces"`
	ActiveConnections int       `json:"active_connections"`
	ListeningPorts    []int     `json:"listening_ports"`
}

// NetworkStats 网络统计结构
type NetworkStats struct {
	TotalRequests     int    `json:"total_requests"`
	BlockedRequests   int    `json:"blocked_requests"`
	SuspiciousIPs     int    `json:"suspicious_ips"`
	ThreatLevel       string `json:"threat_level"`
	LastAttack        string `json:"last_attack"`
	ActiveConnections int    `json:"active_connections"`
}

// ThreatInfo 威胁信息结构
type ThreatInfo struct {
	IP            string    `json:"ip"`
	Country       string    `json:"country"`
	ThreatType    string    `json:"threat_type"`
	Severity      string    `json:"severity"`
	Timestamp     time.Time `json:"timestamp"`
	Blocked       bool      `json:"blocked"`
	RequestsCount int       `json:"requests_count"`
}

// LogEntry 日志条目结构
type LogEntry struct {
	Timestamp  string `json:"timestamp"`
	Level      string `json:"level"`
	Message    string `json:"message"`
	IP         string `json:"ip,omitempty"`
	ThreatType string `json:"threat_type,omitempty"`
}

// ConnectionInfo 连接信息结构
type ConnectionInfo struct {
	LocalAddr   string `json:"local_addr"`
	RemoteAddr  string `json:"remote_addr"`
	State       string `json:"state"`
	ProcessName string `json:"process_name"`
	PID         int    `json:"pid"`
}

// NetworkInterface 网络接口结构
type NetworkInterface struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	IsUp      bool     `json:"is_up"`
	BytesSent int64    `json:"bytes_sent"`
	BytesRecv int64    `json:"bytes_recv"`
}

// DiskInfo 磁盘信息结构
type DiskInfo struct {
	Device     string  `json:"device"`
	Mountpoint string  `json:"mountpoint"`
	Fstype     string  `json:"fstype"`
	Total      uint64  `json:"total"`
	Used       uint64  `json:"used"`
	Free       uint64  `json:"free"`
	Percent    float64 `json:"percent"`
}

// MemoryInfo 内存信息结构
type MemoryInfo struct {
	Total       uint64  `json:"total"`
	Available   uint64  `json:"available"`
	Used        uint64  `json:"used"`
	UsedPercent float64 `json:"used_percent"`
	Free        uint64  `json:"free"`
	Buffers     uint64  `json:"buffers"`
	Cached      uint64  `json:"cached"`
}

// CPUInfo CPU信息结构
type CPUInfo struct {
	ModelName string    `json:"model_name"`
	Cores     int       `json:"cores"`
	Usage     []float64 `json:"usage"`
	Frequency float64   `json:"frequency"`
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
