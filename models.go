package main

import (
	"time"
	netutil "github.com/shirou/gopsutil/v3/net"
)

// RealDataCollector collects real system data
type RealDataCollector struct {
	hostname         string
	enabled          bool
	networkStats     *NetworkStats
	connections      []ConnectionInfo
	processes        []ProcessInfo
	startTime        time.Time
	lastNetworkStats netutil.IOCountersStat
	lastUpdateTime   time.Time
}

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
	PID         int32   `json:"pid"`
	Name        string  `json:"name"`
	CPUPercent  float64 `json:"cpu_percent"`
	MemoryMB    float32 `json:"memory_mb"`
	Status      string  `json:"status"`
	CreateTime  int64   `json:"create_time"`
	Connections int     `json:"connections"`
}

// Threat represents a security threat
type Threat struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Level       string    `json:"level"`
	Source      string    `json:"source"`
	Target      string    `json:"target"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	Count       int       `json:"count"`
	Status      string    `json:"status"`
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
	Hostname        string `json:"hostname"`
	OS              string `json:"os"`
	Platform        string `json:"platform"`
	PlatformVersion string `json:"platform_version"`
	Architecture    string `json:"architecture"`
	Uptime          uint64 `json:"uptime"`
	BootTime        uint64 `json:"boot_time"`
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
	Protocol    string `json:"protocol"`
	LocalAddr   string `json:"local_addr"`
	RemoteAddr  string `json:"remote_addr"`
	State       string `json:"state"`
	ProcessName string `json:"process_name"`
	PID         int    `json:"pid"`
	Timestamp   string `json:"timestamp"`
}

// NetworkInterface 网络接口结构
type NetworkInterface struct {
	Name      string `json:"name"`
	BytesSent uint64 `json:"bytes_sent"`
	BytesRecv uint64 `json:"bytes_recv"`
	IsUp      bool   `json:"is_up"`
}

// DiskInfo 磁盘信息结构
type DiskInfo struct {
	Device        string  `json:"device"`
	Mountpoint    string  `json:"mountpoint"`
	Fstype        string  `json:"fstype"`
	Total         uint64  `json:"total"`
	Used          uint64  `json:"used"`
	Free          uint64  `json:"free"`
	UsagePercent  float64 `json:"usage_percent"`
}

// MemoryInfo 内存信息结构
type MemoryInfo struct {
	Total        uint64  `json:"total"`
	Available    uint64  `json:"available"`
	Used         uint64  `json:"used"`
	UsedPercent  float64 `json:"used_percent"`
	Free         uint64  `json:"free"`
	Buffers      uint64  `json:"buffers"`
	Cached       uint64  `json:"cached"`
	SwapTotal    uint64  `json:"swap_total"`
	SwapUsed     uint64  `json:"swap_used"`
}

// CPUInfo CPU信息结构
type CPUInfo struct {
	Cores     int     `json:"cores"`
	Usage     float64 `json:"usage"`
	LoadAvg   float64 `json:"load_avg"`
	Frequency float64 `json:"frequency"`
}

// NetworkInfo 网络信息结构
type NetworkInfo struct {
	BytesSent     uint64             `json:"bytes_sent"`
	BytesRecv     uint64             `json:"bytes_recv"`
	PacketsSent   uint64             `json:"packets_sent"`
	PacketsRecv   uint64             `json:"packets_recv"`
	Connections   int                `json:"connections"`
	ListenPorts   []int              `json:"listen_ports"`
	Interfaces    []NetworkInterface `json:"interfaces"`
}

// SystemData 系统数据结构
type SystemData struct {
	Timestamp   time.Time        `json:"timestamp"`
	CPU         CPUInfo          `json:"cpu"`
	Memory      MemoryInfo       `json:"memory"`
	Disk        DiskInfo         `json:"disk"`
	Network     NetworkInfo      `json:"network"`
	Processes   []ProcessInfo    `json:"processes"`
	Connections []ConnectionInfo `json:"connections"`
	Threats     []Threat         `json:"threats"`
	SystemInfo  SystemInfo       `json:"system_info"`
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

// Connection 网络连接
type Connection struct {
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	Status     string `json:"status"`
	PID        int32  `json:"pid"`
	Process    string `json:"process"`
}

// Agent 代理信息
type Agent struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Host     string    `json:"host"`
	Port     int       `json:"port"`
	Status   string    `json:"status"`
	LastSeen time.Time `json:"last_seen"`
	Version  string    `json:"version"`
	OS       string    `json:"os"`
}

// AlertRule 告警规则
type AlertRule struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Type        string  `json:"type"`
	Condition   string  `json:"condition"`
	Threshold   float64 `json:"threshold"`
	Enabled     bool    `json:"enabled"`
	Description string  `json:"description"`
}

// Alert 告警信息
type Alert struct {
	ID          string    `json:"id"`
	RuleID      string    `json:"rule_id"`
	Level       string    `json:"level"`
	Title       string    `json:"title"`
	Message     string    `json:"message"`
	Timestamp   time.Time `json:"timestamp"`
	Status      string    `json:"status"`
	Source      string    `json:"source"`
}
