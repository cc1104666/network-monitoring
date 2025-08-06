package main

import (
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// 系统指标
type SystemMetrics struct {
	CPUUsage    float64   `json:"CPUUsage"`
	MemoryUsage float64   `json:"MemoryUsage"`
	DiskUsage   float64   `json:"DiskUsage"`
	NetworkIn   uint64    `json:"NetworkIn"`
	NetworkOut  uint64    `json:"NetworkOut"`
	Timestamp   time.Time `json:"Timestamp"`
}

// 网络连接
type NetworkConnection struct {
	Protocol    string    `json:"Protocol"`
	LocalAddr   string    `json:"LocalAddr"`
	RemoteAddr  string    `json:"RemoteAddr"`
	State       string    `json:"State"`
	Port        int       `json:"Port"`
	ProcessName string    `json:"ProcessName"`
	Timestamp   time.Time `json:"Timestamp"`
}

// HTTP请求
type HTTPRequest struct {
	Method      string    `json:"Method"`
	Path        string    `json:"Path"`
	IP          string    `json:"IP"`
	UserAgent   string    `json:"UserAgent"`
	StatusCode  int       `json:"StatusCode"`
	Size        int       `json:"Size"`
	ThreatScore int       `json:"ThreatScore"`
	Timestamp   time.Time `json:"Timestamp"`
}

// 进程信息
type ProcessInfo struct {
	PID       int       `json:"PID"`
	Name      string    `json:"Name"`
	CPUUsage  float64   `json:"CPUUsage"`
	Memory    float64   `json:"Memory"`
	Status    string    `json:"Status"`
	Timestamp time.Time `json:"Timestamp"`
}

// 威胁信息
type Threat struct {
	ID          string    `json:"ID"`
	Type        string    `json:"Type"`
	Severity    string    `json:"Severity"`
	Source      string    `json:"Source"`
	Target      string    `json:"Target"`
	Description string    `json:"Description"`
	Timestamp   time.Time `json:"Timestamp"`
	Status      string    `json:"Status"`
}

// 告警信息
type Alert struct {
	ID           string    `json:"ID"`
	Type         string    `json:"Type"`
	Message      string    `json:"Message"`
	Severity     string    `json:"Severity"`
	Timestamp    time.Time `json:"Timestamp"`
	Acknowledged bool      `json:"Acknowledged"`
}

// 流量统计数据
type TrafficStats struct {
	Timestamp    time.Time `json:"timestamp"`
	Requests     int       `json:"requests"`
	Threats      int       `json:"threats"`
	ResponseTime float64   `json:"response_time"`
}

// 服务器状态
type ServerStatus struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	IP       string    `json:"ip"`
	Status   string    `json:"status"` // healthy, warning, critical
	CPU      float64   `json:"cpu"`
	Memory   float64   `json:"memory"`
	Requests int       `json:"requests"`
	LastSeen time.Time `json:"last_seen"`
}

// API端点统计
type EndpointStats struct {
	Endpoint     string    `json:"endpoint"`
	Requests     int       `json:"requests"`
	AvgResponse  float64   `json:"avg_response"`
	Status       string    `json:"status"` // normal, suspicious, alert
	LastRequest  time.Time `json:"last_request"`
	RequestRate  float64   `json:"request_rate"` // 每分钟请求数
}

// 威胁告警
type ThreatAlert struct {
	ID             int             `json:"id"`
	Type           string          `json:"type"`        // DDoS, BruteForce, RateLimit
	Severity       string          `json:"severity"`    // critical, high, medium, low
	Endpoint       string          `json:"endpoint"`
	Requests       int             `json:"requests"`
	TimeWindow     string          `json:"time_window"`
	SourceIP       string          `json:"source_ip"`
	Timestamp      time.Time       `json:"timestamp"`
	Description    string          `json:"description"`
	Active         bool            `json:"active"`
	RequestDetails []RequestDetail `json:"request_details,omitempty"`
}

// 网络监控器
type NetworkMonitor struct {
	mu             sync.RWMutex
	trafficData    []TrafficStats
	servers        map[string]*ServerStatus
	endpoints      map[string]*EndpointStats
	clients        map[*WSClient]bool
	requestChan    chan RequestEvent
	maxDataPoints  int
	requestDetails []RequestDetail
	detailsMutex   sync.RWMutex
}

// 威胁检测器
type ThreatDetector struct {
	mu           sync.RWMutex
	alerts       []ThreatAlert
	requestCount map[string]map[string]int // endpoint -> IP -> count
	timeWindows  map[string]time.Time      // endpoint -> last reset time
	alertID      int

	// 新增字段用于真实威胁检测
	ipFailCount  map[string]int       // IP -> 失败次数
	ipLastFail   map[string]time.Time // IP -> 最后失败时间
	systemErrors []string             // 系统错误日志
	processDown  []string             // 停止的进程
}

// 请求事件
type RequestEvent struct {
	Endpoint     string
	IP           string
	ResponseTime float64
	Timestamp    time.Time
	UserAgent    string
}

// WebSocket客户端
type WSClient struct {
	conn     *websocket.Conn
	send     chan []byte
	monitor  *NetworkMonitor
	detector *ThreatDetector
	done     chan struct{}
}

// 请求详情
type RequestDetail struct {
	ID           int       `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	IP           string    `json:"ip"`
	Method       string    `json:"method"`
	Endpoint     string    `json:"endpoint"`
	StatusCode   int       `json:"status_code"`
	ResponseTime int       `json:"response_time"`
	UserAgent    string    `json:"user_agent"`
	RequestSize  int       `json:"request_size"`
	ResponseSize int       `json:"response_size"`
	Referer      string    `json:"referer"`
	Country      string    `json:"country"`
	IsSuspicious bool      `json:"is_suspicious"`
}
