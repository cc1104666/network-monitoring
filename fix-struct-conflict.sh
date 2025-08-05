#!/bin/bash

echo "🔧 修复结构体冲突问题..."

# 设置Go环境
export PATH=$PATH:/usr/local/go/bin
export GOPROXY=https://goproxy.cn,direct

# 备份原文件
echo "💾 备份原文件..."
cp models.go models.go.backup
cp threat_detector.go threat_detector.go.backup

# 修复models.go中的ThreatDetector结构体
echo "📝 修复models.go..."
cat > models.go << 'EOF'
package main

import (
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

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

// 系统指标结构 - 从agent.go移动到这里避免重复
type SystemMetrics struct {
	ServerID   string    `json:"server_id"`
	ServerName string    `json:"server_name"`
	ServerIP   string    `json:"server_ip"`
	Timestamp  time.Time `json:"timestamp"`
	CPU        float64   `json:"cpu"`
	Memory     float64   `json:"memory"`
	Disk       float64   `json:"disk"`
	Network    struct {
		BytesSent   uint64 `json:"bytes_sent"`
		BytesRecv   uint64 `json:"bytes_recv"`
		PacketsSent uint64 `json:"packets_sent"`
		PacketsRecv uint64 `json:"packets_recv"`
	} `json:"network"`
	Status string `json:"status"`
}
EOF

# 修复threat_detector.go，移除重复的结构体定义
echo "📝 修复threat_detector.go..."
cat > threat_detector.go << 'EOF'
package main

import (
	"log"
	"sync"
	"time"
)

func NewThreatDetector() *ThreatDetector {
	return &ThreatDetector{
		mu:           sync.RWMutex{},
		alerts:       make([]ThreatAlert, 0),
		requestCount: make(map[string]map[string]int),
		timeWindows:  make(map[string]time.Time),
		alertID:      1,
		ipFailCount:  make(map[string]int),
		ipLastFail:   make(map[string]time.Time),
		systemErrors: make([]string, 0),
		processDown:  make([]string, 0),
	}
}

func (td *ThreatDetector) Start() {
	go td.monitorThreats()
	log.Println("威胁检测器已启动")
}

func (td *ThreatDetector) monitorThreats() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		td.analyzeThreats()
		td.cleanupOldAlerts()
	}
}

// 处理真实请求
func (td *ThreatDetector) processRequest(ip, endpoint string, statusCode int) {
	td.mu.Lock()
	defer td.mu.Unlock()
	
	// 初始化数据结构
	if td.requestCount[endpoint] == nil {
		td.requestCount[endpoint] = make(map[string]int)
	}
	
	td.requestCount[endpoint][ip]++
	
	// 检查是否需要重置时间窗口
	if lastReset, exists := td.timeWindows[endpoint]; !exists || time.Since(lastReset) > 5*time.Minute {
		td.timeWindows[endpoint] = time.Now()
		td.requestCount[endpoint] = make(map[string]int)
		td.requestCount[endpoint][ip] = 1
	}
	
	// 检测异常请求频率
	if td.requestCount[endpoint][ip] > 100 { // 5分钟内超过100次请求
		td.createThreatAlert("RateLimit", "high", endpoint, ip, 
			td.requestCount[endpoint][ip], "检测到异常高频请求")
	}
	
	// 检测HTTP错误
	if statusCode >= 400 {
		td.checkHTTPErrors(ip, endpoint, statusCode)
	}
}

// 记录登录失败
func (td *ThreatDetector) recordFailedLogin(ip string) {
	td.mu.Lock()
	defer td.mu.Unlock()
	
	td.ipFailCount[ip]++
	td.ipLastFail[ip] = time.Now()
	
	// 检测暴力破解攻击
	if td.ipFailCount[ip] > 5 { // 5次失败登录
		td.createThreatAlert("BruteForce", "critical", "/login", ip, 
			td.ipFailCount[ip], "检测到暴力破解攻击")
	}
}

// 记录系统错误
func (td *ThreatDetector) recordSystemError(errorMsg string) {
	td.mu.Lock()
	defer td.mu.Unlock()
	
	td.systemErrors = append(td.systemErrors, errorMsg)
	
	// 保持最新100条错误
	if len(td.systemErrors) > 100 {
		td.systemErrors = td.systemErrors[1:]
	}
	
	// 检测系统异常
	if len(td.systemErrors) > 10 { // 短时间内大量错误
		td.createThreatAlert("SystemError", "medium", "/system", "localhost", 
			len(td.systemErrors), "检测到系统异常")
	}
}

// 记录进程停止
func (td *ThreatDetector) recordProcessDown(processName string) {
	td.mu.Lock()
	defer td.mu.Unlock()
	
	// 检查是否已经记录
	for _, process := range td.processDown {
		if process == processName {
			return
		}
	}
	
	td.processDown = append(td.processDown, processName)
	
	td.createThreatAlert("ProcessDown", "critical", "/system", "localhost", 
		1, "关键进程停止: "+processName)
}

// 检测HTTP错误
func (td *ThreatDetector) checkHTTPErrors(ip, endpoint string, statusCode int) {
	// 404错误可能表示扫描行为
	if statusCode == 404 {
		key := ip + "_404"
		if td.requestCount["_404_scan"] == nil {
			td.requestCount["_404_scan"] = make(map[string]int)
		}
		td.requestCount["_404_scan"][key]++
		
		if td.requestCount["_404_scan"][key] > 20 { // 20个404错误
			td.createThreatAlert("Scanning", "medium", endpoint, ip, 
				td.requestCount["_404_scan"][key], "检测到可能的扫描行为")
		}
	}
	
	// 5xx错误可能表示攻击
	if statusCode >= 500 {
		key := ip + "_5xx"
		if td.requestCount["_5xx_errors"] == nil {
			td.requestCount["_5xx_errors"] = make(map[string]int)
		}
		td.requestCount["_5xx_errors"][key]++
		
		if td.requestCount["_5xx_errors"][key] > 10 { // 10个5xx错误
			td.createThreatAlert("ServerError", "high", endpoint, ip, 
				td.requestCount["_5xx_errors"][key], "检测到服务器错误攻击")
		}
	}
}

// 创建威胁告警
func (td *ThreatDetector) createThreatAlert(alertType, severity, endpoint, sourceIP string, requests int, description string) {
	alert := ThreatAlert{
		ID:          td.alertID,
		Type:        alertType,
		Severity:    severity,
		Endpoint:    endpoint,
		Requests:    requests,
		TimeWindow:  "5分钟",
		SourceIP:    sourceIP,
		Timestamp:   time.Now(),
		Description: description,
		Active:      true,
	}
	
	td.alerts = append(td.alerts, alert)
	td.alertID++
	
	// 保持最新100个告警
	if len(td.alerts) > 100 {
		td.alerts = td.alerts[1:]
	}
	
	log.Printf("🚨 威胁告警: %s - %s (来源: %s)", alertType, description, sourceIP)
}

// 分析威胁
func (td *ThreatDetector) analyzeThreats() {
	td.mu.Lock()
	defer td.mu.Unlock()
	
	// 分析IP行为模式
	td.analyzeIPBehavior()
	
	// 分析端点访问模式
	td.analyzeEndpointPatterns()
	
	// 清理过期数据
	td.cleanupExpiredData()
}

// 分析IP行为模式
func (td *ThreatDetector) analyzeIPBehavior() {
	ipRequestCounts := make(map[string]int)
	
	// 统计每个IP的总请求数
	for _, endpointMap := range td.requestCount {
		for ip, count := range endpointMap {
			if ip != "_404_scan" && ip != "_5xx_errors" {
				ipRequestCounts[ip] += count
			}
		}
	}
	
	// 检测异常活跃的IP
	for ip, totalRequests := range ipRequestCounts {
		if totalRequests > 500 { // 5分钟内超过500次请求
			td.createThreatAlert("DDoS", "critical", "/", ip, 
				totalRequests, "检测到可能的DDoS攻击")
		}
	}
}

// 分析端点访问模式
func (td *ThreatDetector) analyzeEndpointPatterns() {
	for endpoint, ipMap := range td.requestCount {
		if endpoint == "_404_scan" || endpoint == "_5xx_errors" {
			continue
		}
		
		totalRequests := 0
		for _, count := range ipMap {
			totalRequests += count
		}
		
		// 检测端点异常访问
		if totalRequests > 1000 { // 5分钟内超过1000次请求
			td.createThreatAlert("EndpointFlood", "high", endpoint, "multiple", 
				totalRequests, "检测到端点异常访问")
		}
	}
}

// 清理过期数据
func (td *ThreatDetector) cleanupExpiredData() {
	now := time.Now()
	
	// 清理过期的失败登录记录
	for ip, lastFail := range td.ipLastFail {
		if now.Sub(lastFail) > 10*time.Minute {
			delete(td.ipFailCount, ip)
			delete(td.ipLastFail, ip)
		}
	}
	
	// 清理过期的进程停止记录
	td.processDown = []string{}
}

// 清理旧告警
func (td *ThreatDetector) cleanupOldAlerts() {
	td.mu.Lock()
	defer td.mu.Unlock()
	
	now := time.Now()
	activeAlerts := []ThreatAlert{}
	
	for _, alert := range td.alerts {
		// 保留最近1小时的告警
		if now.Sub(alert.Timestamp) < time.Hour {
			activeAlerts = append(activeAlerts, alert)
		}
	}
	
	td.alerts = activeAlerts
}

// 获取活跃威胁数量
func (td *ThreatDetector) getActiveThreatCount() int {
	td.mu.RLock()
	defer td.mu.RUnlock()
	
	count := 0
	now := time.Now()
	
	for _, alert := range td.alerts {
		if alert.Active && now.Sub(alert.Timestamp) < 10*time.Minute {
			count++
		}
	}
	
	return count
}

// 获取所有威胁
func (td *ThreatDetector) GetAllThreats() []ThreatAlert {
	td.mu.RLock()
	defer td.mu.RUnlock()
	
	threats := make([]ThreatAlert, len(td.alerts))
	copy(threats, td.alerts)
	return threats
}

// 获取活跃威胁
func (td *ThreatDetector) GetActiveThreats() []ThreatAlert {
	td.mu.RLock()
	defer td.mu.RUnlock()
	
	var activeThreats []ThreatAlert
	now := time.Now()
	
	for _, alert := range td.alerts {
		if alert.Active && now.Sub(alert.Timestamp) < 10*time.Minute {
			activeThreats = append(activeThreats, alert)
		}
	}
	
	return activeThreats
}
EOF

# 修复agent.go，移除重复的SystemMetrics结构体定义
echo "📝 修复agent.go..."
cat > agent.go << 'EOF'
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

func runAgent() {
	log.Println("🤖 启动天眼代理模式...")
	
	// 从环境变量获取配置
	serverURL := os.Getenv("MONITOR_SERVER_URL")
	if serverURL == "" {
		serverURL = "http://localhost:8080"
	}
	
	serverID := os.Getenv("SERVER_ID")
	if serverID == "" {
		serverID = "agent-001"
	}
	
	serverName := os.Getenv("SERVER_NAME")
	if serverName == "" {
		serverName = "Agent Server"
	}
	
	serverIP := os.Getenv("SERVER_IP")
	if serverIP == "" {
		serverIP = "127.0.0.1"
	}
	
	log.Printf("📡 连接到监控服务器: %s", serverURL)
	log.Printf("🏷️ 服务器标识: %s (%s)", serverName, serverID)
	
	// 定期收集和发送指标
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			metrics := collectSystemMetrics(serverID, serverName, serverIP)
			if err := sendMetrics(serverURL, metrics); err != nil {
				log.Printf("❌ 发送指标失败: %v", err)
			} else {
				log.Printf("✅ 指标发送成功 - CPU: %.1f%%, 内存: %.1f%%", 
					metrics.CPU, metrics.Memory)
			}
		}
	}
}

func collectSystemMetrics(serverID, serverName, serverIP string) SystemMetrics {
	metrics := SystemMetrics{
		ServerID:   serverID,
		ServerName: serverName,
		ServerIP:   serverIP,
		Timestamp:  time.Now(),
	}
	
	// 收集CPU使用率
	if cpuPercent, err := cpu.Percent(time.Second, false); err == nil && len(cpuPercent) > 0 {
		metrics.CPU = cpuPercent[0]
	}
	
	// 收集内存使用率
	if memInfo, err := mem.VirtualMemory(); err == nil {
		metrics.Memory = memInfo.UsedPercent
	}
	
	// 收集磁盘使用率
	if diskInfo, err := disk.Usage("/"); err == nil {
		metrics.Disk = diskInfo.UsedPercent
	}
	
	// 收集网络统计
	if netStats, err := net.IOCounters(false); err == nil && len(netStats) > 0 {
		metrics.Network.BytesSent = netStats[0].BytesSent
		metrics.Network.BytesRecv = netStats[0].BytesRecv
		metrics.Network.PacketsSent = netStats[0].PacketsSent
		metrics.Network.PacketsRecv = netStats[0].PacketsRecv
	}
	
	// 确定服务器状态
	if metrics.CPU > 90 || metrics.Memory > 90 {
		metrics.Status = "critical"
	} else if metrics.CPU > 70 || metrics.Memory > 80 {
		metrics.Status = "warning"
	} else {
		metrics.Status = "healthy"
	}
	
	return metrics
}

func sendMetrics(serverURL string, metrics SystemMetrics) error {
	jsonData, err := json.Marshal(metrics)
	if err != nil {
		return fmt.Errorf("序列化指标失败: %v", err)
	}
	
	url := fmt.Sprintf("%s/api/agent/metrics", serverURL)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("发送HTTP请求失败: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("服务器返回错误状态: %d", resp.StatusCode)
	}
	
	return nil
}
EOF

echo "✅ 结构体冲突修复完成"

# 重新编译
echo "🔨 重新编译..."
go build -ldflags="-s -w" -o sky-eye-monitor-real *.go

if [ $? -eq 0 ]; then
    echo "✅ 编译成功！"
    chmod +x sky-eye-monitor-real
    
    echo ""
    echo "📊 程序信息:"
    ls -lh sky-eye-monitor-real
    
    echo ""
    echo "🎉 真实数据监控系统编译完成！"
    echo ""
    echo "🚀 启动命令: ./start-real-monitor.sh"
    echo "📊 访问地址: http://localhost:8080"
    
else
    echo "❌ 编译仍然失败"
    echo "请检查错误信息并重试"
fi
