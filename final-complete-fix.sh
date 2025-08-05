#!/bin/bash

echo "🔧 最终完整修复天眼监控系统..."

# 设置Go环境
export PATH=$PATH:/usr/local/go/bin
export GOPROXY=https://goproxy.cn,direct
export GOSUMDB=sum.golang.google.cn
export GO111MODULE=on

echo "✅ Go环境已设置"

# 停止现有服务
echo "🛑 停止现有服务..."
pkill -f "sky-eye-monitor" 2>/dev/null || true

# 备份原文件
echo "💾 备份原文件..."
mkdir -p backup
cp *.go backup/ 2>/dev/null || true

# 修复models.go - 只保留结构体定义
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

// 系统指标结构
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

# 修复threat_detector.go - 移除重复的结构体定义
echo "📝 修复threat_detector.go..."
cat > threat_detector.go << 'EOF'
package main

import (
	"log"
	"time"
)

func NewThreatDetector() *ThreatDetector {
	return &ThreatDetector{
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

# 修复agent.go - 移除未使用的导入
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

# 修复monitor.go - 移除未使用的导入
echo "📝 修复monitor.go..."
cat > monitor.go << 'EOF'
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/gorilla/websocket"
)

func NewNetworkMonitor() *NetworkMonitor {
	return &NetworkMonitor{
		trafficData:    make([]TrafficStats, 0),
		servers:        make(map[string]*ServerStatus),
		endpoints:      make(map[string]*EndpointStats),
		clients:        make(map[*WSClient]bool),
		requestChan:    make(chan RequestEvent, 1000),
		maxDataPoints:  100,
		requestDetails: make([]RequestDetail, 0),
	}
}

func (nm *NetworkMonitor) Start() {
	go nm.generateTrafficData()
	go nm.generateServerData()
	go nm.generateEndpointData()
	go nm.generateRequestDetails()
	go nm.processRequests()
	log.Println("网络监控器已启动")
}

func (nm *NetworkMonitor) generateTrafficData() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		nm.mu.Lock()
		
		// 生成模拟数据
		stats := TrafficStats{
			Timestamp:    time.Now(),
			Requests:     rand.Intn(1000) + 500,
			Threats:      rand.Intn(50),
			ResponseTime: rand.Float64()*200 + 50,
		}

		nm.trafficData = append(nm.trafficData, stats)
		
		// 保持最大数据点数量
		if len(nm.trafficData) > nm.maxDataPoints {
			nm.trafficData = nm.trafficData[1:]
		}
		
		nm.mu.Unlock()
		
		// 广播数据到所有客户端
		nm.broadcastTrafficData(stats)
	}
}

func (nm *NetworkMonitor) generateServerData() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	servers := []struct {
		id   string
		name string
		ip   string
	}{
		{"srv-001", "Web服务器-1", "192.168.1.10"},
		{"srv-002", "API服务器-1", "192.168.1.20"},
		{"srv-003", "数据库服务器", "192.168.1.30"},
		{"srv-004", "缓存服务器", "192.168.1.40"},
		{"srv-005", "负载均衡器", "192.168.1.50"},
	}

	for range ticker.C {
		nm.mu.Lock()
		
		for _, srv := range servers {
			status := nm.generateServerStatus(srv.id, srv.name, srv.ip)
			nm.servers[srv.id] = status
		}
		
		nm.mu.Unlock()
		nm.broadcastServerData()
	}
}

func (nm *NetworkMonitor) generateServerStatus(id, name, ip string) *ServerStatus {
	statuses := []string{"healthy", "warning", "critical"}
	weights := []int{70, 25, 5}
	
	status := nm.weightedRandomChoice(statuses, weights)
	
	var cpu, memory float64
	switch status {
	case "healthy":
		cpu = rand.Float64()*30 + 10
		memory = rand.Float64()*40 + 20
	case "warning":
		cpu = rand.Float64()*30 + 60
		memory = rand.Float64()*25 + 65
	case "critical":
		cpu = rand.Float64()*10 + 90
		memory = rand.Float64()*10 + 90
	}

	return &ServerStatus{
		ID:       id,
		Name:     name,
		IP:       ip,
		Status:   status,
		CPU:      cpu,
		Memory:   memory,
		Requests: rand.Intn(5000) + 1000,
		LastSeen: time.Now(),
	}
}

func (nm *NetworkMonitor) generateEndpointData() {
	ticker := time.NewTicker(8 * time.Second)
	defer ticker.Stop()

	endpoints := []string{
		"/api/users", "/api/orders", "/api/products", "/api/search",
		"/api/login", "/api/logout", "/api/dashboard", "/api/reports",
		"/api/upload", "/api/download", "/api/settings", "/api/notifications",
	}

	for range ticker.C {
		nm.mu.Lock()
		
		for _, endpoint := range endpoints {
			stats := nm.generateEndpointStats(endpoint)
			nm.endpoints[endpoint] = stats
		}
		
		nm.mu.Unlock()
		nm.broadcastEndpointData()
	}
}

func (nm *NetworkMonitor) generateEndpointStats(endpoint string) *EndpointStats {
	statuses := []string{"normal", "suspicious", "alert"}
	weights := []int{80, 15, 5}
	
	status := nm.weightedRandomChoice(statuses, weights)
	
	var requests int
	var avgResponse float64
	
	switch status {
	case "normal":
		requests = rand.Intn(1000) + 100
		avgResponse = rand.Float64()*100 + 50
	case "suspicious":
		requests = rand.Intn(3000) + 1000
		avgResponse = rand.Float64()*200 + 100
	case "alert":
		requests = rand.Intn(10000) + 5000
		avgResponse = rand.Float64()*500 + 200
	}

	return &EndpointStats{
		Endpoint:     endpoint,
		Requests:     requests,
		AvgResponse:  avgResponse,
		Status:       status,
		LastRequest:  time.Now(),
		RequestRate:  float64(requests) / 60.0,
	}
}

func (nm *NetworkMonitor) generateRequestDetails() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
		"curl/7.68.0",
		"PostmanRuntime/7.28.4",
		"python-requests/2.25.1",
	}

	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
	endpoints := []string{
		"/api/users", "/api/orders", "/api/products", "/api/search",
		"/api/login", "/api/logout", "/api/dashboard", "/api/reports",
	}

	countries := []string{"中国", "美国", "日本", "德国", "英国", "法国", "俄罗斯", "未知"}

	id := 1
	for range ticker.C {
		nm.detailsMutex.Lock()
		
		count := rand.Intn(5) + 1
		for i := 0; i < count; i++ {
			detail := RequestDetail{
				ID:           id,
				Timestamp:    time.Now(),
				IP:           nm.generateRandomIP(),
				Method:       methods[rand.Intn(len(methods))],
				Endpoint:     endpoints[rand.Intn(len(endpoints))],
				StatusCode:   nm.generateStatusCode(),
				ResponseTime: rand.Intn(2000) + 50,
				UserAgent:    userAgents[rand.Intn(len(userAgents))],
				RequestSize:  rand.Intn(10000) + 100,
				ResponseSize: rand.Intn(50000) + 500,
				Referer:      "https://example.com",
				Country:      countries[rand.Intn(len(countries))],
				IsSuspicious: rand.Float32() < 0.1,
			}
			
			nm.requestDetails = append(nm.requestDetails, detail)
			id++
		}
		
		if len(nm.requestDetails) > 1000 {
			nm.requestDetails = nm.requestDetails[len(nm.requestDetails)-1000:]
		}
		
		nm.detailsMutex.Unlock()
		nm.broadcastRequestDetails()
	}
}

func (nm *NetworkMonitor) generateRandomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", 
		rand.Intn(255)+1, 
		rand.Intn(255), 
		rand.Intn(255), 
		rand.Intn(255))
}

func (nm *NetworkMonitor) generateStatusCode() int {
	codes := []int{200, 201, 204, 400, 401, 403, 404, 500, 502, 503}
	weights := []int{60, 10, 5, 8, 5, 3, 4, 2, 2, 1}
	
	return nm.weightedRandomChoiceInt(codes, weights)
}

func (nm *NetworkMonitor) weightedRandomChoice(choices []string, weights []int) string {
	total := 0
	for _, w := range weights {
		total += w
	}
	
	r := rand.Intn(total)
	for i, w := range weights {
		r -= w
		if r < 0 {
			return choices[i]
		}
	}
	return choices[0]
}

func (nm *NetworkMonitor) weightedRandomChoiceInt(choices []int, weights []int) int {
	total := 0
	for _, w := range weights {
		total += w
	}
	
	r := rand.Intn(total)
	for i, w := range weights {
		r -= w
		if r < 0 {
			return choices[i]
		}
	}
	return choices[0]
}

func (nm *NetworkMonitor) processRequests() {
	for event := range nm.requestChan {
		log.Printf("处理请求: %s from %s", event.Endpoint, event.IP)
	}
}

// 客户端管理方法
func (nm *NetworkMonitor) RegisterClient(client *WSClient) {
	nm.mu.Lock()
	nm.clients[client] = true
	nm.mu.Unlock()
	log.Printf("新客户端连接，当前连接数: %d", len(nm.clients))
}

func (nm *NetworkMonitor) UnregisterClient(client *WSClient) {
	nm.mu.Lock()
	delete(nm.clients, client)
	nm.mu.Unlock()
	log.Printf("客户端断开连接，当前连接数: %d", len(nm.clients))
}

// 数据获取方法
func (nm *NetworkMonitor) GetCurrentStats() []TrafficStats {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	
	data := make([]TrafficStats, len(nm.trafficData))
	copy(data, nm.trafficData)
	return data
}

func (nm *NetworkMonitor) GetServerStatus() []*ServerStatus {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	
	servers := make([]*ServerStatus, 0, len(nm.servers))
	for _, server := range nm.servers {
		servers = append(servers, server)
	}
	return servers
}

func (nm *NetworkMonitor) GetEndpointStats() []*EndpointStats {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	
	endpoints := make([]*EndpointStats, 0, len(nm.endpoints))
	for _, endpoint := range nm.endpoints {
		endpoints = append(endpoints, endpoint)
	}
	return endpoints
}

func (nm *NetworkMonitor) GetRequestDetails() []RequestDetail {
	nm.detailsMutex.RLock()
	defer nm.detailsMutex.RUnlock()
	
	details := make([]RequestDetail, len(nm.requestDetails))
	copy(details, nm.requestDetails)
	return details
}

func (nm *NetworkMonitor) GetRequestDetailsByEndpoint(endpoint string) []RequestDetail {
	nm.detailsMutex.RLock()
	defer nm.detailsMutex.RUnlock()
	
	var filtered []RequestDetail
	for _, detail := range nm.requestDetails {
		if detail.Endpoint == endpoint {
			filtered = append(filtered, detail)
		}
	}
	return filtered
}

func (nm *NetworkMonitor) UpdateServerFromAgent(metrics *SystemMetrics) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	server := &ServerStatus{
		ID:       metrics.ServerID,
		Name:     metrics.ServerName,
		IP:       metrics.ServerIP,
		Status:   metrics.Status,
		CPU:      metrics.CPU,
		Memory:   metrics.Memory,
		Requests: 0,
		LastSeen: metrics.Timestamp,
	}

	nm.servers[server.ID] = server
	log.Printf("更新服务器状态: %s (%s) - CPU: %.1f%%, 内存: %.1f%%",
		server.Name, server.IP, server.CPU, server.Memory)
}

// 广播方法
func (nm *NetworkMonitor) broadcastTrafficData(stats TrafficStats) {
	message := map[string]interface{}{
		"type": "traffic",
		"data": stats,
	}
	nm.broadcast(message)
}

func (nm *NetworkMonitor) broadcastServerData() {
	nm.mu.RLock()
	servers := make([]*ServerStatus, 0, len(nm.servers))
	for _, server := range nm.servers {
		servers = append(servers, server)
	}
	nm.mu.RUnlock()

	message := map[string]interface{}{
		"type": "servers",
		"data": servers,
	}
	nm.broadcast(message)
}

func (nm *NetworkMonitor) broadcastEndpointData() {
	nm.mu.RLock()
	endpoints := make([]*EndpointStats, 0, len(nm.endpoints))
	for _, endpoint := range nm.endpoints {
		endpoints = append(endpoints, endpoint)
	}
	nm.mu.RUnlock()

	message := map[string]interface{}{
		"type": "endpoints",
		"data": endpoints,
	}
	nm.broadcast(message)
}

func (nm *NetworkMonitor) broadcastRequestDetails() {
	nm.detailsMutex.RLock()
	var recentDetails []RequestDetail
	if len(nm.requestDetails) > 10 {
		recentDetails = nm.requestDetails[len(nm.requestDetails)-10:]
	} else {
		recentDetails = nm.requestDetails
	}
	nm.detailsMutex.RUnlock()

	message := map[string]interface{}{
		"type": "requests",
		"data": recentDetails,
	}
	nm.broadcast(message)
}

func (nm *NetworkMonitor) broadcast(message interface{}) {
	data, err := json.Marshal(message)
	if err != nil {
		log.Printf("序列化消息失败: %v", err)
		return
	}

	nm.mu.RLock()
	clients := make([]*WSClient, 0, len(nm.clients))
	for client := range nm.clients {
		clients = append(clients, client)
	}
	nm.mu.RUnlock()

	for _, client := range clients {
		select {
		case client.send <- data:
		default:
			nm.UnregisterClient(client)
			close(client.send)
		}
	}
}

// WebSocket客户端方法
func (client *WSClient) SendJSON(data interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	select {
	case client.send <- jsonData:
		return nil
	default:
		return nil
	}
}

func (client *WSClient) writePump() {
	defer client.conn.Close()

	for {
		select {
		case message, ok := <-client.send:
			if !ok {
				client.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			client.conn.WriteMessage(websocket.TextMessage, message)
		}
	}
}

func (client *WSClient) readPump() {
	defer func() {
		close(client.done)
		client.conn.Close()
	}()

	for {
		_, _, err := client.conn.ReadMessage()
		if err != nil {
			break
		}
	}
}
EOF

# 修复real-data-collector.go - 移除未使用的导入
echo "📝 修复real-data-collector.go..."
cat > real-data-collector.go << 'EOF'
package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// 真实数据收集器
type RealDataCollector struct {
	monitor          *NetworkMonitor
	detector         *ThreatDetector
	nginxLogPath     string
	apacheLogPath    string
	interfaces       []string
	realServers      []string
	logTailProcesses []*exec.Cmd
}

// 创建真实数据收集器
func NewRealDataCollector(monitor *NetworkMonitor, detector *ThreatDetector) *RealDataCollector {
	return &RealDataCollector{
		monitor:       monitor,
		detector:      detector,
		nginxLogPath:  "/var/log/nginx/access.log",
		apacheLogPath: "/var/log/apache2/access.log",
		interfaces:    []string{"eth0", "ens33", "enp0s3"},
		realServers: []string{
			"127.0.0.1:80",
			"127.0.0.1:443",
			"127.0.0.1:8080",
			"127.0.0.1:3306",
			"127.0.0.1:6379",
		},
	}
}

// 启动真实数据收集
func (rdc *RealDataCollector) Start() {
	log.Println("🔍 启动真实数据收集器...")
	
	// 启动各种数据收集协程
	go rdc.collectNetworkTraffic()
	go rdc.collectServerMetrics()
	go rdc.collectLogData()
	go rdc.detectRealThreats()
	go rdc.monitorProcesses()
	go rdc.collectSystemStats()
	
	log.Println("✅ 真实数据收集器已启动")
}

// 收集网络流量数据
func (rdc *RealDataCollector) collectNetworkTraffic() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	var lastStats map[string]*NetworkInterfaceStats
	
	for range ticker.C {
		currentStats := rdc.getNetworkInterfaceStats()
		
		if lastStats != nil {
			totalRequests := 0
			totalBytes := uint64(0)
			
			for iface, current := range currentStats {
				if last, exists := lastStats[iface]; exists {
					// 计算增量
					bytesDiff := current.BytesRecv - last.BytesRecv
					packetsDiff := current.PacketsRecv - last.PacketsRecv
					
					totalBytes += bytesDiff
					totalRequests += int(packetsDiff)
				}
			}
			
			// 估算响应时间（基于网络延迟）
			responseTime := rdc.measureNetworkLatency()
			
			// 更新监控数据
			rdc.monitor.mu.Lock()
			stats := TrafficStats{
				Timestamp:    time.Now(),
				Requests:     totalRequests,
				Threats:      rdc.detector.getActiveThreatCount(),
				ResponseTime: responseTime,
			}
			
			rdc.monitor.trafficData = append(rdc.monitor.trafficData, stats)
			if len(rdc.monitor.trafficData) > rdc.monitor.maxDataPoints {
				rdc.monitor.trafficData = rdc.monitor.trafficData[1:]
			}
			rdc.monitor.mu.Unlock()
			
			// 广播数据
			rdc.monitor.broadcastTrafficData(stats)
		}
		
		lastStats = currentStats
	}
}

// 网络接口统计
type NetworkInterfaceStats struct {
	BytesRecv   uint64
	BytesSent   uint64
	PacketsRecv uint64
	PacketsSent uint64
}

// 获取网络接口统计
func (rdc *RealDataCollector) getNetworkInterfaceStats() map[string]*NetworkInterfaceStats {
	stats := make(map[string]*NetworkInterfaceStats)
	
	// 读取 /proc/net/dev
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return stats
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) != 2 {
				continue
			}
			
			iface := strings.TrimSpace(parts[0])
			data := strings.Fields(strings.TrimSpace(parts[1]))
			
			if len(data) >= 16 {
				bytesRecv, _ := strconv.ParseUint(data[0], 10, 64)
				packetsRecv, _ := strconv.ParseUint(data[1], 10, 64)
				bytesSent, _ := strconv.ParseUint(data[8], 10, 64)
				packetsSent, _ := strconv.ParseUint(data[9], 10, 64)
				
				stats[iface] = &NetworkInterfaceStats{
					BytesRecv:   bytesRecv,
					BytesSent:   bytesSent,
					PacketsRecv: packetsRecv,
					PacketsSent: packetsSent,
				}
			}
		}
	}
	
	return stats
}

// 测量网络延迟
func (rdc *RealDataCollector) measureNetworkLatency() float64 {
	start := time.Now()
	
	// 尝试连接本地服务
	conn, err := net.DialTimeout("tcp", "127.0.0.1:80", 1*time.Second)
	if err != nil {
		// 如果本地连接失败，尝试ping本地回环
		return rdc.pingLocalhost()
	}
	defer conn.Close()
	
	return float64(time.Since(start).Nanoseconds()) / 1000000.0 // 转换为毫秒
}

// Ping本地主机
func (rdc *RealDataCollector) pingLocalhost() float64 {
	cmd := exec.Command("ping", "-c", "1", "-W", "1", "127.0.0.1")
	output, err := cmd.Output()
	if err != nil {
		return 100.0 // 默认延迟
	}
	
	// 解析ping输出
	re := regexp.MustCompile(`time=([0-9.]+)`)
	matches := re.FindStringSubmatch(string(output))
	if len(matches) > 1 {
		if latency, err := strconv.ParseFloat(matches[1], 64); err == nil {
			return latency
		}
	}
	
	return 50.0 // 默认延迟
}

// 收集真实服务器指标
func (rdc *RealDataCollector) collectServerMetrics() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		rdc.monitor.mu.Lock()
		
		// 清空现有服务器数据
		rdc.monitor.servers = make(map[string]*ServerStatus)
		
		// 检查真实服务器
		for i, serverAddr := range rdc.realServers {
			serverID := fmt.Sprintf("real-srv-%d", i+1)
			status := rdc.checkServerStatus(serverAddr)
			
			// 获取系统资源使用情况
			cpu, memory := rdc.getSystemResources()
			
			server := &ServerStatus{
				ID:       serverID,
				Name:     fmt.Sprintf("服务器-%s", serverAddr),
				IP:       strings.Split(serverAddr, ":")[0],
				Status:   status,
				CPU:      cpu,
				Memory:   memory,
				Requests: rdc.getServerRequestCount(serverAddr),
				LastSeen: time.Now(),
			}
			
			rdc.monitor.servers[serverID] = server
		}
		
		rdc.monitor.mu.Unlock()
		rdc.monitor.broadcastServerData()
	}
}

// 检查服务器状态
func (rdc *RealDataCollector) checkServerStatus(addr string) string {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return "critical"
	}
	defer conn.Close()
	
	// 如果是HTTP服务，尝试发送请求
	if strings.HasSuffix(addr, ":80") || strings.HasSuffix(addr, ":8080") {
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get(fmt.Sprintf("http://%s/", addr))
		if err != nil {
			return "warning"
		}
		defer resp.Body.Close()
		
		if resp.StatusCode >= 500 {
			return "critical"
		} else if resp.StatusCode >= 400 {
			return "warning"
		}
	}
	
	return "healthy"
}

// 获取系统资源使用情况
func (rdc *RealDataCollector) getSystemResources() (float64, float64) {
	// CPU使用率
	cpu := rdc.getCPUUsage()
	
	// 内存使用率
	memory := rdc.getMemoryUsage()
	
	return cpu, memory
}

// 获取CPU使用率
func (rdc *RealDataCollector) getCPUUsage() float64 {
	// 读取 /proc/stat
	file, err := os.Open("/proc/stat")
	if err != nil {
		return 0.0
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) >= 8 {
				user, _ := strconv.ParseFloat(fields[1], 64)
				nice, _ := strconv.ParseFloat(fields[2], 64)
				system, _ := strconv.ParseFloat(fields[3], 64)
				idle, _ := strconv.ParseFloat(fields[4], 64)
				
				total := user + nice + system + idle
				if total > 0 {
					return ((total - idle) / total) * 100.0
				}
			}
		}
	}
	
	return 0.0
}

// 获取内存使用率
func (rdc *RealDataCollector) getMemoryUsage() float64 {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0.0
	}
	defer file.Close()
	
	var memTotal, memFree, memAvailable float64
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				memTotal, _ = strconv.ParseFloat(fields[1], 64)
			}
		} else if strings.HasPrefix(line, "MemFree:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				memFree, _ = strconv.ParseFloat(fields[1], 64)
			}
		} else if strings.HasPrefix(line, "MemAvailable:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				memAvailable, _ = strconv.ParseFloat(fields[1], 64)
			}
		}
	}
	
	if memTotal > 0 {
		used := memTotal - memAvailable
		if memAvailable == 0 {
			used = memTotal - memFree
		}
		return (used / memTotal) * 100.0
	}
	
	return 0.0
}

// 获取服务器请求数量
func (rdc *RealDataCollector) getServerRequestCount(addr string) int {
	// 这里可以通过解析日志文件或查询服务器状态API来获取
	// 暂时返回一个基于连接数的估算值
	return rdc.getConnectionCount(addr)
}

// 获取连接数
func (rdc *RealDataCollector) getConnectionCount(addr string) int {
	port := strings.Split(addr, ":")[1]
	
	cmd := exec.Command("netstat", "-an")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}
	
	count := 0
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, ":"+port) && strings.Contains(line, "ESTABLISHED") {
			count++
		}
	}
	
	return count
}

// 收集日志数据
func (rdc *RealDataCollector) collectLogData() {
	// 尝试监控不同的日志文件
	logPaths := []string{
		"/var/log/nginx/access.log",
		"/var/log/apache2/access.log",
		"/var/log/httpd/access_log",
		"/var/log/syslog",
		"/var/log/auth.log",
	}
	
	for _, logPath := range logPaths {
		if rdc.fileExists(logPath) {
			go rdc.tailLogFile(logPath)
		}
	}
}

// 检查文件是否存在
func (rdc *RealDataCollector) fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// 监控日志文件
func (rdc *RealDataCollector) tailLogFile(logPath string) {
	cmd := exec.Command("tail", "-f", logPath)
	rdc.logTailProcesses = append(rdc.logTailProcesses, cmd)
	
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	
	if err := cmd.Start(); err != nil {
		return
	}
	
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		rdc.parseLogLine(line, logPath)
	}
}

// 解析日志行
func (rdc *RealDataCollector) parseLogLine(line, logPath string) {
	// 解析不同类型的日志
	if strings.Contains(logPath, "nginx") || strings.Contains(logPath, "apache") {
		rdc.parseWebServerLog(line)
	} else if strings.Contains(logPath, "auth") {
		rdc.parseAuthLog(line)
	} else if strings.Contains(logPath, "syslog") {
		rdc.parseSysLog(line)
	}
}

// 解析Web服务器日志
func (rdc *RealDataCollector) parseWebServerLog(line string) {
	// Nginx/Apache日志格式解析
	// 示例: 192.168.1.1 - - [05/Aug/2025:16:51:53 +0000] "GET /api/users HTTP/1.1" 200 1234
	
	// 简单的正则表达式解析
	re := regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\d+)`)
	matches := re.FindStringSubmatch(line)
	
	if len(matches) >= 7 {
		ip := matches[1]
		method := matches[3]
		endpoint := matches[4]
		statusCode, _ := strconv.Atoi(matches[5])
		responseSize, _ := strconv.Atoi(matches[6])
		
		// 创建请求详情
		detail := RequestDetail{
			ID:           int(time.Now().UnixNano() % 1000000),
			Timestamp:    time.Now(),
			IP:           ip,
			Method:       method,
			Endpoint:     endpoint,
			StatusCode:   statusCode,
			ResponseTime: 50 + int(time.Now().UnixNano()%1000), // 模拟响应时间
			UserAgent:    "Real-User-Agent",
			RequestSize:  100,
			ResponseSize: responseSize,
			Referer:      "-",
			Country:      rdc.getCountryFromIP(ip),
			IsSuspicious: rdc.isSuspiciousRequest(ip, endpoint, statusCode),
		}
		
		// 添加到监控数据
		rdc.monitor.detailsMutex.Lock()
		rdc.monitor.requestDetails = append(rdc.monitor.requestDetails, detail)
		if len(rdc.monitor.requestDetails) > 1000 {
			rdc.monitor.requestDetails = rdc.monitor.requestDetails[1:]
		}
		rdc.monitor.detailsMutex.Unlock()
		
		// 威胁检测
		if detail.IsSuspicious {
			rdc.detector.processRequest(ip, endpoint, statusCode)
		}
	}
}

// 解析认证日志
func (rdc *RealDataCollector) parseAuthLog(line string) {
	// 检测登录失败等安全事件
	if strings.Contains(line, "Failed password") || strings.Contains(line, "authentication failure") {
		// 提取IP地址
		re := regexp.MustCompile(`from (\d+\.\d+\.\d+\.\d+)`)
		matches := re.FindStringSubmatch(line)
		if len(matches) > 1 {
			ip := matches[1]
			rdc.detector.recordFailedLogin(ip)
		}
	}
}

// 解析系统日志
func (rdc *RealDataCollector) parseSysLog(line string) {
	// 检测系统异常
	if strings.Contains(line, "ERROR") || strings.Contains(line, "CRITICAL") {
		rdc.detector.recordSystemError(line)
	}
}

// 从IP获取国家信息
func (rdc *RealDataCollector) getCountryFromIP(ip string) string {
	// 简单的IP地址分类
	if strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") {
		return "本地"
	}
	
	// 这里可以集成GeoIP数据库
	return "未知"
}

// 判断是否为可疑请求
func (rdc *RealDataCollector) isSuspiciousRequest(ip, endpoint string, statusCode int) bool {
	// 简单的可疑请求判断逻辑
	suspiciousEndpoints := []string{"/admin", "/wp-admin", "/.env", "/config", "/backup"}
	
	for _, suspicious := range suspiciousEndpoints {
		if strings.Contains(endpoint, suspicious) {
			return true
		}
	}
	
	// 状态码异常
	if statusCode == 404 || statusCode >= 500 {
		return true
	}
	
	return false
}

// 检测真实威胁
func (rdc *RealDataCollector) detectRealThreats() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		rdc.detector.analyzeThreats()
	}
}

// 监控进程
func (rdc *RealDataCollector) monitorProcesses() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		rdc.checkCriticalProcesses()
	}
}

// 检查关键进程
func (rdc *RealDataCollector) checkCriticalProcesses() {
	criticalProcesses := []string{"nginx", "apache2", "mysql", "redis-server", "sshd"}
	
	for _, process := range criticalProcesses {
		if !rdc.isProcessRunning(process) {
			rdc.detector.recordProcessDown(process)
		}
	}
}

// 检查进程是否运行
func (rdc *RealDataCollector) isProcessRunning(processName string) bool {
	cmd := exec.Command("pgrep", processName)
	err := cmd.Run()
	return err == nil
}

// 收集系统统计信息
func (rdc *RealDataCollector) collectSystemStats() {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		stats := rdc.getSystemStats()
		rdc.updateSystemMetrics(stats)
	}
}

// 系统统计信息
type SystemStats struct {
	LoadAverage    []float64
	DiskUsage      map[string]float64
	NetworkErrors  int
	OpenFiles      int
	ActiveSessions int
}

// 获取系统统计信息
func (rdc *RealDataCollector) getSystemStats() *SystemStats {
	stats := &SystemStats{
		DiskUsage: make(map[string]float64),
	}
	
	// 获取负载平均值
	stats.LoadAverage = rdc.getLoadAverage()
	
	// 获取磁盘使用率
	stats.DiskUsage = rdc.getDiskUsage()
	
	// 获取网络错误数
	stats.NetworkErrors = rdc.getNetworkErrors()
	
	// 获取打开文件数
	stats.OpenFiles = rdc.getOpenFiles()
	
	// 获取活跃会话数
	stats.ActiveSessions = rdc.getActiveSessions()
	
	return stats
}

// 获取负载平均值
func (rdc *RealDataCollector) getLoadAverage() []float64 {
	file, err := os.Open("/proc/loadavg")
	if err != nil {
		return []float64{0, 0, 0}
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 {
			load1, _ := strconv.ParseFloat(fields[0], 64)
			load5, _ := strconv.ParseFloat(fields[1], 64)
			load15, _ := strconv.ParseFloat(fields[2], 64)
			return []float64{load1, load5, load15}
		}
	}
	
	return []float64{0, 0, 0}
}

// 获取磁盘使用率
func (rdc *RealDataCollector) getDiskUsage() map[string]float64 {
	usage := make(map[string]float64)
	
	cmd := exec.Command("df", "-h")
	output, err := cmd.Output()
	if err != nil {
		return usage
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines[1:] { // 跳过标题行
		fields := strings.Fields(line)
		if len(fields) >= 6 {
			mountPoint := fields[5]
			usePercent := strings.TrimSuffix(fields[4], "%")
			if percent, err := strconv.ParseFloat(usePercent, 64); err == nil {
				usage[mountPoint] = percent
			}
		}
	}
	
	return usage
}

// 获取网络错误数
func (rdc *RealDataCollector) getNetworkErrors() int {
	// 从 /proc/net/dev 读取错误统计
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0
	}
	defer file.Close()
	
	totalErrors := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				data := strings.Fields(strings.TrimSpace(parts[1]))
				if len(data) >= 16 {
					rxErrors, _ := strconv.Atoi(data[2])
					txErrors, _ := strconv.Atoi(data[10])
					totalErrors += rxErrors + txErrors
				}
			}
		}
	}
	
	return totalErrors
}

// 获取打开文件数
func (rdc *RealDataCollector) getOpenFiles() int {
	cmd := exec.Command("lsof")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}
	
	lines := strings.Split(string(output), "\n")
	return len(lines) - 1 // 减去标题行
}

// 获取活跃会话数
func (rdc *RealDataCollector) getActiveSessions() int {
	cmd := exec.Command("who")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}
	
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	return len(lines)
}

// 更新系统指标
func (rdc *RealDataCollector) updateSystemMetrics(stats *SystemStats) {
	// 这里可以将系统统计信息更新到监控数据中
	log.Printf("系统负载: %.2f, 磁盘使用率: %v, 网络错误: %d", 
		stats.LoadAverage[0], stats.DiskUsage, stats.NetworkErrors)
}

// 停止数据收集
func (rdc *RealDataCollector) Stop() {
	log.Println("🛑 停止真实数据收集器...")
	
	// 停止所有tail进程
	for _, cmd := range rdc.logTailProcesses {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}
	
	log.Println("✅ 真实数据收集器已停止")
}
EOF

echo "✅ 所有文件修复完成"

# 完全清理Go模块
echo "🧹 完全清理Go模块..."
rm -rf go.mod go.sum
go clean -cache
go clean -modcache

# 重新初始化Go模块
echo "📦 重新初始化Go模块..."
go mod init network-monitor

# 添加依赖
echo "📥 添加依赖..."
go get github.com/gorilla/mux@v1.8.1
go get github.com/gorilla/websocket@v1.5.1
go get github.com/shirou/gopsutil/v3@v3.23.10

# 整理依赖
echo "🔄 整理依赖..."
go mod tidy

# 下载依赖
echo "⬇️ 下载依赖..."
go mod download

# 验证依赖
echo "✅ 验证依赖..."
go mod verify

# 编译
echo "🔨 开始编译..."
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
    echo "🚀 启动命令: ./sky-eye-monitor-real"
    echo "📊 访问地址: http://localhost:8080"
    
    # 询问是否立即启动
    read -p "是否立即启动服务? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "🚀 启动天眼监控系统..."
        mkdir -p logs
        nohup ./sky-eye-monitor-real > logs/monitor.log 2>&1 &
        
        sleep 3
        
        if pgrep -f "sky-eye-monitor-real" > /dev/null; then
            echo "✅ 服务启动成功！"
            
            # 获取服务器IP信息
            LOCAL_IP=$(hostname -I | awk '{print $1}')
            EXTERNAL_IP=$(curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
            
            echo ""
            echo "🎉 天眼监控系统运行中！"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo "📊 访问地址:"
            echo "   本地访问: http://localhost:8080"
            echo "   内网访问: http://$LOCAL_IP:8080"
            echo "   外网访问: http://$EXTERNAL_IP:8080"
            echo ""
            echo "🔧 管理命令:"
            echo "   查看日志: tail -f logs/monitor.log"
            echo "   停止服务: pkill -f sky-eye-monitor-real"
            echo "   查看进程: ps aux | grep sky-eye-monitor-real"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            
        else
            echo "❌ 服务启动失败，查看日志: cat logs/monitor.log"
        fi
    fi
    
else
    echo "❌ 编译失败"
    echo ""
    echo "🔍 详细错误信息："
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    go build -v -o sky-eye-monitor-real *.go
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    exit 1
fi
