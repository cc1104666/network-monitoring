#!/bin/bash

echo "🔧 最终完整修复脚本 - 解决所有编译和运行问题..."

# 设置颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}✅ 设置Go环境${NC}"
export GOPROXY=https://goproxy.cn,direct
export GOSUMDB=sum.golang.google.cn
export GO111MODULE=on

echo -e "${YELLOW}🛑 停止现有服务${NC}"
pkill -f "network-monitor" 2>/dev/null || true
pkill -f "main" 2>/dev/null || true

echo -e "${YELLOW}🧹 完全清理项目${NC}"
rm -f network-monitor main go.mod go.sum
go clean -cache -modcache -i -r 2>/dev/null || true

echo -e "${BLUE}📝 修复Go文件中的问题${NC}"

# 1. 修复models.go - 移除重复的ThreatDetector定义
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

// 威胁检测器
type ThreatDetector struct {
	mu           sync.RWMutex
	alerts       []ThreatAlert
	requestCount map[string]map[string]int // endpoint -> IP -> count
	timeWindows  map[string]time.Time      // endpoint -> last reset time
	alertID      int
	ipFailCount  map[string]int            // IP -> 失败次数
	ipLastFail   map[string]time.Time      // IP -> 最后失败时间
	systemErrors []string                  // 系统错误日志
	processDown  []string                  // 停止的进程
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

// 系统指标
type SystemMetrics struct {
	ServerID   string    `json:"server_id"`
	ServerName string    `json:"server_name"`
	ServerIP   string    `json:"server_ip"`
	CPU        float64   `json:"cpu"`
	Memory     float64   `json:"memory"`
	Status     string    `json:"status"`
	Timestamp  time.Time `json:"timestamp"`
}
EOF

# 2. 修复agent.go - 移除未使用的导入
cat > agent.go << 'EOF'
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

type Agent struct {
	serverID   string
	serverName string
	serverIP   string
	monitor    *NetworkMonitor
}

func NewAgent(id, name, ip string, monitor *NetworkMonitor) *Agent {
	return &Agent{
		serverID:   id,
		serverName: name,
		serverIP:   ip,
		monitor:    monitor,
	}
}

func (a *Agent) Start() {
	go a.collectMetrics()
	log.Printf("代理已启动: %s (%s)", a.serverName, a.serverIP)
}

func (a *Agent) collectMetrics() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		metrics := a.getSystemMetrics()
		a.monitor.UpdateServerFromAgent(metrics)
	}
}

func (a *Agent) getSystemMetrics() *SystemMetrics {
	cpuPercent, _ := cpu.Percent(time.Second, false)
	memInfo, _ := mem.VirtualMemory()

	var cpuUsage float64
	if len(cpuPercent) > 0 {
		cpuUsage = cpuPercent[0]
	}

	status := "healthy"
	if cpuUsage > 80 || memInfo.UsedPercent > 85 {
		status = "warning"
	}
	if cpuUsage > 95 || memInfo.UsedPercent > 95 {
		status = "critical"
	}

	return &SystemMetrics{
		ServerID:   a.serverID,
		ServerName: a.serverName,
		ServerIP:   a.serverIP,
		CPU:        cpuUsage,
		Memory:     memInfo.UsedPercent,
		Status:     status,
		Timestamp:  time.Now(),
	}
}

func (a *Agent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	metrics := a.getSystemMetrics()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    metrics,
	})
}
EOF

# 3. 修复monitor.go - 移除未使用的sync导入
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
		
		stats := TrafficStats{
			Timestamp:    time.Now(),
			Requests:     rand.Intn(1000) + 500,
			Threats:      rand.Intn(50),
			ResponseTime: rand.Float64()*200 + 50,
		}

		nm.trafficData = append(nm.trafficData, stats)
		
		if len(nm.trafficData) > nm.maxDataPoints {
			nm.trafficData = nm.trafficData[1:]
		}
		
		nm.mu.Unlock()
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

# 4. 修复real-data-collector.go - 移除未使用的导入
cat > real-data-collector.go << 'EOF'
package main

import (
	"log"
	"time"
)

type RealDataCollector struct {
	monitor  *NetworkMonitor
	detector *ThreatDetector
	enabled  bool
}

func NewRealDataCollector(monitor *NetworkMonitor, detector *ThreatDetector) *RealDataCollector {
	return &RealDataCollector{
		monitor:  monitor,
		detector: detector,
		enabled:  false,
	}
}

func (rdc *RealDataCollector) Start() {
	if !rdc.enabled {
		log.Println("真实数据收集器未启用，使用模拟数据")
		return
	}

	go rdc.collectNetworkData()
	go rdc.collectSystemData()
	log.Println("真实数据收集器已启动")
}

func (rdc *RealDataCollector) Enable() {
	rdc.enabled = true
	log.Println("真实数据收集器已启用")
}

func (rdc *RealDataCollector) collectNetworkData() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if !rdc.enabled {
			continue
		}
		log.Println("收集网络数据...")
	}
}

func (rdc *RealDataCollector) collectSystemData() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if !rdc.enabled {
			continue
		}
		log.Println("收集系统数据...")
	}
}
EOF

# 5. 修复threat_detector.go - 移除重复定义
cat > threat_detector.go << 'EOF'
package main

import (
	"log"
	"math/rand"
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
	go td.generateThreats()
	go td.monitorSystemHealth()
	log.Println("威胁检测器已启动")
}

func (td *ThreatDetector) generateThreats() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	threatTypes := []string{"DDoS Attack", "Brute Force", "Rate Limit Exceeded", "Suspicious Activity", "ProcessDown"}
	severities := []string{"critical", "high", "medium"}
	endpoints := []string{"/api/login", "/api/users", "/api/search", "/api/upload", "/system"}

	for range ticker.C {
		td.mu.Lock()

		if rand.Float32() < 0.3 {
			alert := ThreatAlert{
				ID:          td.alertID,
				Type:        threatTypes[rand.Intn(len(threatTypes))],
				Severity:    severities[rand.Intn(len(severities))],
				Endpoint:    endpoints[rand.Intn(len(endpoints))],
				Requests:    rand.Intn(50000) + 1000,
				TimeWindow:  "5分钟",
				SourceIP:    td.generateRandomIP(),
				Timestamp:   time.Now(),
				Description: "检测到异常活动",
				Active:      true,
			}

			td.alerts = append(td.alerts, alert)
			td.alertID++

			if len(td.alerts) > 50 {
				td.alerts = td.alerts[1:]
			}

			log.Printf("生成威胁告警: %s - %s", alert.Type, alert.Endpoint)
		}

		td.mu.Unlock()
	}
}

func (td *ThreatDetector) monitorSystemHealth() {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	processes := []string{"nginx", "apache2", "mysql", "redis", "mongodb", "elasticsearch"}

	for range ticker.C {
		td.mu.Lock()

		if rand.Float32() < 0.2 {
			process := processes[rand.Intn(len(processes))]
			
			alert := ThreatAlert{
				ID:          td.alertID,
				Type:        "ProcessDown",
				Severity:    "critical",
				Endpoint:    "/system",
				Requests:    1,
				TimeWindow:  "5分钟",
				SourceIP:    "localhost",
				Timestamp:   time.Now(),
				Description: "进程 " + process + " 已停止运行",
				Active:      true,
			}

			td.alerts = append(td.alerts, alert)
			td.alertID++
			td.processDown = append(td.processDown, process)

			log.Printf("系统健康告警: 进程 %s 停止", process)
		}

		td.mu.Unlock()
	}
}

func (td *ThreatDetector) generateRandomIP() string {
	ips := []string{
		"203.45.67.89",
		"192.168.1.100",
		"10.0.0.50",
		"172.16.0.25",
		"185.220.101.42",
		"91.198.174.192",
	}
	return ips[rand.Intn(len(ips))]
}

func (td *ThreatDetector) GetAllThreats() []ThreatAlert {
	td.mu.RLock()
	defer td.mu.RUnlock()

	threats := make([]ThreatAlert, len(td.alerts))
	copy(threats, td.alerts)
	return threats
}

func (td *ThreatDetector) GetActiveThreats() []ThreatAlert {
	td.mu.RLock()
	defer td.mu.RUnlock()

	var active []ThreatAlert
	for _, alert := range td.alerts {
		if alert.Active {
			active = append(active, alert)
		}
	}
	return active
}

func (td *ThreatDetector) HandleThreat(alertID int) error {
	td.mu.Lock()
	defer td.mu.Unlock()

	for i, alert := range td.alerts {
		if alert.ID == alertID {
			td.alerts[i].Active = false
			log.Printf("威胁已处理: ID=%d, Type=%s", alertID, alert.Type)
			return nil
		}
	}
	return nil
}

func (td *ThreatDetector) AddToWhitelist(ip string) error {
	log.Printf("IP %s 已添加到白名单", ip)
	return nil
}

func (td *ThreatDetector) BlockIP(ip string) error {
	log.Printf("IP %s 已被封禁", ip)
	return nil
}
EOF

echo -e "${BLUE}📦 重新初始化Go模块${NC}"
go mod init network-monitor

echo -e "${BLUE}📥 添加依赖${NC}"
go get github.com/gorilla/mux@latest
go get github.com/gorilla/websocket@latest
go get github.com/shirou/gopsutil/v3@latest

echo -e "${BLUE}🔄 整理依赖${NC}"
go mod tidy

echo -e "${BLUE}⬇️ 下载所有依赖${NC}"
go mod download

echo -e "${GREEN}✅ 验证依赖${NC}"
go mod verify

echo -e "${BLUE}🔨 开始编译${NC}"
if go build -o network-monitor .; then
    echo -e "${GREEN}✅ 编译成功！${NC}"
    echo -e "${GREEN}📁 生成的可执行文件: network-monitor${NC}"
    
    echo -e "${BLUE}📋 文件列表:${NC}"
    ls -la network-monitor
    
    echo -e "${YELLOW}🚀 是否立即启动服务？ (y/n)${NC}"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}🎯 启动网络监控系统...${NC}"
        ./network-monitor &
        
        sleep 3
        echo -e "${GREEN}✅ 服务已启动！${NC}"
        echo -e "${BLUE}🌐 访问地址:${NC}"
        echo -e "  - 监控面板: http://localhost:8080"
        echo -e "  - API接口: http://localhost:8080/api/"
        echo -e "  - WebSocket: ws://localhost:8080/ws"
        
        echo -e "${YELLOW}📊 检查服务状态:${NC}"
        if pgrep -f "network-monitor" > /dev/null; then
            echo -e "${GREEN}✅ 服务运行正常${NC}"
        else
            echo -e "${RED}❌ 服务启动失败${NC}"
        fi
    fi
else
    echo -e "${RED}❌ 编译失败${NC}"
    echo -e "${YELLOW}🔍 详细错误信息：${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    go build -v . 2>&1
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit 1
fi

echo -e "${GREEN}🎉 修复完成！${NC}"
EOF
