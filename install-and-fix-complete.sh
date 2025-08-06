#!/bin/bash

echo "🔧 完整安装Go环境并修复网络监控系统..."

# 设置颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 检查是否为root用户
if [ "$EUID" -ne 0 ]; then
   echo -e "${RED}请使用sudo运行此脚本${NC}"
   exit 1
fi

echo -e "${BLUE}🔍 检查Go环境...${NC}"

# 检查Go是否已安装
if command -v go &> /dev/null; then
   GO_VERSION=$(go version | awk '{print $3}')
   echo -e "${GREEN}✅ Go已安装: $GO_VERSION${NC}"
else
   echo -e "${YELLOW}📦 Go未安装，开始安装...${NC}"
   
   # 下载并安装Go
   cd /tmp
   echo -e "${BLUE}⬇️ 下载Go 1.21.5...${NC}"
   wget -q https://golang.org/dl/go1.21.5.linux-amd64.tar.gz
   
   if [ $? -ne 0 ]; then
       echo -e "${RED}❌ 下载Go失败，尝试备用源...${NC}"
       wget -q https://golang.google.cn/dl/go1.21.5.linux-amd64.tar.gz
   fi
   
   if [ ! -f "go1.21.5.linux-amd64.tar.gz" ]; then
       echo -e "${RED}❌ 无法下载Go，请检查网络连接${NC}"
       exit 1
   fi
   
   echo -e "${BLUE}📦 安装Go...${NC}"
   rm -rf /usr/local/go
   tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
   
   # 设置环境变量
   echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
   echo 'export GOPROXY=https://goproxy.cn,direct' >> /etc/profile
   echo 'export GOSUMDB=sum.golang.google.cn' >> /etc/profile
   echo 'export GO111MODULE=on' >> /etc/profile
   
   # 为当前会话设置环境变量
   export PATH=$PATH:/usr/local/go/bin
   export GOPROXY=https://goproxy.cn,direct
   export GOSUMDB=sum.golang.google.cn
   export GO111MODULE=on
   
   echo -e "${GREEN}✅ Go安装完成${NC}"
   go version
fi

# 确保环境变量设置正确
export PATH=$PATH:/usr/local/go/bin
export GOPROXY=https://goproxy.cn,direct
export GOSUMDB=sum.golang.google.cn
export GO111MODULE=on

echo -e "${BLUE}🔧 开始修复网络监控系统...${NC}"

# 进入项目目录
cd /opt/network-monitoring

echo -e "${YELLOW}🛑 停止现有服务${NC}"
pkill -f "network-monitor" 2>/dev/null || true
pkill -f "main" 2>/dev/null || true
pkill -f "sky-eye-monitor" 2>/dev/null || true

echo -e "${YELLOW}🧹 完全清理项目${NC}"
rm -f network-monitor main sky-eye-monitor* go.mod go.sum
go clean -cache -modcache -i -r 2>/dev/null || true

echo -e "${BLUE}📝 修复Go文件...${NC}"

# 1. 创建models.go
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

// 数据包信息
type PacketInfo struct {
	ID          int       `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	SourceIP    string    `json:"source_ip"`
	DestIP      string    `json:"dest_ip"`
	SourcePort  int       `json:"source_port"`
	DestPort    int       `json:"dest_port"`
	Protocol    string    `json:"protocol"`
	Length      int       `json:"length"`
	Flags       string    `json:"flags"`
	RawData     string    `json:"raw_data"`
	IsSuspicious bool     `json:"is_suspicious"`
}

// HTTP请求详情
type HTTPRequestDetail struct {
	ID              int                    `json:"id"`
	Timestamp       time.Time              `json:"timestamp"`
	SourceIP        string                 `json:"source_ip"`
	Method          string                 `json:"method"`
	URL             string                 `json:"url"`
	Headers         map[string]string      `json:"headers"`
	Body            string                 `json:"body"`
	ResponseCode    int                    `json:"response_code"`
	ResponseHeaders map[string]string      `json:"response_headers"`
	ResponseBody    string                 `json:"response_body"`
	ResponseTime    int                    `json:"response_time"`
	UserAgent       string                 `json:"user_agent"`
	Referer         string                 `json:"referer"`
	Cookies         string                 `json:"cookies"`
	ContentType     string                 `json:"content_type"`
	ContentLength   int                    `json:"content_length"`
	Country         string                 `json:"country"`
	ISP             string                 `json:"isp"`
	ThreatScore     int                    `json:"threat_score"`
	ThreatReasons   []string               `json:"threat_reasons"`
	PacketTrace     []PacketInfo           `json:"packet_trace"`
}

// IP分析信息
type IPAnalysis struct {
	IP              string    `json:"ip"`
	RequestCount    int       `json:"request_count"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	Countries       []string  `json:"countries"`
	UserAgents      []string  `json:"user_agents"`
	RequestedPaths  []string  `json:"requested_paths"`
	StatusCodes     []int     `json:"status_codes"`
	ThreatScore     int       `json:"threat_score"`
	IsBlacklisted   bool      `json:"is_blacklisted"`
	IsWhitelisted   bool      `json:"is_whitelisted"`
}
EOF

# 2. 创建monitor.go
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

# 3. 创建threat_detector.go
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

// 处理可疑数据包
func (td *ThreatDetector) ProcessSuspiciousPacket(packet PacketInfo) {
	// 简单实现，实际应用中会有更复杂的逻辑
	log.Printf("处理可疑数据包: %s -> %s", packet.SourceIP, packet.DestIP)
}

// 处理可疑HTTP请求
func (td *ThreatDetector) ProcessSuspiciousHTTPRequest(request HTTPRequestDetail) {
	// 简单实现，实际应用中会有更复杂的逻辑
	log.Printf("处理可疑HTTP请求: %s %s", request.Method, request.URL)
}

// 处理可疑IP
func (td *ThreatDetector) ProcessSuspiciousIP(ip string, analysis *IPAnalysis) {
	// 简单实现，实际应用中会有更复杂的逻辑
	log.Printf("处理可疑IP: %s", ip)
}

// 创建威胁告警
func (td *ThreatDetector) CreateThreatAlert(alertType, severity, endpoint, sourceIP string, 
	requests int, description string, httpRequests []HTTPRequestDetail) {
	
	td.mu.Lock()
	defer td.mu.Unlock()
	
	alert := ThreatAlert{
		ID:          td.alertID,
		Type:        alertType,
		Severity:    severity,
		Endpoint:    endpoint,
		SourceIP:    sourceIP,
		Requests:    requests,
		TimeWindow:  "5分钟",
		Timestamp:   time.Now(),
		Description: description,
		Active:      true,
	}
	
	td.alerts = append(td.alerts, alert)
	td.alertID++
	
	log.Printf("创建威胁告警: %s - %s", alert.Type, alert.Description)
}
EOF

# 4. 创建main.go
cat > main.go << 'EOF'
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

var (
	monitor  *NetworkMonitor
	detector *ThreatDetector
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
)

func main() {
	var port = flag.Int("port", 8080, "服务端口")
	var agentMode = flag.Bool("agent", false, "代理模式")
	flag.Parse()

	log.Printf("🚀 启动天眼网络监控系统 (端口: %d)", *port)

	// 初始化组件
	monitor = NewNetworkMonitor()
	detector = NewThreatDetector()

	// 启动服务
	monitor.Start()
	detector.Start()

	if *agentMode {
		agent := NewAgent("agent-001", "本地代理", "127.0.0.1", monitor)
		agent.Start()
		log.Println("🤖 代理模式已启动")
	}

	// 设置路由
	router := setupRoutes()

	// 启动HTTP服务器
	addr := fmt.Sprintf(":%d", *port)
	log.Printf("🌐 服务器启动在 http://localhost%s", addr)
	log.Printf("📊 监控面板: http://localhost%s", addr)
	log.Printf("🔌 WebSocket: ws://localhost%s/ws", addr)

	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatal("启动服务器失败:", err)
	}
}

func setupRoutes() *mux.Router {
	router := mux.NewRouter()

	// 静态文件服务
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))

	// 主页面
	router.HandleFunc("/", serveIndex).Methods("GET")

	// API路由
	api := router.PathPrefix("/api").Subrouter()
	api.Use(corsMiddleware)

	// 监控数据API
	api.HandleFunc("/stats", getStats).Methods("GET")
	api.HandleFunc("/servers", getServers).Methods("GET")
	api.HandleFunc("/endpoints", getEndpoints).Methods("GET")
	api.HandleFunc("/requests", getRequests).Methods("GET")
	api.HandleFunc("/requests/{endpoint}", getRequestsByEndpoint).Methods("GET")

	// 威胁管理API
	api.HandleFunc("/threats", getThreats).Methods("GET")
	api.HandleFunc("/threats/active", getActiveThreats).Methods("GET")
	api.HandleFunc("/threats/{id}/handle", handleThreat).Methods("POST")
	api.HandleFunc("/threats/{id}/whitelist", addToWhitelist).Methods("POST")
	api.HandleFunc("/threats/{id}/block", blockIP).Methods("POST")

	// 代理数据接收API
	api.HandleFunc("/agent/metrics", receiveAgentMetrics).Methods("POST")

	// WebSocket连接
	router.HandleFunc("/ws", handleWebSocket)

	return router
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./static/index.html")
}

// API处理函数
func getStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	stats := monitor.GetCurrentStats()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    stats,
	})
}

func getServers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	servers := monitor.GetServerStatus()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    servers,
	})
}

func getEndpoints(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	endpoints := monitor.GetEndpointStats()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    endpoints,
	})
}

func getRequests(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	requests := monitor.GetRequestDetails()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    requests,
	})
}

func getRequestsByEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	endpoint := vars["endpoint"]

	requests := monitor.GetRequestDetailsByEndpoint(endpoint)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    requests,
	})
}

func getThreats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	threats := detector.GetAllThreats()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    threats,
	})
}

func getActiveThreats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	threats := detector.GetActiveThreats()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    threats,
	})
}

func handleThreat(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "无效的威胁ID", http.StatusBadRequest)
		return
	}

	err = detector.HandleThreat(id)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "威胁已成功处理",
	})
}

func addToWhitelist(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "无效的威胁ID", http.StatusBadRequest)
		return
	}

	// 获取威胁信息以获取IP
	threats := detector.GetAllThreats()
	var targetIP string
	for _, threat := range threats {
		if threat.ID == id {
			targetIP = threat.SourceIP
			break
		}
	}

	if targetIP == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "未找到威胁信息",
		})
		return
	}

	err = detector.AddToWhitelist(targetIP)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("IP %s 已添加到白名单", targetIP),
	})
}

func blockIP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "无效的威胁ID", http.StatusBadRequest)
		return
	}

	// 获取威胁信息以获取IP
	threats := detector.GetAllThreats()
	var targetIP string
	for _, threat := range threats {
		if threat.ID == id {
			targetIP = threat.SourceIP
			break
		}
	}

	if targetIP == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "未找到威胁信息",
		})
		return
	}

	err = detector.BlockIP(targetIP)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("IP %s 已被封禁", targetIP),
	})
}

func receiveAgentMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var metrics SystemMetrics
	if err := json.NewDecoder(r.Body).Decode(&metrics); err != nil {
		http.Error(w, "解析数据失败", http.StatusBadRequest)
		return
	}

	monitor.UpdateServerFromAgent(&metrics)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "指标数据已接收",
	})
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket升级失败: %v", err)
		return
	}

	client := &WSClient{
		conn:     conn,
		send:     make(chan []byte, 256),
		monitor:  monitor,
		detector: detector,
		done:     make(chan struct{}),
	}

	monitor.RegisterClient(client)

	go client.writePump()
	go client.readPump()

	// 发送初始数据
	client.SendJSON(map[string]interface{}{
		"type": "init",
		"data": map[string]interface{}{
			"traffic":   monitor.GetCurrentStats(),
			"servers":   monitor.GetServerStatus(),
			"endpoints": monitor.GetEndpointStats(),
			"threats":   detector.GetActiveThreats(),
		},
	})

	<-client.done
	monitor.UnregisterClient(client)
}
EOF

# 5. 创建agent.go
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

# 6. 创建静态文件目录和HTML文件
mkdir -p static

cat > static/index.html << 'EOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>天眼网络监控系统</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        .threat-card {
            transition: all 0.3s ease;
        }
        .threat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        }
        .status-healthy { color: #10b981; }
        .status-warning { color: #f59e0b; }
        .status-critical { color: #ef4444; }
        .bg-healthy { background-color: #dcfce7; }
        .bg-warning { background-color: #fef3c7; }
        .bg-critical { background-color: #fee2e2; }
    </style>
</head>
<body class="bg-gray-100">
    <div class="min-h-screen">
        <!-- 头部导航 -->
        <header class="bg-white shadow-sm border-b">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="flex justify-between items-center py-4">
                    <div class="flex items-center">
                        <h1 class="text-2xl font-bold text-gray-900">🔍 天眼网络监控系统</h1>
                        <span class="ml-4 px-3 py-1 bg-green-100 text-green-800 text-sm rounded-full" id="status">
                            ● 运行中
                        </span>
                    </div>
                    <div class="flex items-center space-x-4">
                        <div class="text-sm text-gray-500">
                            最后更新: <span id="lastUpdate">--</span>
                        </div>
                        <button onclick="refreshData()" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
                            刷新数据
                        </button>
                    </div>
                </div>
            </div>
        </header>

        <!-- 主要内容 -->
        <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <!-- 统计卡片 -->
            <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
                <div class="bg-white rounded-lg shadow p-6">
                    <div class="flex items-center">
                        <div class="p-2 bg-blue-100 rounded-lg">
                            <svg class="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
                            </svg>
                        </div>
                        <div class="ml-4">
                            <p class="text-sm font-medium text-gray-500">总请求数</p>
                            <p class="text-2xl font-semibold text-gray-900" id="totalRequests">0</p>
                        </div>
                    </div>
                </div>

                <div class="bg-white rounded-lg shadow p-6">
                    <div class="flex items-center">
                        <div class="p-2 bg-red-100 rounded-lg">
                            <svg class="w-6 h-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
                            </svg>
                        </div>
                        <div class="ml-4">
                            <p class="text-sm font-medium text-gray-500">活跃威胁</p>
                            <p class="text-2xl font-semibold text-gray-900" id="activeThreats">0</p>
                        </div>
                    </div>
                </div>

                <div class="bg-white rounded-lg shadow p-6">
                    <div class="flex items-center">
                        <div class="p-2 bg-green-100 rounded-lg">
                            <svg class="w-6 h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12l5 5L20 7"></path>
                            </svg>
                        </div>
                        <div class="ml-4">
                            <p class="text-sm font-medium text-gray-500">健康服务器</p>
                            <p class="text-2xl font-semibold text-gray-900" id="healthyServers">0</p>
                        </div>
                    </div>
                </div>

                <div class="bg-white rounded-lg shadow p-6">
                    <div class="flex items-center">
                        <div class="p-2 bg-yellow-100 rounded-lg">
                            <svg class="w-6 h-6 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                            </svg>
                        </div>
                        <div class="ml-4">
                            <p class="text-sm font-medium text-gray-500">平均响应时间</p>
                            <p class="text-2xl font-semibold text-gray-900" id="avgResponseTime">0ms</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- 威胁告警列表 -->
            <div class="bg-white rounded-lg shadow mb-8">
                <div class="px-6 py-4 border-b border-gray-200">
                    <h2 class="text-lg font-semibold text-gray-900">🚨 威胁告警</h2>
                </div>
                <div class="p-6">
                    <div id="threatsList" class="space-y-4">
                        <div class="text-center text-gray-500 py-8">
                            正在加载威胁数据...
                        </div>
                    </div>
                </div>
            </div>

            <!-- 服务器状态 -->
            <div class="bg-white rounded-lg shadow mb-8">
                <div class="px-6 py-4 border-b border-gray-200">
                    <h2 class="text-lg font-semibold text-gray-900">🖥️ 服务器状态</h2>
                </div>
                <div class="p-6">
                    <div id="serversList" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        <div class="text-center text-gray-500 py-8">
                            正在加载服务器数据...
                        </div>
                    </div>
                </div>
            </div>

            <!-- 流量图表 -->
            <div class="bg-white rounded-lg shadow">
                <div class="px-6 py-4 border-b border-gray-200">
                    <h2 class="text-lg font-semibold text-gray-900">📊 流量监控</h2>
                </div>
                <div class="p-6">
                    <canvas id="trafficChart" width="400" height="200"></canvas>
                </div>
            </div>
        </main>
    </div>

    <script>
        let ws;
        let trafficChart;
        let chartData = {
            labels: [],
            datasets: [{
                label: '请求数',
                data: [],
                borderColor: 'rgb(59, 130, 246)',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                tension: 0.4
            }, {
                label: '威胁数',
                data: [],
                borderColor: 'rgb(239, 68, 68)',
                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                tension: 0.4
            }]
        };

        // 初始化
        document.addEventListener('DOMContentLoaded', function() {
            initChart();
            connectWebSocket();
            loadInitialData();
        });

        // 初始化图表
        function initChart() {
            const ctx = document.getElementById('trafficChart').getContext('2d');
            trafficChart = new Chart(ctx, {
                type: 'line',
                data: chartData,
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    },
                    plugins: {
                        legend: {
                            display: true
                        }
                    }
                }
            });
        }

        // 连接WebSocket
        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}/ws`;
            
            ws = new WebSocket(wsUrl);
            
            ws.onopen = function() {
                console.log('WebSocket连接已建立');
                updateStatus('运行中', 'green');
            };
            
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                handleWebSocketMessage(data);
            };
            
            ws.onclose = function() {
                console.log('WebSocket连接已关闭');
                updateStatus('连接断开', 'red');
                // 5秒后重连
                setTimeout(connectWebSocket, 5000);
            };
            
            ws.onerror = function(error) {
                console.error('WebSocket错误:', error);
                updateStatus('连接错误', 'red');
            };
        }

        // 处理WebSocket消息
        function handleWebSocketMessage(data) {
            switch(data.type) {
                case 'init':
                    handleInitData(data.data);
                    break;
                case 'traffic':
                    updateTrafficChart(data.data);
                    break;
                case 'servers':
                    updateServersList(data.data);
                    break;
                case 'threats':
                    updateThreatsList(data.data);
                    break;
            }
            updateLastUpdateTime();
        }

        // 处理初始数据
        function handleInitData(data) {
            if (data.traffic) {
                data.traffic.forEach(item => updateTrafficChart(item));
            }
            if (data.servers) {
                updateServersList(data.servers);
            }
            if (data.threats) {
                updateThreatsList(data.threats);
            }
        }

        // 更新流量图表
        function updateTrafficChart(data) {
            const time = new Date(data.timestamp).toLocaleTimeString();
            
            chartData.labels.push(time);
            chartData.datasets[0].data.push(data.requests);
            chartData.datasets[1].data.push(data.threats);
            
            // 保持最多20个数据点
            if (chartData.labels.length > 20) {
                chartData.labels.shift();
                chartData.datasets[0].data.shift();
                chartData.datasets[1].data.shift();
            }
            
            trafficChart.update('none');
            
            // 更新统计数据
            document.getElementById('totalRequests').textContent = data.requests.toLocaleString();
            document.getElementById('activeThreats').textContent = data.threats;
            document.getElementById('avgResponseTime').textContent = Math.round(data.response_time) + 'ms';
        }

        // 更新服务器列表
        function updateServersList(servers) {
            const container = document.getElementById('serversList');
            
            if (!servers || servers.length === 0) {
                container.innerHTML = '<div class="text-center text-gray-500 py-8">暂无服务器数据</div>';
                return;
            }
            
            let healthyCount = 0;
            const html = servers.map(server => {
                if (server.status === 'healthy') healthyCount++;
                
                const statusClass = `status-${server.status}`;
                const bgClass = `bg-${server.status}`;
                
                return `
                    <div class="border rounded-lg p-4 ${bgClass}">
                        <div class="flex justify-between items-start mb-2">
                            <h3 class="font-semibold text-gray-900">${server.name}</h3>
                            <span class="px-2 py-1 text-xs rounded-full ${statusClass} bg-white">
                                ${getStatusText(server.status)}
                            </span>
                        </div>
                        <p class="text-sm text-gray-600 mb-2">IP: ${server.ip}</p>
                        <div class="space-y-1">
                            <div class="flex justify-between text-sm">
                                <span>CPU:</span>
                                <span>${server.cpu.toFixed(1)}%</span>
                            </div>
                            <div class="flex justify-between text-sm">
                                <span>内存:</span>
                                <span>${server.memory.toFixed(1)}%</span>
                            </div>
                            <div class="flex justify-between text-sm">
                                <span>请求数:</span>
                                <span>${server.requests.toLocaleString()}</span>
                            </div>
                        </div>
                    </div>
                `;
            }).join('');
            
            container.innerHTML = html;
            document.getElementById('healthyServers').textContent = healthyCount;
        }

        // 更新威胁列表
        function updateThreatsList(threats) {
            const container = document.getElementById('threatsList');
            
            if (!threats || threats.length === 0) {
                container.innerHTML = '<div class="text-center text-gray-500 py-8">暂无威胁告警</div>';
                return;
            }
            
            const activeThreats = threats.filter(threat => threat.active);
            
            const html = activeThreats.map(threat => {
                const severityColors = {
                    'critical': 'bg-red-100 text-red-800 border-red-200',
                    'high': 'bg-orange-100 text-orange-800 border-orange-200',
                    'medium': 'bg-yellow-100 text-yellow-800 border-yellow-200',
                    'low': 'bg-blue-100 text-blue-800 border-blue-200'
                };
                
                const severityColor = severityColors[threat.severity] || severityColors['medium'];
                
                return `
                    <div class="threat-card border rounded-lg p-4 ${severityColor}">
                        <div class="flex justify-between items-start mb-3">
                            <div>
                                <h3 class="font-semibold text-lg">${getThreatIcon(threat.type)} ${threat.type}</h3>
                                <p class="text-sm opacity-75">${threat.description}</p>
                            </div>
                            <span class="px-2 py-1 text-xs rounded-full bg-white bg-opacity-50">
                                ${threat.severity.toUpperCase()}
                            </span>
                        </div>
                        
                        <div class="grid grid-cols-2 gap-4 mb-4 text-sm">
                            <div>
                                <span class="font-medium">目标端口:</span>
                                <span class="ml-1">${threat.endpoint}</span>
                            </div>
                            <div>
                                <span class="font-medium">请求数量:</span>
                                <span class="ml-1">${threat.requests.toLocaleString()} 次/${threat.time_window}</span>
                            </div>
                            <div>
                                <span class="font-medium">来源:</span>
                                <span class="ml-1">${threat.source_ip}</span>
                            </div>
                            <div>
                                <span class="font-medium">检测时间:</span>
                                <span class="ml-1">${new Date(threat.timestamp).toLocaleString()}</span>
                            </div>
                        </div>
                        
                        <div class="flex space-x-2">
                            <button onclick="handleThreat(${threat.id})" 
                                    class="px-4 py-2 bg-green-600 text-white text-sm rounded hover:bg-green-700 transition-colors">
                                处理
                            </button>
                            <button onclick="addToWhitelist(${threat.id})" 
                                    class="px-4 py-2 bg-blue-600 text-white text-sm rounded hover:bg-blue-700 transition-colors">
                                加白名单
                            </button>
                            <button onclick="blockIP(${threat.id})" 
                                    class="px-4 py-2 bg-red-600 text-white text-sm rounded hover:bg-red-700 transition-colors">
                                封禁IP
                            </button>
                        </div>
                    </div>
                `;
            }).join('');
            
            container.innerHTML = html || '<div class="text-center text-gray-500 py-8">暂无活跃威胁</div>';
        }

        // 威胁处理函数
        async function handleThreat(threatId) {
            try {
                const response = await fetch(`/api/threats/${threatId}/handle`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showNotification('威胁已成功处理', 'success');
                    refreshThreats();
                } else {
                    showNotification('处理失败: ' + result.message, 'error');
                }
            } catch (error) {
                console.error('处理威胁失败:', error);
                showNotification('处理威胁时发生错误', 'error');
            }
        }

        // 添加到白名单
        async function addToWhitelist(threatId) {
            try {
                const response = await fetch(`/api/threats/${threatId}/whitelist`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showNotification(result.message, 'success');
                    refreshThreats();
                } else {
                    showNotification('添加白名单失败: ' + result.message, 'error');
                }
            } catch (error) {
                console.error('添加白名单失败:', error);
                showNotification('添加白名单时发生错误', 'error');
            }
        }

        // 封禁IP
        async function blockIP(threatId) {
            if (!confirm('确定要封禁此IP吗？')) {
                return;
            }
            
            try {
                const response = await fetch(`/api/threats/${threatId}/block`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showNotification(result.message, 'success');
                    refreshThreats();
                } else {
                    showNotification('封禁IP失败: ' + result.message, 'error');
                }
            } catch (error) {
                console.error('封禁IP失败:', error);
                showNotification('封禁IP时发生错误', 'error');
            }
        }

        // 刷新威胁数据
        async function refreshThreats() {
            try {
                const response = await fetch('/api/threats/active');
                const result = await response.json();
                
                if (result.success) {
                    updateThreatsList(result.data);
                }
            } catch (error) {
                console.error('刷新威胁数据失败:', error);
            }
        }

        // 刷新所有数据
        async function refreshData() {
            try {
                // 刷新威胁数据
                await refreshThreats();
                
                // 刷新服务器数据
                const serversResponse = await fetch('/api/servers');
                const serversResult = await serversResponse.json();
                if (serversResult.success) {
                    updateServersList(serversResult.data);
                }
                
                showNotification('数据已刷新', 'success');
            } catch (error) {
                console.error('刷新数据失败:', error);
                showNotification('刷新数据失败', 'error');
            }
        }

        // 加载初始数据
        async function loadInitialData() {
            try {
                // 加载威胁数据
                const threatsResponse = await fetch('/api/threats/active');
                const threatsResult = await threatsResponse.json();
                if (threatsResult.success) {
                    updateThreatsList(threatsResult.data);
                }
                
                // 加载服务器数据
                const serversResponse = await fetch('/api/servers');
                const serversResult = await serversResponse.json();
                if (serversResult.success) {
                    updateServersList(serversResult.data);
                }
                
                // 加载流量数据
                const statsResponse = await fetch('/api/stats');
                const statsResult = await statsResponse.json();
                if (statsResult.success && statsResult.data.length > 0) {
                    statsResult.data.forEach(item => updateTrafficChart(item));
                }
            } catch (error) {
                console.error('加载初始数据失败:', error);
            }
        }

        // 工具函数
        function getStatusText(status) {
            const statusMap = {
                'healthy': '健康',
                'warning': '警告',
                'critical': '严重'
            };
            return statusMap[status] || status;
        }

        function getThreatIcon(type) {
            const iconMap = {
                'DDoS Attack': '⚡',
                'Brute Force': '🔨',
                'Rate Limit Exceeded': '⏱️',
                'Suspicious Activity': '🔍',
                'ProcessDown': '⚠️'
            };
            return iconMap[type] || '🚨';
        }

        function updateStatus(text, color) {
            const statusElement = document.getElementById('status');
            statusElement.textContent = `● ${text}`;
            statusElement.className = `ml-4 px-3 py-1 text-sm rounded-full`;
            
            if (color === 'green') {
                statusElement.classList.add('bg-green-100', 'text-green-800');
            } else if (color === 'red') {
                statusElement.classList.add('bg-red-100', 'text-red-800');
            } else {
                statusElement.classList.add('bg-yellow-100', 'text-yellow-800');
            }
        }

        function updateLastUpdateTime() {
            document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();
        }

        function showNotification(message, type) {
            // 创建通知元素
            const notification = document.createElement('div');
            notification.className = `fixed top-4 right-4 px-6 py-3 rounded-lg shadow-lg z-50 transition-all duration-300`;
            
            if (type === 'success') {
                notification.classList.add('bg-green-500', 'text-white');
            } else if (type === 'error') {
                notification.classList.add('bg-red-500', 'text-white');
            } else {
                notification.classList.add('bg-blue-500', 'text-white');
            }
            
            notification.textContent = message;
            document.body.appendChild(notification);
            
            // 3秒后自动移除
            setTimeout(() => {
                notification.style.opacity = '0';
                notification.style.transform = 'translateX(100%)';
                setTimeout(() => {
                    document.body.removeChild(notification);
                }, 300);
            }, 3000);
        }
    </script>
</body>
</html>
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
   
   echo -e "${BLUE}📋 文件信息:${NC}"
   ls -la network-monitor
   
   echo -e "${YELLOW}🚀 是否立即启动服务？ (y/n)${NC}"
   read -r response
   if [[ "$response" =~ ^[Yy]$ ]]; then
       echo -e "${GREEN}🎯 启动网络监控系统...${NC}"
       
       # 创建日志目录
       mkdir -p logs
       
       # 后台启动服务
       nohup ./network-monitor > logs/monitor.log 2>&1 &
       
       sleep 3
       
       if pgrep -f "network-monitor" > /dev/null; then
           echo -e "${GREEN}✅ 服务启动成功！${NC}"
           
           # 获取服务器IP信息
           LOCAL_IP=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "127.0.0.1")
           
           echo ""
           echo -e "${GREEN}🎉 天眼网络监控系统运行中！${NC}"
           echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
           echo -e "${BLUE}📊 访问地址:${NC}"
           echo "   本地访问: http://localhost:8080"
           echo "   内网访问: http://$LOCAL_IP:8080"
           echo ""
           echo -e "${BLUE}🔧 管理命令:${NC}"
           echo "   查看日志: tail -f logs/monitor.log"
           echo "   停止服务: pkill -f network-monitor"
           echo "   查看进程: ps aux | grep network-monitor"
           echo "   重启服务: pkill -f network-monitor && ./network-monitor &"
           echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
           
           echo -e "${YELLOW}💡 提示: 现在可以在浏览器中访问监控面板！${NC}"
           
       else
           echo -e "${RED}❌ 服务启动失败，查看日志: cat logs/monitor.log${NC}"
       fi
   else
       echo -e "${BLUE}💡 手动启动命令: ./network-monitor${NC}"
   fi
   
else
   echo -e "${RED}❌ 编译失败${NC}"
   echo -e "${YELLOW}🔍 详细错误信息：${NC}"
   echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
   go build -v . 2>&1
   echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
   exit 1
fi

echo -e "${GREEN}🎉 安装和修复完成！${NC}"
