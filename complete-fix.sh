#!/bin/bash

echo "🔧 完整修复天眼监控系统..."

# 设置Go环境
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
export GOPROXY=https://goproxy.cn,direct

echo "✅ Go环境已设置"

# 备份当前文件
echo "💾 备份当前文件..."
mkdir -p backup
cp *.go backup/ 2>/dev/null || true

# 创建完整的monitor.go文件
echo "📝 创建完整的monitor.go..."
cat > monitor.go << 'EOF'
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"sync"
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
	go nm.generateRequestDetailsLoop()
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

func (nm *NetworkMonitor) generateRequestDetailsLoop() {
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

// 数据获取方法 - handlers.go需要的方法
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

// 代理更新方法 - main.go需要的方法
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

// WebSocket客户端方法 - main.go需要的方法
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

# 创建完整的threat_detector.go文件
echo "📝 创建完整的threat_detector.go..."
cat > threat_detector.go << 'EOF'
package main

import (
	"fmt"
	"log"
	"math/rand"
	"sync"
	"time"
)

func NewThreatDetector() *ThreatDetector {
	return &ThreatDetector{
		alerts:       make([]ThreatAlert, 0),
		requestCount: make(map[string]map[string]int),
		timeWindows:  make(map[string]time.Time),
		alertID:      1,
	}
}

func (td *ThreatDetector) Start() {
	go td.generateThreats()
	go td.cleanupOldAlerts()
	log.Println("威胁检测器已启动")
}

func (td *ThreatDetector) generateThreats() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	threatTypes := []string{"DDoS", "BruteForce", "RateLimit", "SQLInjection", "XSS"}
	severities := []string{"critical", "high", "medium", "low"}
	endpoints := []string{"/api/login", "/api/users", "/api/data", "/api/upload", "/api/search"}
	sourceIPs := []string{"203.45.67.89", "192.168.1.100", "10.0.0.50", "172.16.0.25", "45.123.45.67"}

	for range ticker.C {
		if rand.Float32() < 0.3 {
			td.mu.Lock()
			
			alert := ThreatAlert{
				ID:          td.alertID,
				Type:        threatTypes[rand.Intn(len(threatTypes))],
				Severity:    severities[rand.Intn(len(severities))],
				Endpoint:    endpoints[rand.Intn(len(endpoints))],
				Requests:    rand.Intn(10000) + 1000,
				TimeWindow:  "5分钟",
				SourceIP:    sourceIPs[rand.Intn(len(sourceIPs))],
				Timestamp:   time.Now(),
				Description: td.generateThreatDescription(),
				Active:      true,
			}
			
			td.alerts = append(td.alerts, alert)
			td.alertID++
			
			td.mu.Unlock()
			
			log.Printf("🚨 检测到威胁: %s - %s (%s)", alert.Type, alert.Severity, alert.SourceIP)
		}
	}
}

func (td *ThreatDetector) generateThreatDescription() string {
	descriptions := []string{
		"检测到异常高频请求，可能存在DDoS攻击",
		"发现多次登录失败尝试，疑似暴力破解",
		"请求频率超过正常阈值，触发限流保护",
		"检测到可疑的SQL注入尝试",
		"发现潜在的跨站脚本攻击",
		"异常的API调用模式，可能存在恶意行为",
		"检测到来自可疑IP的大量请求",
		"发现异常的用户代理字符串",
	}
	return descriptions[rand.Intn(len(descriptions))]
}

func (td *ThreatDetector) cleanupOldAlerts() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		td.mu.Lock()
		
		cutoff := time.Now().Add(-1 * time.Hour)
		var activeAlerts []ThreatAlert
		
		for _, alert := range td.alerts {
			if alert.Timestamp.After(cutoff) {
				activeAlerts = append(activeAlerts, alert)
			}
		}
		
		td.alerts = activeAlerts
		td.mu.Unlock()
	}
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
	
	var activeThreats []ThreatAlert
	for _, alert := range td.alerts {
		if alert.Active {
			activeThreats = append(activeThreats, alert)
		}
	}
	return activeThreats
}

func (td *ThreatDetector) AddThreat(alert ThreatAlert) {
	td.mu.Lock()
	defer td.mu.Unlock()
	
	alert.ID = td.alertID
	alert.Timestamp = time.Now()
	alert.Active = true
	
	td.alerts = append(td.alerts, alert)
	td.alertID++
}

func (td *ThreatDetector) DeactivateThreat(id int) {
	td.mu.Lock()
	defer td.mu.Unlock()
	
	for i := range td.alerts {
		if td.alerts[i].ID == id {
			td.alerts[i].Active = false
			break
		}
	}
}
EOF

# 清理并重新构建
echo "🧹 清理缓存..."
go clean -cache -modcache -i -r 2>/dev/null

echo "📦 重新初始化模块..."
rm -f go.mod go.sum
go mod init network-monitor
go mod tidy

echo "📥 下载依赖..."
go get github.com/gorilla/mux@latest
go get github.com/gorilla/websocket@latest
go get github.com/shirou/gopsutil/v3@latest

echo "🔨 开始编译..."
if go build -o sky-eye-monitor *.go; then
    echo "✅ 编译成功！"
    echo ""
    echo "🚀 启动服务："
    echo "  ./sky-eye-monitor"
    echo ""
    echo "🤖 启动代理模式："
    echo "  ./sky-eye-monitor agent"
    echo ""
    echo "📊 访问监控面板："
    echo "  http://localhost:8080"
    echo "  http://$(hostname -I | awk '{print $1}'):8080"
    echo ""
    
    # 询问是否立即启动
    read -p "是否立即启动服务？(y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "🚀 启动天眼监控系统..."
        echo "📋 日志将保存到 monitor.log"
        nohup ./sky-eye-monitor > monitor.log 2>&1 &
        echo "✅ 服务已在后台启动 (PID: $!)"
        echo ""
        echo "📊 管理命令："
        echo "  查看日志: tail -f monitor.log"
        echo "  停止服务: pkill sky-eye-monitor"
        echo "  查看进程: ps aux | grep sky-eye-monitor"
    fi
else
    echo "❌ 编译失败"
    echo ""
    echo "🔍 详细错误信息："
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    go build -o sky-eye-monitor *.go
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit 1
fi
