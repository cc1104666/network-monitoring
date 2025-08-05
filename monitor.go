package main

import (
	"encoding/json"
	"log"
	"math/rand"
	"time"
	"sync"

	"github.com/gorilla/websocket"
)

func NewNetworkMonitor() *NetworkMonitor {
	monitor := &NetworkMonitor{
		mu:             sync.RWMutex{},
		trafficData:    make([]TrafficStats, 0),
		servers:        make(map[string]*ServerStatus),
		endpoints:      make(map[string]*EndpointStats),
		clients:        make(map[*WSClient]bool),
		requestChan:    make(chan RequestEvent, 1000),
		maxDataPoints:  50,
		requestDetails: make([]RequestDetail, 0),
		detailsMutex:   sync.RWMutex{},
	}

	// 初始化服务器数据
	monitor.initializeServers()
	monitor.initializeEndpoints()

	return monitor
}

func (nm *NetworkMonitor) initializeServers() {
	servers := []*ServerStatus{
		{
			ID:     "web-01",
			Name:   "Web Server 01",
			IP:     "192.168.1.10",
			Status: "healthy",
			CPU:    45.0,
			Memory: 62.0,
		},
		{
			ID:     "web-02",
			Name:   "Web Server 02",
			IP:     "192.168.1.11",
			Status: "warning",
			CPU:    78.0,
			Memory: 85.0,
		},
		{
			ID:     "api-01",
			Name:   "API Server 01",
			IP:     "192.168.1.20",
			Status: "healthy",
			CPU:    32.0,
			Memory: 48.0,
		},
		{
			ID:     "db-01",
			Name:   "Database 01",
			IP:     "192.168.1.30",
			Status: "critical",
			CPU:    92.0,
			Memory: 95.0,
		},
	}

	for _, server := range servers {
		server.LastSeen = time.Now()
		nm.servers[server.ID] = server
	}
}

func (nm *NetworkMonitor) initializeEndpoints() {
	endpoints := []*EndpointStats{
		{
			Endpoint:    "/api/users",
			Requests:    15420,
			AvgResponse: 120.0,
			Status:      "normal",
		},
		{
			Endpoint:    "/api/login",
			Requests:    8950,
			AvgResponse: 250.0,
			Status:      "suspicious",
		},
		{
			Endpoint:    "/api/data",
			Requests:    25600,
			AvgResponse: 80.0,
			Status:      "normal",
		},
		{
			Endpoint:    "/api/upload",
			Requests:    3200,
			AvgResponse: 1200.0,
			Status:      "normal",
		},
		{
			Endpoint:    "/api/search",
			Requests:    45000,
			AvgResponse: 300.0,
			Status:      "alert",
		},
	}

	for _, endpoint := range endpoints {
		endpoint.LastRequest = time.Now()
		endpoint.RequestRate = float64(endpoint.Requests) / 60.0 // 假设过去1小时的平均值
		nm.endpoints[endpoint.Endpoint] = endpoint
	}
}

// 从代理更新服务器状态
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
		Requests: 0, // 这里可以从代理获取请求数
		LastSeen: metrics.Timestamp,
	}

	nm.servers[server.ID] = server
	log.Printf("更新服务器状态: %s (%s) - CPU: %.1f%%, 内存: %.1f%%",
		server.Name, server.IP, server.CPU, server.Memory)
}

func (nm *NetworkMonitor) Start() {
	// 启动数据生成器
	go nm.generateTrafficData()
	go nm.updateServerMetrics()
	go nm.processRequests()
	go nm.generateRequestDetailsLoop()

	log.Println("网络监控器已启动")
}

func (nm *NetworkMonitor) generateTrafficData() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		nm.mu.Lock()

		// 生成随机流量数据
		stats := TrafficStats{
			Timestamp:    time.Now(),
			Requests:     rand.Intn(800) + 200,
			Threats:      rand.Intn(10),
			ResponseTime: 100 + rand.Float64()*200,
		}

		nm.trafficData = append(nm.trafficData, stats)

		// 保持数据点数量限制
		if len(nm.trafficData) > nm.maxDataPoints {
			nm.trafficData = nm.trafficData[1:]
		}

		nm.mu.Unlock()

		// 模拟请求事件
		nm.generateRequestEvents(stats.Requests)
	}
}

func (nm *NetworkMonitor) generateRequestEvents(count int) {
	endpoints := []string{"/api/users", "/api/login", "/api/data", "/api/upload", "/api/search"}
	ips := []string{"192.168.1.100", "203.45.67.89", "10.0.0.50", "172.16.0.25"}

	for i := 0; i < count/10; i++ { // 减少事件数量以避免过载
		event := RequestEvent{
			Endpoint:     endpoints[rand.Intn(len(endpoints))],
			IP:           ips[rand.Intn(len(ips))],
			ResponseTime: 50 + rand.Float64()*500,
			Timestamp:    time.Now(),
			UserAgent:    "Mozilla/5.0 (compatible; Monitor/1.0)",
		}

		select {
		case nm.requestChan <- event:
		default:
			// 通道满了，跳过这个事件
		}
	}
}

func (nm *NetworkMonitor) generateRequestDetails() {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
		"Python-requests/2.28.1",
		"curl/7.68.0",
		"PostmanRuntime/7.29.2",
		"python-urllib3/1.26.12",
		"Go-http-client/1.1",
		"okhttp/4.9.3",
	}

	endpoints := []string{"/api/users", "/api/login", "/api/data", "/api/upload", "/api/search"}
	methods := []string{"GET", "POST", "PUT", "DELETE"}
	statusCodes := []int{200, 201, 400, 401, 403, 404, 429, 500}
	ips := []string{"203.45.67.89", "192.168.1.100", "10.0.0.50", "172.16.0.25", "45.123.45.67"}
	countries := []string{"中国", "美国", "俄罗斯", "印度", "巴西"}

	nm.detailsMutex.Lock()
	defer nm.detailsMutex.Unlock()

	// 生成新的请求详情
	for i := 0; i < 5; i++ {
		detail := RequestDetail{
			ID:           len(nm.requestDetails) + i + 1,
			Timestamp:    time.Now().Add(-time.Duration(rand.Intn(3600)) * time.Second),
			IP:           ips[rand.Intn(len(ips))],
			Method:       methods[rand.Intn(len(methods))],
			Endpoint:     endpoints[rand.Intn(len(endpoints))],
			StatusCode:   statusCodes[rand.Intn(len(statusCodes))],
			ResponseTime: rand.Intn(2000) + 50,
			UserAgent:    userAgents[rand.Intn(len(userAgents))],
			RequestSize:  rand.Intn(10000) + 100,
			ResponseSize: rand.Intn(50000) + 500,
			Referer:      "-",
			Country:      countries[rand.Intn(len(countries))],
			IsSuspicious: rand.Float64() > 0.7,
		}

		nm.requestDetails = append(nm.requestDetails, detail)
	}

	// 保持最新1000条记录
	if len(nm.requestDetails) > 1000 {
		nm.requestDetails = nm.requestDetails[len(nm.requestDetails)-1000:]
	}
}

func (nm *NetworkMonitor) generateRequestDetailsLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		nm.generateRequestDetails()
	}
}

func (nm *NetworkMonitor) processRequests() {
	for event := range nm.requestChan {
		nm.mu.Lock()

		// 更新端点统计
		if endpoint, exists := nm.endpoints[event.Endpoint]; exists {
			endpoint.Requests++
			endpoint.LastRequest = event.Timestamp
			endpoint.AvgResponse = (endpoint.AvgResponse + event.ResponseTime) / 2
			endpoint.RequestRate = float64(endpoint.Requests) / 60.0
		}

		nm.mu.Unlock()
	}
}

func (nm *NetworkMonitor) updateServerMetrics() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		nm.mu.Lock()

		for _, server := range nm.servers {
			// 模拟服务器指标变化
			server.CPU += (rand.Float64() - 0.5) * 10
			server.Memory += (rand.Float64() - 0.5) * 5
			server.Requests += rand.Intn(100)

			// 限制范围
			if server.CPU < 0 {
				server.CPU = 0
			}
			if server.CPU > 100 {
				server.CPU = 100
			}
			if server.Memory < 0 {
				server.Memory = 0
			}
			if server.Memory > 100 {
				server.Memory = 100
			}

			// 更新状态
			if server.CPU > 90 || server.Memory > 90 {
				server.Status = "critical"
			} else if server.CPU > 70 || server.Memory > 80 {
				server.Status = "warning"
			} else {
				server.Status = "healthy"
			}

			server.LastSeen = time.Now()
		}

		nm.mu.Unlock()
	}
}

func (nm *NetworkMonitor) RegisterClient(client *WSClient) {
	nm.mu.Lock()
	nm.clients[client] = true
	nm.mu.Unlock()
	log.Printf("WebSocket客户端已连接，当前连接数: %d", len(nm.clients))
}

func (nm *NetworkMonitor) UnregisterClient(client *WSClient) {
	nm.mu.Lock()
	delete(nm.clients, client)
	nm.mu.Unlock()
	log.Printf("WebSocket客户端已断开，当前连接数: %d", len(nm.clients))
}

func (nm *NetworkMonitor) GetCurrentStats() []TrafficStats {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	// 返回副本以避免并发问题
	stats := make([]TrafficStats, len(nm.trafficData))
	copy(stats, nm.trafficData)
	return stats
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

func (client *WSClient) SendJSON(data interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	select {
	case client.send <- jsonData:
		return nil
	default:
		return nil // 客户端发送缓冲区满
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
