package main

import (
	"encoding/json"
	"log"
	"math/rand"
	"sync"
	"time"
)

// NewNetworkMonitor 创建网络监控器
func NewNetworkMonitor() *NetworkMonitor {
	return &NetworkMonitor{
		trafficData:    []TrafficStats{},
		servers:        make(map[string]*ServerStatus),
		endpoints:      make(map[string]*EndpointStats),
		clients:        make(map[*WSClient]bool),
		requestChan:    make(chan RequestEvent, 100),
		maxDataPoints:  100,
		requestDetails: []RequestDetail{},
	}
}

// Start 启动网络监控器
func (nm *NetworkMonitor) Start() {
	log.Println("📊 网络监控器启动")
	
	// 启动数据收集
	go nm.collectTrafficData()
	go nm.processRequests()
	go nm.broadcastData()
}

// collectTrafficData 收集流量数据
func (nm *NetworkMonitor) collectTrafficData() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		nm.mu.Lock()
		
		// 生成模拟流量数据
		stats := TrafficStats{
			Timestamp:    time.Now(),
			Requests:     rand.Intn(100) + 50,
			Threats:      rand.Intn(10),
			ResponseTime: rand.Float64()*100 + 50,
		}
		
		nm.trafficData = append(nm.trafficData, stats)
		
		// 保持数据点数量限制
		if len(nm.trafficData) > nm.maxDataPoints {
			nm.trafficData = nm.trafficData[1:]
		}
		
		nm.mu.Unlock()
	}
}

// processRequests 处理请求事件
func (nm *NetworkMonitor) processRequests() {
	for event := range nm.requestChan {
		nm.updateEndpointStats(event)
		nm.addRequestDetail(event)
	}
}

// updateEndpointStats 更新端点统计
func (nm *NetworkMonitor) updateEndpointStats(event RequestEvent) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	
	endpoint := event.Endpoint
	if nm.endpoints[endpoint] == nil {
		nm.endpoints[endpoint] = &EndpointStats{
			Endpoint:    endpoint,
			Requests:    0,
			AvgResponse: 0,
			Status:      "normal",
			LastRequest: time.Now(),
			RequestRate: 0,
		}
	}
	
	stats := nm.endpoints[endpoint]
	stats.Requests++
	stats.AvgResponse = (stats.AvgResponse + event.ResponseTime) / 2
	stats.LastRequest = event.Timestamp
	
	// 计算请求速率（每分钟）
	stats.RequestRate = float64(stats.Requests) / time.Since(stats.LastRequest).Minutes()
	
	// 确定状态
	if stats.RequestRate > 100 {
		stats.Status = "alert"
	} else if stats.RequestRate > 50 {
		stats.Status = "suspicious"
	} else {
		stats.Status = "normal"
	}
}

// addRequestDetail 添加请求详情
func (nm *NetworkMonitor) addRequestDetail(event RequestEvent) {
	nm.detailsMutex.Lock()
	defer nm.detailsMutex.Unlock()
	
	detail := RequestDetail{
		ID:           len(nm.requestDetails) + 1,
		Timestamp:    event.Timestamp,
		IP:           event.IP,
		Method:       "GET",
		Endpoint:     event.Endpoint,
		StatusCode:   200,
		ResponseTime: int(event.ResponseTime),
		UserAgent:    event.UserAgent,
		RequestSize:  rand.Intn(1000),
		ResponseSize: rand.Intn(5000),
		Referer:      "",
		Country:      "Unknown",
		IsSuspicious: false,
	}
	
	nm.requestDetails = append(nm.requestDetails, detail)
	
	// 保持最近1000条记录
	if len(nm.requestDetails) > 1000 {
		nm.requestDetails = nm.requestDetails[1:]
	}
}

// broadcastData 广播数据到WebSocket客户端
func (nm *NetworkMonitor) broadcastData() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		nm.mu.RLock()
		
		data := map[string]interface{}{
			"type":      "update",
			"timestamp": time.Now(),
			"traffic":   nm.trafficData,
			"servers":   nm.servers,
			"endpoints": nm.endpoints,
		}
		
		message, err := json.Marshal(data)
		if err != nil {
			nm.mu.RUnlock()
			continue
		}
		
		// 发送给所有连接的客户端
		for client := range nm.clients {
			select {
			case client.send <- message:
			default:
				close(client.send)
				delete(nm.clients, client)
			}
		}
		
		nm.mu.RUnlock()
	}
}

// AddClient 添加WebSocket客户端
func (nm *NetworkMonitor) AddClient(client *WSClient) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	
	nm.clients[client] = true
	log.Printf("WebSocket客户端连接，当前连接数: %d", len(nm.clients))
}

// RemoveClient 移除WebSocket客户端
func (nm *NetworkMonitor) RemoveClient(client *WSClient) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	
	if _, ok := nm.clients[client]; ok {
		delete(nm.clients, client)
		close(client.send)
		log.Printf("WebSocket客户端断开，当前连接数: %d", len(nm.clients))
	}
}

// UpdateServerMetrics 更新服务器指标
func (nm *NetworkMonitor) UpdateServerMetrics(metrics SystemMetrics) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	
	server := &ServerStatus{
		ID:       metrics.ServerID,
		Name:     metrics.ServerName,
		IP:       metrics.ServerIP,
		Status:   metrics.Status,
		CPU:      metrics.CPU,
		Memory:   metrics.Memory,
		Requests: rand.Intn(1000),
		LastSeen: metrics.Timestamp,
	}
	
	nm.servers[metrics.ServerID] = server
}

// GetServers 获取服务器列表
func (nm *NetworkMonitor) GetServers() []*ServerStatus {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	
	servers := make([]*ServerStatus, 0, len(nm.servers))
	for _, server := range nm.servers {
		servers = append(servers, server)
	}
	
	return servers
}

// GetEndpoints 获取端点列表
func (nm *NetworkMonitor) GetEndpoints() []*EndpointStats {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	
	endpoints := make([]*EndpointStats, 0, len(nm.endpoints))
	for _, endpoint := range nm.endpoints {
		endpoints = append(endpoints, endpoint)
	}
	
	return endpoints
}

// GetRequestDetails 获取请求详情
func (nm *NetworkMonitor) GetRequestDetails() []RequestDetail {
	nm.detailsMutex.RLock()
	defer nm.detailsMutex.RUnlock()
	
	// 返回最近100条记录
	start := 0
	if len(nm.requestDetails) > 100 {
		start = len(nm.requestDetails) - 100
	}
	
	return nm.requestDetails[start:]
}

// AddRequestEvent 添加请求事件
func (nm *NetworkMonitor) AddRequestEvent(event RequestEvent) {
	select {
	case nm.requestChan <- event:
	default:
		log.Println("请求通道已满，丢弃事件")
	}
}
