package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 真实数据收集器
type RealDataCollector struct {
	mu                sync.RWMutex
	monitor          *NetworkMonitor
	detector         *ThreatDetector
	isRunning        bool
	stopChan         chan struct{}
	networkStats     *NetworkStats
	systemStats      *SystemStats
	httpRequests     []HTTPRequest
	maxRequests      int
}

// 网络统计
type NetworkStats struct {
	mu              sync.RWMutex
	totalPackets    int64
	totalBytes      int64
	connections     map[string]*ConnectionInfo
	trafficHistory  []TrafficPoint
}

// 连接信息
type ConnectionInfo struct {
	SourceIP    string    `json:"source_ip"`
	DestIP      string    `json:"dest_ip"`
	SourcePort  int       `json:"source_port"`
	DestPort    int       `json:"dest_port"`
	Protocol    string    `json:"protocol"`
	State       string    `json:"state"`
	Packets     int64     `json:"packets"`
	Bytes       int64     `json:"bytes"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// 流量点
type TrafficPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Requests  int       `json:"requests"`
	Bytes     int64     `json:"bytes"`
	Threats   int       `json:"threats"`
}

// 系统统计
type SystemStats struct {
	mu            sync.RWMutex
	cpuUsage      float64
	memoryUsage   float64
	diskUsage     float64
	networkIO     NetworkIO
	processes     []ProcessInfo
	loadAverage   []float64
}

// 网络IO
type NetworkIO struct {
	BytesReceived int64 `json:"bytes_received"`
	BytesSent     int64 `json:"bytes_sent"`
	PacketsReceived int64 `json:"packets_received"`
	PacketsSent   int64 `json:"packets_sent"`
}

// 进程信息
type ProcessInfo struct {
	PID     int     `json:"pid"`
	Name    string  `json:"name"`
	CPU     float64 `json:"cpu"`
	Memory  float64 `json:"memory"`
	Status  string  `json:"status"`
}

// HTTP请求
type HTTPRequest struct {
	ID           int                    `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	Method       string                 `json:"method"`
	URL          string                 `json:"url"`
	SourceIP     string                 `json:"source_ip"`
	UserAgent    string                 `json:"user_agent"`
	StatusCode   int                    `json:"status_code"`
	ResponseTime int                    `json:"response_time"`
	Size         int                    `json:"size"`
	Headers      map[string]string      `json:"headers"`
	IsSuspicious bool                   `json:"is_suspicious"`
	ThreatScore  int                    `json:"threat_score"`
}

// 创建真实数据收集器
func NewRealDataCollector(monitor *NetworkMonitor, detector *ThreatDetector) *RealDataCollector {
	return &RealDataCollector{
		monitor:      monitor,
		detector:     detector,
		stopChan:     make(chan struct{}),
		maxRequests:  1000,
		networkStats: &NetworkStats{
			connections:    make(map[string]*ConnectionInfo),
			trafficHistory: make([]TrafficPoint, 0),
		},
		systemStats: &SystemStats{
			processes: make([]ProcessInfo, 0),
		},
		httpRequests: make([]HTTPRequest, 0),
	}
}

// 启动真实数据收集
func (rdc *RealDataCollector) Start() {
	log.Println("🔍 启动真实数据收集器...")
	
	rdc.mu.Lock()
	rdc.isRunning = true
	rdc.mu.Unlock()
	
	// 启动各种收集协程
	go rdc.collectSystemMetrics()
	go rdc.collectNetworkTraffic()
	go rdc.collectHTTPRequests()
	go rdc.monitorProcesses()
	go rdc.analyzeThreats()
	
	log.Println("✅ 真实数据收集器已启动")
}

// 收集系统指标
func (rdc *RealDataCollector) collectSystemMetrics() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-rdc.stopChan:
			return
		case <-ticker.C:
			rdc.updateSystemStats()
			rdc.updateTrafficStats()
		}
	}
}

// 更新系统统计
func (rdc *RealDataCollector) updateSystemStats() {
	rdc.systemStats.mu.Lock()
	defer rdc.systemStats.mu.Unlock()
	
	// 获取CPU使用率
	rdc.systemStats.cpuUsage = rdc.getCPUUsage()
	
	// 获取内存使用率
	rdc.systemStats.memoryUsage = rdc.getMemoryUsage()
	
	// 获取磁盘使用率
	rdc.systemStats.diskUsage = rdc.getDiskUsage()
	
	// 获取负载平均值
	rdc.systemStats.loadAverage = rdc.getLoadAverage()
	
	// 更新监控器中的服务器状态
	rdc.updateMonitorServers()
}

// 获取CPU使用率
func (rdc *RealDataCollector) getCPUUsage() float64 {
	cmd := exec.Command("top", "-bn1")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "%Cpu(s)") {
			re := regexp.MustCompile(`(\d+\.\d+)%?\s*us`)
			matches := re.FindStringSubmatch(line)
			if len(matches) > 1 {
				if usage, err := strconv.ParseFloat(matches[1], 64); err == nil {
					return usage
				}
			}
		}
	}
	return 0
}

// 获取内存使用率
func (rdc *RealDataCollector) getMemoryUsage() float64 {
	cmd := exec.Command("free")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Mem:") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				total, _ := strconv.ParseFloat(fields[1], 64)
				used, _ := strconv.ParseFloat(fields[2], 64)
				if total > 0 {
					return (used / total) * 100
				}
			}
		}
	}
	return 0
}

// 获取磁盘使用率
func (rdc *RealDataCollector) getDiskUsage() float64 {
	cmd := exec.Command("df", "-h", "/")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}
	
	lines := strings.Split(string(output), "\n")
	if len(lines) > 1 {
		fields := strings.Fields(lines[1])
		if len(fields) >= 5 {
			usageStr := strings.TrimSuffix(fields[4], "%")
			if usage, err := strconv.ParseFloat(usageStr, 64); err == nil {
				return usage
			}
		}
	}
	return 0
}

// 获取负载平均值
func (rdc *RealDataCollector) getLoadAverage() []float64 {
	cmd := exec.Command("uptime")
	output, err := cmd.Output()
	if err != nil {
		return []float64{0, 0, 0}
	}
	
	re := regexp.MustCompile(`load average: (\d+\.\d+), (\d+\.\d+), (\d+\.\d+)`)
	matches := re.FindStringSubmatch(string(output))
	if len(matches) >= 4 {
		load1, _ := strconv.ParseFloat(matches[1], 64)
		load5, _ := strconv.ParseFloat(matches[2], 64)
		load15, _ := strconv.ParseFloat(matches[3], 64)
		return []float64{load1, load5, load15}
	}
	return []float64{0, 0, 0}
}

// 更新监控器中的服务器状态
func (rdc *RealDataCollector) updateMonitorServers() {
	// 获取本机IP
	localIP := rdc.getLocalIP()
	
	// 确定服务器状态
	status := "healthy"
	if rdc.systemStats.cpuUsage > 80 || rdc.systemStats.memoryUsage > 85 {
		status = "warning"
	}
	if rdc.systemStats.cpuUsage > 95 || rdc.systemStats.memoryUsage > 95 {
		status = "critical"
	}
	
	// 更新服务器状态
	server := &ServerStatus{
		ID:       "local-server",
		Name:     "本地服务器",
		IP:       localIP,
		Status:   status,
		CPU:      rdc.systemStats.cpuUsage,
		Memory:   rdc.systemStats.memoryUsage,
		Requests: rdc.getRequestCount(),
		LastSeen: time.Now(),
	}
	
	rdc.monitor.mu.Lock()
	rdc.monitor.servers["local-server"] = server
	rdc.monitor.mu.Unlock()
}

// 获取本机IP
func (rdc *RealDataCollector) getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// 获取请求数量
func (rdc *RealDataCollector) getRequestCount() int {
	rdc.mu.RLock()
	defer rdc.mu.RUnlock()
	return len(rdc.httpRequests)
}

// 更新流量统计
func (rdc *RealDataCollector) updateTrafficStats() {
	rdc.networkStats.mu.Lock()
	defer rdc.networkStats.mu.Unlock()
	
	// 创建新的流量点
	point := TrafficPoint{
		Timestamp: time.Now(),
		Requests:  rdc.getRequestCount(),
		Bytes:     rdc.networkStats.totalBytes,
		Threats:   len(rdc.detector.GetActiveThreats()),
	}
	
	rdc.networkStats.trafficHistory = append(rdc.networkStats.trafficHistory, point)
	
	// 保持最多100个数据点
	if len(rdc.networkStats.trafficHistory) > 100 {
		rdc.networkStats.trafficHistory = rdc.networkStats.trafficHistory[1:]
	}
	
	// 更新监控器中的流量数据
	stats := TrafficStats{
		Timestamp:    point.Timestamp,
		Requests:     point.Requests,
		Threats:      point.Threats,
		ResponseTime: float64(50 + (point.Requests % 100)), // 模拟响应时间
	}
	
	rdc.monitor.mu.Lock()
	rdc.monitor.trafficData = append(rdc.monitor.trafficData, stats)
	if len(rdc.monitor.trafficData) > rdc.monitor.maxDataPoints {
		rdc.monitor.trafficData = rdc.monitor.trafficData[1:]
	}
	rdc.monitor.mu.Unlock()
}

// 收集网络流量
func (rdc *RealDataCollector) collectNetworkTraffic() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-rdc.stopChan:
			return
		case <-ticker.C:
			rdc.analyzeNetworkConnections()
		}
	}
}

// 分析网络连接
func (rdc *RealDataCollector) analyzeNetworkConnections() {
	cmd := exec.Command("netstat", "-an")
	output, err := cmd.Output()
	if err != nil {
		return
	}
	
	rdc.networkStats.mu.Lock()
	defer rdc.networkStats.mu.Unlock()
	
	lines := strings.Split(string(output), "\n")
	connectionCount := make(map[string]int)
	
	for _, line := range lines {
		if strings.Contains(line, "ESTABLISHED") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				localAddr := fields[3]
				remoteAddr := fields[4]
				
				// 解析地址
				if localIP, localPort := rdc.parseAddress(localAddr); localIP != "" {
					if remoteIP, remotePort := rdc.parseAddress(remoteAddr); remoteIP != "" {
						connKey := fmt.Sprintf("%s:%d->%s:%d", localIP, localPort, remoteIP, remotePort)
						connectionCount[connKey]++
						
						// 检查是否为可疑连接
						if rdc.isSuspiciousConnection(remoteIP, remotePort) {
							rdc.detector.CreateThreatAlert("SuspiciousConnection", "medium", 
								fmt.Sprintf(":%d", remotePort), remoteIP, 1,
								fmt.Sprintf("检测到可疑连接: %s:%d", remoteIP, remotePort), nil)
						}
					}
				}
			}
		}
	}
	
	// 检测连接洪水攻击
	for connKey, count := range connectionCount {
		if count > 100 {
			parts := strings.Split(connKey, "->")
			if len(parts) == 2 {
				sourceIP := strings.Split(parts[0], ":")[0]
				rdc.detector.CreateThreatAlert("ConnectionFlood", "high", "/", sourceIP, count,
					fmt.Sprintf("检测到连接洪水攻击: %d个连接", count), nil)
			}
		}
	}
}

// 解析地址
func (rdc *RealDataCollector) parseAddress(addr string) (string, int) {
	parts := strings.Split(addr, ":")
	if len(parts) >= 2 {
		ip := strings.Join(parts[:len(parts)-1], ":")
		if port, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
			return ip, port
		}
	}
	return "", 0
}

// 判断是否为可疑连接
func (rdc *RealDataCollector) isSuspiciousConnection(ip string, port int) bool {
	// 检查是否连接到可疑端口
	suspiciousPorts := []int{22, 23, 3389, 1433, 3306, 5432, 6379}
	for _, suspiciousPort := range suspiciousPorts {
		if port == suspiciousPort {
			return true
		}
	}
	
	// 检查是否为外部IP
	if !rdc.isLocalIP(ip) {
		return true
	}
	
	return false
}

// 判断是否为本地IP
func (rdc *RealDataCollector) isLocalIP(ip string) bool {
	return strings.HasPrefix(ip, "127.") || 
		   strings.HasPrefix(ip, "192.168.") || 
		   strings.HasPrefix(ip, "10.") || 
		   strings.HasPrefix(ip, "172.")
}

// 收集HTTP请求
func (rdc *RealDataCollector) collectHTTPRequests() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	
	requestID := 1
	
	for {
		select {
		case <-rdc.stopChan:
			return
		case <-ticker.C:
			// 模拟HTTP请求（在实际环境中，这里会解析访问日志）
			rdc.generateHTTPRequest(requestID)
			requestID++
		}
	}
}

// 生成HTTP请求（模拟）
func (rdc *RealDataCollector) generateHTTPRequest(id int) {
	rdc.mu.Lock()
	defer rdc.mu.Unlock()
	
	methods := []string{"GET", "POST", "PUT", "DELETE"}
	urls := []string{"/api/users", "/api/login", "/api/data", "/admin", "/.env", "/config"}
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"curl/7.68.0",
		"python-requests/2.25.1",
		"Googlebot/2.1",
	}
	statusCodes := []int{200, 201, 400, 401, 403, 404, 500}
	
	method := methods[id%len(methods)]
	url := urls[id%len(urls)]
	userAgent := userAgents[id%len(userAgents)]
	statusCode := statusCodes[id%len(statusCodes)]
	sourceIP := rdc.generateRandomIP()
	
	// 计算威胁评分
	threatScore := rdc.calculateThreatScore(method, url, userAgent, statusCode, sourceIP)
	isSuspicious := threatScore > 50
	
	request := HTTPRequest{
		ID:           id,
		Timestamp:    time.Now(),
		Method:       method,
		URL:          url,
		SourceIP:     sourceIP,
		UserAgent:    userAgent,
		StatusCode:   statusCode,
		ResponseTime: 50 + (id % 200),
		Size:         1000 + (id % 5000),
		Headers:      map[string]string{"Content-Type": "application/json"},
		IsSuspicious: isSuspicious,
		ThreatScore:  threatScore,
	}
	
	rdc.httpRequests = append(rdc.httpRequests, request)
	
	// 保持最大数量限制
	if len(rdc.httpRequests) > rdc.maxRequests {
		rdc.httpRequests = rdc.httpRequests[1:]
	}
	
	// 如果是可疑请求，创建威胁告警
	if isSuspicious {
		alertType := "SuspiciousRequest"
		if strings.Contains(url, "admin") || strings.Contains(url, ".env") {
			alertType = "UnauthorizedAccess"
		}
		
		rdc.detector.CreateThreatAlert(alertType, "medium", url, sourceIP, 1,
			fmt.Sprintf("检测到可疑HTTP请求: %s %s", method, url), nil)
	}
	
	// 更新请求详情到监控器
	detail := RequestDetail{
		ID:           id,
		Timestamp:    request.Timestamp,
		IP:           request.SourceIP,
		Method:       request.Method,
		Endpoint:     request.URL,
		StatusCode:   request.StatusCode,
		ResponseTime: request.ResponseTime,
		UserAgent:    request.UserAgent,
		RequestSize:  request.Size,
		ResponseSize: request.Size + 500,
		Referer:      "https://example.com",
		Country:      rdc.getCountryFromIP(request.SourceIP),
		IsSuspicious: request.IsSuspicious,
	}
	
	rdc.monitor.detailsMutex.Lock()
	rdc.monitor.requestDetails = append(rdc.monitor.requestDetails, detail)
	if len(rdc.monitor.requestDetails) > 1000 {
		rdc.monitor.requestDetails = rdc.monitor.requestDetails[1:]
	}
	rdc.monitor.detailsMutex.Unlock()
}

// 生成随机IP
func (rdc *RealDataCollector) generateRandomIP() string {
	ips := []string{
		"192.168.1.100", "192.168.1.101", "192.168.1.102",
		"203.45.67.89", "185.220.101.42", "91.198.174.192",
		"127.0.0.1", "10.0.0.50", "172.16.0.25",
	}
	return ips[time.Now().Nanosecond()%len(ips)]
}

// 计算威胁评分
func (rdc *RealDataCollector) calculateThreatScore(method, url, userAgent string, statusCode int, sourceIP string) int {
	score := 0
	
	// 基于URL路径
	if strings.Contains(url, "admin") || strings.Contains(url, ".env") || strings.Contains(url, "config") {
		score += 40
	}
	
	// 基于HTTP方法
	if method == "POST" || method == "PUT" || method == "DELETE" {
		score += 20
	}
	
	// 基于User-Agent
	if strings.Contains(strings.ToLower(userAgent), "curl") || 
	   strings.Contains(strings.ToLower(userAgent), "python") {
		score += 30
	}
	
	// 基于状态码
	if statusCode >= 400 {
		score += 25
	}
	
	// 基于IP地址
	if !rdc.isLocalIP(sourceIP) {
		score += 15
	}
	
	return score
}

// 获取国家信息
func (rdc *RealDataCollector) getCountryFromIP(ip string) string {
	if rdc.isLocalIP(ip) {
		return "本地"
	}
	
	countries := []string{"中国", "美国", "俄罗斯", "德国", "日本", "未知"}
	return countries[len(ip)%len(countries)]
}

// 监控进程
func (rdc *RealDataCollector) monitorProcesses() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	criticalProcesses := []string{"nginx", "apache2", "mysql", "redis-server", "sshd"}
	
	for {
		select {
		case <-rdc.stopChan:
			return
		case <-ticker.C:
			for _, process := range criticalProcesses {
				if !rdc.isProcessRunning(process) {
					rdc.detector.CreateThreatAlert("ProcessDown", "critical", "/system", "localhost", 1,
						fmt.Sprintf("关键进程 %s 已停止运行", process), nil)
				}
			}
		}
	}
}

// 检查进程是否运行
func (rdc *RealDataCollector) isProcessRunning(processName string) bool {
	cmd := exec.Command("pgrep", processName)
	err := cmd.Run()
	return err == nil
}

// 分析威胁
func (rdc *RealDataCollector) analyzeThreats() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-rdc.stopChan:
			return
		case <-ticker.C:
			rdc.performThreatAnalysis()
		}
	}
}

// 执行威胁分析
func (rdc *RealDataCollector) performThreatAnalysis() {
	rdc.mu.RLock()
	defer rdc.mu.RUnlock()
	
	// 分析HTTP请求模式
	ipRequestCount := make(map[string]int)
	suspiciousRequests := 0
	
	now := time.Now()
	for _, request := range rdc.httpRequests {
		// 只分析最近5分钟的请求
		if now.Sub(request.Timestamp) <= 5*time.Minute {
			ipRequestCount[request.SourceIP]++
			if request.IsSuspicious {
				suspiciousRequests++
			}
		}
	}
	
	// 检测DDoS攻击
	for ip, count := range ipRequestCount {
		if count > 100 { // 5分钟内超过100个请求
			rdc.detector.CreateThreatAlert("DDoS", "critical", "/", ip, count,
				fmt.Sprintf("检测到来自 %s 的DDoS攻击，5分钟内 %d 个请求", ip, count), nil)
		}
	}
	
	// 检测异常活动
	if suspiciousRequests > 50 {
		rdc.detector.CreateThreatAlert("AnomalousActivity", "high", "/", "multiple", suspiciousRequests,
			fmt.Sprintf("检测到异常活动，5分钟内 %d 个可疑请求", suspiciousRequests), nil)
	}
}

// 停止收集器
func (rdc *RealDataCollector) Stop() {
	log.Println("🛑 停止真实数据收集器...")
	
	rdc.mu.Lock()
	rdc.isRunning = false
	rdc.mu.Unlock()
	
	close(rdc.stopChan)
	
	log.Println("✅ 真实数据收集器已停止")
}

// 获取HTTP请求数据
func (rdc *RealDataCollector) GetHTTPRequests() []HTTPRequest {
	rdc.mu.RLock()
	defer rdc.mu.RUnlock()
	
	requests := make([]HTTPRequest, len(rdc.httpRequests))
	copy(requests, rdc.httpRequests)
	return requests
}

// 获取网络统计
func (rdc *RealDataCollector) GetNetworkStats() *NetworkStats {
	rdc.networkStats.mu.RLock()
	defer rdc.networkStats.mu.RUnlock()
	
	return rdc.networkStats
}

// 获取系统统计
func (rdc *RealDataCollector) GetSystemStats() *SystemStats {
	rdc.systemStats.mu.RLock()
	defer rdc.systemStats.mu.RUnlock()
	
	return rdc.systemStats
}
