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
		td.CreateThreatAlert("RateLimit", "high", endpoint, ip, 
			td.requestCount[endpoint][ip], "检测到异常高频请求", nil)
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
		td.CreateThreatAlert("BruteForce", "critical", "/login", ip, 
			td.ipFailCount[ip], "检测到暴力破解攻击", nil)
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
		td.CreateThreatAlert("SystemError", "medium", "/system", "localhost", 
			len(td.systemErrors), "检测到系统异常", nil)
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
	
	td.CreateThreatAlert("ProcessDown", "critical", "/system", "localhost", 
		1, "关键进程停止: "+processName, nil)
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
			td.CreateThreatAlert("Scanning", "medium", endpoint, ip, 
				td.requestCount["_404_scan"][key], "检测到可能的扫描行为", nil)
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
			td.CreateThreatAlert("ServerError", "high", endpoint, ip, 
				td.requestCount["_5xx_errors"][key], "检测到服务器错误攻击", nil)
		}
	}
}

// 创建威胁告警
func (td *ThreatDetector) CreateThreatAlert(alertType, severity, endpoint, sourceIP string, requests int, description string, details []RequestDetail) {
	td.mu.Lock()
	defer td.mu.Unlock()
	
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
		RequestDetails: details,
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
			td.CreateThreatAlert("DDoS", "critical", "/", ip, 
				totalRequests, "检测到可能的DDoS攻击", nil)
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
			td.CreateThreatAlert("EndpointFlood", "high", endpoint, "multiple", 
				totalRequests, "检测到端点异常访问", nil)
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

// 处理威胁
func (td *ThreatDetector) HandleThreat(threatID int) {
	td.mu.Lock()
	defer td.mu.Unlock()
	
	for i, alert := range td.alerts {
		if alert.ID == threatID {
			td.alerts[i].Active = false
			log.Printf("威胁 %d 已处理", threatID)
			break
		}
	}
}
