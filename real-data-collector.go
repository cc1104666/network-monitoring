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
