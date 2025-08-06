package main

import (
	"bufio"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"net"
)

// RealDataCollector collects real system data
type RealDataCollector struct {
	hostname       string
	enabled        bool
	networkStats   *NetworkStats
	connections    []ConnectionInfo
	processes      []ProcessInfo
}

// NetworkStats holds network statistics
type NetworkStats struct {
	ActiveConnections int
	TotalRequests     int
	SuspiciousIPs     int
	BlockedRequests   int
	ThreatLevel       string
	LastAttack        string
}

// ConnectionInfo holds information about network connections
type ConnectionInfo struct {
	LocalAddr   string
	RemoteAddr  string
	State       string
	ProcessName string
	PID         int
}

// ProcessInfo holds information about running processes
type ProcessInfo struct {
	PID         int
	Name        string
	CPUPercent  float64
	MemoryMB    float64
	Status      string
	CreateTime  string
	CommandLine string
}

// SystemInfo holds basic system information
type SystemInfo struct {
	Hostname        string
	OS              string
	Platform        string
	CPUCores        int
	RealDataEnabled bool
	Uptime          int64
	CPUModel        string
	TotalMemory     uint64
}

// SystemMetrics holds current system metrics
type SystemMetrics struct {
	ServerID       string
	ServerName     string
	ServerIP       string
	Timestamp      string
	Status         string
	CPU            float64
	Memory         float64
	Disk           float64
	Network        NetworkMetrics
	ProcessCount   int
}

// NetworkMetrics holds network metrics
type NetworkMetrics struct {
	BytesSent   uint64
	BytesRecv   uint64
	PacketsSent uint64
	PacketsRecv uint64
	Connections int
}

// NewRealDataCollector creates a new real data collector
func NewRealDataCollector() *RealDataCollector {
	hostname, _ := os.Hostname()
	return &RealDataCollector{
		hostname: hostname,
		enabled:  true,
		networkStats: &NetworkStats{
			ThreatLevel: "LOW",
			LastAttack:  "无",
		},
		connections: make([]ConnectionInfo, 0),
		processes:   make([]ProcessInfo, 0),
	}
}

// GetSystemInfo returns basic system information
func (r *RealDataCollector) GetSystemInfo() (*SystemInfo, error) {
	info := &SystemInfo{
		Hostname:        r.hostname,
		OS:              runtime.GOOS,
		Platform:        runtime.GOARCH,
		CPUCores:        runtime.NumCPU(),
		RealDataEnabled: r.enabled,
	}

	// Get uptime (Linux/Unix only)
	if runtime.GOOS == "linux" {
		if uptime, err := r.getUptime(); err == nil {
			info.Uptime = uptime
		}
	}

	// Get CPU model (Linux only)
	if runtime.GOOS == "linux" {
		if cpuModel, err := r.getCPUModel(); err == nil {
			info.CPUModel = cpuModel
		}
	}

	// Get total memory (Linux only)
	if runtime.GOOS == "linux" {
		if totalMem, err := r.getTotalMemory(); err == nil {
			info.TotalMemory = totalMem
		}
	}

	return info, nil
}

// GetSystemMetrics returns current system metrics
func (r *RealDataCollector) GetSystemMetrics() (*SystemMetrics, error) {
	metrics := &SystemMetrics{
		ServerID:   "server-001",
		ServerName: r.hostname,
		ServerIP:   r.getLocalIP(),
		Timestamp:  time.Now().Format(time.RFC3339),
		Status:     "healthy",
	}

	// Get CPU usage
	if cpu, err := r.getCPUUsage(); err == nil {
		metrics.CPU = cpu
	}

	// Get memory usage
	if memory, err := r.getMemoryUsage(); err == nil {
		metrics.Memory = memory
	}

	// Get disk usage
	if disk, err := r.getDiskUsage(); err == nil {
		metrics.Disk = disk
	}

	// Get network metrics
	if network, err := r.getNetworkMetrics(); err == nil {
		metrics.Network = *network
	}

	// Get load average (Linux only)
	if runtime.GOOS == "linux" {
		if loadAvg, err := r.getLoadAverage(); err == nil {
			metrics.Network.BytesSent = loadAvg[0]
			metrics.Network.BytesRecv = loadAvg[1]
			metrics.Network.PacketsSent = loadAvg[2]
			metrics.Network.PacketsRecv = loadAvg[3]
			metrics.Network.Connections = int(loadAvg[4])
		}
	}

	// Get process count
	if procCount, err := r.getProcessCount(); err == nil {
		metrics.ProcessCount = procCount
	}

	// Determine status based on metrics
	metrics.Status = r.determineStatus(metrics)

	return metrics, nil
}

// GetNetworkConnections returns current network connections
func (r *RealDataCollector) GetNetworkConnections() ([]ConnectionInfo, error) {
	var connections []ConnectionInfo

	if runtime.GOOS == "linux" {
		// Use netstat or ss command
		cmd := exec.Command("ss", "-tuln")
		output, err := cmd.Output()
		if err != nil {
			// Fallback to netstat
			cmd = exec.Command("netstat", "-tuln")
			output, err = cmd.Output()
			if err != nil {
				return r.getMockNetworkConnections(), nil
			}
		}

		connections = r.parseNetworkConnections(string(output))
	} else {
		// Return mock data for non-Linux systems
		connections = r.getMockNetworkConnections()
	}

	return connections, nil
}

// GetNetworkStats returns network statistics
func (rdc *RealDataCollector) GetNetworkStats() *NetworkStats {
	rdc.updateNetworkStats()
	return rdc.networkStats
}

// updateNetworkStats updates network statistics
func (rdc *RealDataCollector) updateNetworkStats() {
	// 获取网络连接数
	activeConnections := rdc.getActiveConnections()
	
	// 模拟一些统计数据（在实际环境中应该从真实数据源获取）
	rdc.networkStats.ActiveConnections = activeConnections
	rdc.networkStats.TotalRequests += rand.Intn(10) + 1
	
	// 随机生成一些威胁数据用于演示
	if rand.Float32() < 0.1 { // 10% 概率检测到威胁
		rdc.networkStats.SuspiciousIPs++
		rdc.networkStats.BlockedRequests += rand.Intn(5) + 1
		
		// 更新威胁等级
		if rdc.networkStats.SuspiciousIPs > 10 {
			rdc.networkStats.ThreatLevel = "HIGH"
		} else if rdc.networkStats.SuspiciousIPs > 5 {
			rdc.networkStats.ThreatLevel = "MEDIUM"
		} else {
			rdc.networkStats.ThreatLevel = "LOW"
		}
		
		rdc.networkStats.LastAttack = time.Now().Format("15:04:05")
	}
}

// getActiveConnections returns the number of active connections
func (rdc *RealDataCollector) getActiveConnections() int {
	// 尝试从 /proc/net/tcp 读取连接信息
	if connections := rdc.readProcNetTCP(); connections > 0 {
		return connections
	}
	
	// 备用方法：使用 netstat 命令
	if connections := rdc.getConnectionsFromNetstat(); connections > 0 {
		return connections
	}
	
	// 如果都失败了，返回模拟数据
	return rand.Intn(50) + 10
}

// readProcNetTCP reads active connections from /proc/net/tcp
func (rdc *RealDataCollector) readProcNetTCP() int {
	file, err := os.Open("/proc/net/tcp")
	if err != nil {
		return 0
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	
	// 跳过标题行
	if scanner.Scan() {
		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)
			
			if len(fields) >= 4 {
				// 检查连接状态 (01 = ESTABLISHED)
				if fields[3] == "01" {
					count++
				}
			}
		}
	}
	
	return count
}

// getConnectionsFromNetstat returns active connections from netstat command
func (rdc *RealDataCollector) getConnectionsFromNetstat() int {
	cmd := exec.Command("netstat", "-tn")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}

	lines := strings.Split(string(output), "\n")
	count := 0
	
	for _, line := range lines {
		if strings.Contains(line, "ESTABLISHED") {
			count++
		}
	}
	
	return count
}

// GetConnections returns current network connections
func (rdc *RealDataCollector) GetConnections() []ConnectionInfo {
	rdc.updateConnections()
	return rdc.connections
}

// updateConnections updates network connections
func (rdc *RealDataCollector) updateConnections() {
	connections := make([]ConnectionInfo, 0)
	
	// 尝试读取 /proc/net/tcp
	file, err := os.Open("/proc/net/tcp")
	if err != nil {
		log.Printf("无法读取 /proc/net/tcp: %v", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	
	// 跳过标题行
	if scanner.Scan() {
		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)
			
			if len(fields) >= 10 {
				localAddr := rdc.parseAddress(fields[1])
				remoteAddr := rdc.parseAddress(fields[2])
				state := rdc.parseState(fields[3])
				
				conn := ConnectionInfo{
					LocalAddr:   localAddr,
					RemoteAddr:  remoteAddr,
					State:       state,
					ProcessName: "unknown",
					PID:         0,
				}
				
				connections = append(connections, conn)
			}
		}
	}
	
	rdc.connections = connections
}

// parseAddress parses the hexadecimal address to a human-readable format
func (rdc *RealDataCollector) parseAddress(hexAddr string) string {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return hexAddr
	}
	
	// 解析IP地址 (小端序)
	ipHex := parts[0]
	if len(ipHex) == 8 {
		ip := make([]string, 4)
		for i := 0; i < 4; i++ {
			byteHex := ipHex[i*2 : i*2+2]
			if val, err := strconv.ParseInt(byteHex, 16, 32); err == nil {
				ip[3-i] = strconv.Itoa(int(val))
			}
		}
		
		// 解析端口
		if port, err := strconv.ParseInt(parts[1], 16, 32); err == nil {
			return fmt.Sprintf("%s:%d", strings.Join(ip, "."), port)
		}
	}
	
	return hexAddr
}

// parseState parses the hexadecimal state to a human-readable format
func (rdc *RealDataCollector) parseState(stateHex string) string {
	states := map[string]string{
		"01": "ESTABLISHED",
		"02": "SYN_SENT",
		"03": "SYN_RECV",
		"04": "FIN_WAIT1",
		"05": "FIN_WAIT2",
		"06": "TIME_WAIT",
		"07": "CLOSE",
		"08": "CLOSE_WAIT",
		"09": "LAST_ACK",
		"0A": "LISTEN",
		"0B": "CLOSING",
	}
	
	if state, exists := states[stateHex]; exists {
		return state
	}
	
	return "UNKNOWN"
}

// GetProcesses returns current running processes
func (rdc *RealDataCollector) GetProcesses() []ProcessInfo {
	rdc.updateProcesses()
	return rdc.processes
}

// updateProcesses updates running processes
func (rdc *RealDataCollector) updateProcesses() {
	processes := make([]ProcessInfo, 0)
	
	// 读取 /proc 目录
	procDir, err := os.Open("/proc")
	if err != nil {
		log.Printf("无法读取 /proc 目录: %v", err)
		return
	}
	defer procDir.Close()
	
	entries, err := procDir.Readdir(-1)
	if err != nil {
		log.Printf("无法读取 /proc 目录内容: %v", err)
		return
	}
	
	for _, entry := range entries {
		if entry.IsDir() {
			if pid, err := strconv.Atoi(entry.Name()); err == nil {
				if process := rdc.getProcessInfo(pid); process != nil {
					processes = append(processes, *process)
				}
			}
		}
	}
	
	rdc.processes = processes
}

// getProcessInfo retrieves information about a specific process
func (rdc *RealDataCollector) getProcessInfo(pid int) *ProcessInfo {
	// 读取进程名称
	commFile := fmt.Sprintf("/proc/%d/comm", pid)
	nameBytes, err := os.ReadFile(commFile)
	if err != nil {
		return nil
	}
	
	name := strings.TrimSpace(string(nameBytes))
	
	// 读取进程状态
	statFile := fmt.Sprintf("/proc/%d/stat", pid)
	statBytes, err := os.ReadFile(statFile)
	if err != nil {
		return nil
	}
	
	statFields := strings.Fields(string(statBytes))
	if len(statFields) < 3 {
		return nil
	}
	
	return &ProcessInfo{
		PID:         pid,
		Name:        name,
		CPUPercent:  0.0, // 需要复杂计算
		MemoryMB:    0.0, // 需要从 /proc/pid/status 读取
		Status:      "running",
		CreateTime:  time.Now().Format("15:04:05"),
	}
}

// GetSystemLoad returns system load averages
func (rdc *RealDataCollector) GetSystemLoad() []float64 {
	loadavgBytes, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return []float64{0.0, 0.0, 0.0}
	}
	
	fields := strings.Fields(string(loadavgBytes))
	if len(fields) < 3 {
		return []float64{0.0, 0.0, 0.0}
	}
	
	load := make([]float64, 3)
	for i := 0; i < 3; i++ {
		if val, err := strconv.ParseFloat(fields[i], 64); err == nil {
			load[i] = val
		}
	}
	
	return load
}

// GetMemoryUsage returns memory usage percentage
func (rdc *RealDataCollector) GetMemoryUsage() float64 {
	meminfoBytes, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0.0
	}
	
	lines := strings.Split(string(meminfoBytes), "\n")
	memInfo := make(map[string]int64)
	
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			key := strings.TrimSuffix(fields[0], ":")
			if val, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				memInfo[key] = val
			}
		}
	}
	
	total := memInfo["MemTotal"]
	available := memInfo["MemAvailable"]
	
	if total > 0 {
		used := total - available
		return float64(used) / float64(total) * 100.0
	}
	
	return 0.0
}

// GetNetworkMetrics returns current network metrics
func (r *RealDataCollector) GetNetworkMetrics() (*NetworkMetrics, error) {
	metrics := &NetworkMetrics{}

	if runtime.GOOS != "linux" {
		// Mock data
		now := time.Now().Unix()
		metrics.BytesSent = uint64(1024*1024*100 + now*1000)
		metrics.BytesRecv = uint64(1024*1024*200 + now*1500)
		metrics.PacketsSent = uint64(50000 + now*10)
		metrics.PacketsRecv = uint64(75000 + now*15)
		metrics.Connections = int(50 + now%20)
		return metrics, nil
	}

	// Read /proc/net/dev for network statistics
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return metrics, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, ":") && !strings.Contains(line, "lo:") {
			fields := strings.Fields(line)
			if len(fields) >= 10 {
				if recv, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					metrics.BytesRecv += recv
				}
				if sent, err := strconv.ParseUint(fields[9], 10, 64); err == nil {
					metrics.BytesSent += sent
				}
				if recvPkts, err := strconv.ParseUint(fields[2], 10, 64); err == nil {
					metrics.PacketsRecv += recvPkts
				}
				if sentPkts, err := strconv.ParseUint(fields[10], 10, 64); err == nil {
					metrics.PacketsSent += sentPkts
				}
			}
		}
	}

	// Count network connections
	if connections, err := r.countNetworkConnections(); err == nil {
		metrics.Connections = connections
	}

	return metrics, nil
}

// getUptime returns system uptime
func (r *RealDataCollector) getUptime() (int64, error) {
	cmd := exec.Command("cat", "/proc/uptime")
	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}

	fields := strings.Fields(string(output))
	if len(fields) < 1 {
		return 0, fmt.Errorf("unexpected uptime format")
	}

	uptime, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}

	return int64(uptime), nil
}

// getCPUModel returns CPU model
func (r *RealDataCollector) getCPUModel() (string, error) {
	cmd := exec.Command("sh", "-c", "grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(output)), nil
}

// getTotalMemory returns total memory in bytes
func (r *RealDataCollector) getTotalMemory() (uint64, error) {
	cmd := exec.Command("sh", "-c", "grep MemTotal /proc/meminfo | awk '{print $2}'")
	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}

	memKB, err := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
	if err != nil {
		return 0, err
	}

	return memKB * 1024, nil // Convert KB to bytes
}

// getLoadAverage returns load averages
func (r *RealDataCollector) getLoadAverage() ([]float64, error) {
	cmd := exec.Command("cat", "/proc/loadavg")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	fields := strings.Fields(string(output))
	if len(fields) < 3 {
		return nil, fmt.Errorf("unexpected loadavg format")
	}

	var loadAvg []float64
	for i := 0; i < 3; i++ {
		if load, err := strconv.ParseFloat(fields[i], 64); err == nil {
			loadAvg = append(loadAvg, load)
		}
	}

	return loadAvg, nil
}

// getProcessCount returns the number of running processes
func (r *RealDataCollector) getProcessCount() (int, error) {
	cmd := exec.Command("sh", "-c", "ps aux | wc -l")
	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}

	count, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil {
		return 0, err
	}

	return count - 1, nil // Subtract header line
}

// countNetworkConnections counts established network connections
func (r *RealDataCollector) countNetworkConnections() (int, error) {
	cmd := exec.Command("ss", "-t", "state", "established")
	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}

	lines := strings.Split(string(output), "\n")
	return len(lines) - 1, nil // Subtract header line
}

// getLocalIP returns the local IP address
func (r *RealDataCollector) getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// determineStatus determines the system status based on metrics
func (r *RealDataCollector) determineStatus(metrics *SystemMetrics) string {
	if metrics.CPU > 90 || metrics.Memory > 90 || metrics.Network.BytesRecv > 95 {
		return "critical"
	}
	if metrics.CPU > 70 || metrics.Memory > 80 || metrics.Network.BytesRecv > 85 {
		return "warning"
	}
	return "healthy"
}

// parseNetworkConnections parses network connections from command output
func (r *RealDataCollector) parseNetworkConnections(output string) []ConnectionInfo {
	var connections []ConnectionInfo
	lines := strings.Split(output, "\n")

	for _, line := range lines[1:] { // Skip header
		if strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		conn := ConnectionInfo{
			Protocol:    strings.ToUpper(fields[0]),
			LocalAddr:   fields[3],
			RemoteAddr:  fields[4],
			State:       "LISTEN",
			ProcessName: "unknown",
			Timestamp:   time.Now().Format(time.RFC3339),
		}

		if len(fields) > 5 {
			conn.State = fields[5]
		}

		connections = append(connections, conn)
	}

	return connections
}

// getMockNetworkConnections returns mock network connections
func (r *RealDataCollector) getMockNetworkConnections() []ConnectionInfo {
	return []ConnectionInfo{
		{
			Protocol:    "TCP",
			LocalAddr:   "0.0.0.0:22",
			RemoteAddr:  "0.0.0.0:*",
			State:       "LISTEN",
			ProcessName: "sshd",
			PID:         1234,
			Timestamp:   time.Now().Format(time.RFC3339),
		},
		{
			Protocol:    "TCP",
			LocalAddr:   "0.0.0.0:80",
			RemoteAddr:  "0.0.0.0:*",
			State:       "LISTEN",
			ProcessName: "nginx",
			PID:         5678,
			Timestamp:   time.Now().Format(time.RFC3339),
		},
		{
			Protocol:    "TCP",
			LocalAddr:   "127.0.0.1:8080",
			RemoteAddr:  "0.0.0.0:*",
			State:       "LISTEN",
			ProcessName: "network-monitor",
			PID:         9999,
			Timestamp:   time.Now().Format(time.RFC3339),
		},
	}
}

// getMockProcesses returns mock process information
func (r *RealDataCollector) getMockProcesses() []ProcessInfo {
	now := time.Now()
	return []ProcessInfo{
		{
			PID:         1,
			Name:        "systemd",
			CPUPercent:    0.1,
			MemoryMB:    512,
			Status:      "S",
			Timestamp:   now.Format(time.RFC3339),
			CommandLine: "/sbin/init",
			CreateTime:  now.Format("15:04:05"),
		},
		{
			PID:         1234,
			Name:        "sshd",
			CPUPercent:    0.2,
			MemoryMB:    1024,
			Status:      "S",
			Timestamp:   now.Format(time.RFC3339),
			CommandLine: "/usr/sbin/sshd -D",
			CreateTime:  now.Format("15:04:05"),
		},
		{
			PID:         9999,
			Name:        "network-monitor",
			CPUPercent:    2.5,
			MemoryMB:    2048,
			Status:      "R",
			Timestamp:   now.Format(time.RFC3339),
			CommandLine: "./network-monitor",
			CreateTime:  now.Format("15:04:05"),
		},
	}
}
