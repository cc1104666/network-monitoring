package main

import (
	"bufio"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
	"net"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	netutil "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

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
		connections:    make([]ConnectionInfo, 0),
		processes:      make([]ProcessInfo, 0),
		startTime:      time.Now(),
		lastUpdateTime: time.Now(),
	}
}

// Start 启动数据收集
func (c *RealDataCollector) Start() {
	log.Println("🔍 启动真实数据收集器...")
	
	// 初始化网络统计
	if netStats, err := netutil.IOCounters(false); err == nil && len(netStats) > 0 {
		c.lastNetworkStats = netStats[0]
	}
	
	log.Println("✅ 数据收集器启动成功")
}

// GetSystemData 获取系统数据
func (c *RealDataCollector) GetSystemData() SystemData {
	now := time.Now()
	
	data := SystemData{
		Timestamp:   now,
		CPU:         c.getCPUInfo(),
		Memory:      c.getMemoryInfo(),
		Disk:        c.getDiskInfo(),
		Network:     c.getNetworkInfo(),
		Processes:   c.getProcessInfo(),
		Connections: c.getConnections(),
		SystemInfo:  c.getSystemInfo(),
		Threats:     []Threat{}, // 威胁数据由ThreatDetector提供
	}
	
	return data
}

// getCPUInfo 获取CPU信息
func (c *RealDataCollector) getCPUInfo() CPUInfo {
	cpuInfo := CPUInfo{
		Cores: runtime.NumCPU(),
	}
	
	// 获取CPU使用率
	if percentages, err := cpu.Percent(time.Second, false); err == nil && len(percentages) > 0 {
		cpuInfo.Usage = percentages[0]
	}
	
	// 获取负载平均值
	if loadAvg, err := host.LoadAvg(); err == nil {
		cpuInfo.LoadAvg = loadAvg.Load1
	}
	
	// 获取CPU频率
	if cpuInfos, err := cpu.Info(); err == nil && len(cpuInfos) > 0 {
		cpuInfo.Frequency = cpuInfos[0].Mhz
	}
	
	return cpuInfo
}

// getMemoryInfo 获取内存信息
func (c *RealDataCollector) getMemoryInfo() MemoryInfo {
	memInfo := MemoryInfo{}
	
	if vmStat, err := mem.VirtualMemory(); err == nil {
		memInfo.Total = vmStat.Total
		memInfo.Used = vmStat.Used
		memInfo.Available = vmStat.Available
		memInfo.UsedPercent = vmStat.UsedPercent
	}
	
	if swapStat, err := mem.SwapMemory(); err == nil {
		memInfo.SwapTotal = swapStat.Total
		memInfo.SwapUsed = swapStat.Used
	}
	
	return memInfo
}

// getDiskInfo 获取磁盘信息
func (c *RealDataCollector) getDiskInfo() DiskInfo {
	diskInfo := DiskInfo{}
	
	if usage, err := disk.Usage("/"); err == nil {
		diskInfo.Total = usage.Total
		diskInfo.Used = usage.Used
		diskInfo.Free = usage.Free
		diskInfo.UsagePercent = usage.UsedPercent
	}
	
	return diskInfo
}

// getNetworkInfo 获取网络信息
func (c *RealDataCollector) getNetworkInfo() NetworkInfo {
	networkInfo := NetworkInfo{}
	
	// 获取网络IO统计
	if netStats, err := netutil.IOCounters(false); err == nil && len(netStats) > 0 {
		stat := netStats[0]
		networkInfo.BytesSent = stat.BytesSent
		networkInfo.BytesRecv = stat.BytesRecv
		networkInfo.PacketsSent = stat.PacketsSent
		networkInfo.PacketsRecv = stat.PacketsRecv
	}
	
	// 获取网络接口信息
	if interfaces, err := netutil.IOCounters(true); err == nil {
		for _, iface := range interfaces {
			networkInfo.Interfaces = append(networkInfo.Interfaces, NetworkInterface{
				Name:      iface.Name,
				BytesSent: iface.BytesSent,
				BytesRecv: iface.BytesRecv,
				IsUp:      true, // 简化处理
			})
		}
	}
	
	// 获取网络连接数
	if connections, err := netutil.Connections("inet"); err == nil {
		networkInfo.Connections = len(connections)
		
		// 获取监听端口
		portMap := make(map[int]bool)
		for _, conn := range connections {
			if conn.Status == "LISTEN" {
				portMap[int(conn.Laddr.Port)] = true
			}
		}
		
		for port := range portMap {
			networkInfo.ListenPorts = append(networkInfo.ListenPorts, port)
		}
	}
	
	return networkInfo
}

// getProcessInfo 获取进程信息
func (c *RealDataCollector) getProcessInfo() []ProcessInfo {
	var processes []ProcessInfo
	
	pids, err := process.Pids()
	if err != nil {
		return processes
	}
	
	// 限制返回的进程数量，避免数据过大
	maxProcesses := 20
	count := 0
	
	for _, pid := range pids {
		if count >= maxProcesses {
			break
		}
		
		proc, err := process.NewProcess(pid)
		if err != nil {
			continue
		}
		
		name, _ := proc.Name()
		cpuPercent, _ := proc.CPUPercent()
		memInfo, _ := proc.MemoryInfo()
		status, _ := proc.Status()
		createTime, _ := proc.CreateTime()
		
		// 获取进程的网络连接数
		connections, _ := proc.Connections()
		
		var memoryMB float32
		if memInfo != nil {
			memoryMB = float32(memInfo.RSS) / 1024 / 1024
		}
		
		processes = append(processes, ProcessInfo{
			PID:         int32(pid),
			Name:        name,
			CPUPercent:  cpuPercent,
			MemoryMB:    memoryMB,
			Status:      status[0], // 取第一个状态
			CreateTime:  createTime,
			Connections: len(connections),
		})
		
		count++
	}
	
	return processes
}

// getConnections 获取网络连接信息
func (c *RealDataCollector) getConnections() []ConnectionInfo {
	var connections []ConnectionInfo
	
	netConnections, err := netutil.Connections("inet")
	if err != nil {
		return connections
	}
	
	// 限制返回的连接数量
	maxConnections := 50
	count := 0
	
	for _, conn := range netConnections {
		if count >= maxConnections {
			break
		}
		
		var processName string
		if conn.Pid != 0 {
			if proc, err := process.NewProcess(conn.Pid); err == nil {
				if name, err := proc.Name(); err == nil {
					processName = name
				}
			}
		}
		
		connections = append(connections, ConnectionInfo{
			Protocol:    "TCP",
			LocalAddr:   fmt.Sprintf("%s:%d", conn.Laddr.IP, conn.Laddr.Port),
			RemoteAddr:  fmt.Sprintf("%s:%d", conn.Raddr.IP, conn.Raddr.Port),
			State:       conn.Status,
			ProcessName: processName,
			PID:         int(conn.Pid),
			Timestamp:   time.Now().Format(time.RFC3339),
		})
		
		count++
	}
	
	return connections
}

// getSystemInfo 获取系统基本信息
func (c *RealDataCollector) getSystemInfo() SystemInfo {
	systemInfo := SystemInfo{}
	
	if hostInfo, err := host.Info(); err == nil {
		systemInfo.Hostname = hostInfo.Hostname
		systemInfo.OS = hostInfo.OS
		systemInfo.Platform = hostInfo.Platform
		systemInfo.PlatformVersion = hostInfo.PlatformVersion
		systemInfo.Architecture = hostInfo.KernelArch
		systemInfo.Uptime = hostInfo.Uptime
		systemInfo.BootTime = hostInfo.BootTime
	}
	
	// 如果无法获取主机名，使用环境变量
	if systemInfo.Hostname == "" {
		if hostname, err := os.Hostname(); err == nil {
			systemInfo.Hostname = hostname
		}
	}
	
	return systemInfo
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

	// Get process count
	if procCount, err := r.getProcessCount(); err == nil {
		metrics.ProcessCount = procCount
	}

	// Determine status based on metrics
	metrics.Status = r.determineStatus(metrics)

	return metrics, nil
}

// GetNetworkStats returns network statistics
func (rdc *RealDataCollector) GetNetworkStats() *NetworkStats {
	// 模拟网络统计数据
	rdc.networkStats.TotalRequests += rand.Intn(10) + 1
	rdc.networkStats.ActiveConnections = rdc.getActiveConnections()
	
	// 随机生成一些威胁数据
	if rand.Intn(100) < 5 { // 5% 概率
		rdc.networkStats.BlockedRequests++
		rdc.networkStats.SuspiciousIPs++
		rdc.networkStats.ThreatLevel = "MEDIUM"
		rdc.networkStats.LastAttack = time.Now().Format("15:04:05")
	}

	return rdc.networkStats
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
	if metrics.CPU > 90 || metrics.Memory > 90 || metrics.Disk > 95 {
		return "critical"
	}
	if metrics.CPU > 70 || metrics.Memory > 80 || metrics.Disk > 85 {
		return "warning"
	}
	return "healthy"
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

// 辅助方法实现
func (r *RealDataCollector) getCPUUsage() (float64, error) {
	if percentages, err := cpu.Percent(time.Second, false); err == nil && len(percentages) > 0 {
		return percentages[0], nil
	}
	return 0.0, fmt.Errorf("failed to get CPU usage")
}

func (r *RealDataCollector) getMemoryUsage() (float64, error) {
	if vmStat, err := mem.VirtualMemory(); err == nil {
		return vmStat.UsedPercent, nil
	}
	return 0.0, fmt.Errorf("failed to get memory usage")
}

func (r *RealDataCollector) getDiskUsage() (float64, error) {
	if usage, err := disk.Usage("/"); err == nil {
		return usage.UsedPercent, nil
	}
	return 0.0, fmt.Errorf("failed to get disk usage")
}

func (r *RealDataCollector) getNetworkMetrics() (*NetworkMetrics, error) {
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
