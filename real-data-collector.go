package main

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	psnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// RealDataCollector collects real system metrics using gopsutil
type RealDataCollector struct {
	enabled bool
	mu      sync.RWMutex
}

// NewRealDataCollector creates a new data collector
func NewRealDataCollector() *RealDataCollector {
	enabled := os.Getenv("ENABLE_REAL_DATA") == "true"
	if enabled {
		log.Println("✅ Real data collection is ENABLED")
	} else {
		log.Println("🟡 Real data collection is DISABLED - using mock data")
	}
	return &RealDataCollector{
		enabled: enabled,
	}
}

// IsEnabled checks if real data collection is active
func (c *RealDataCollector) IsEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.enabled
}

// GetSystemMetrics collects and returns current system metrics
func (c *RealDataCollector) GetSystemMetrics() (SystemMetrics, error) {
	c.mu.RLock()
	enabled := c.enabled
	c.mu.RUnlock()

	if !enabled {
		return c.getMockSystemMetrics(), nil
	}

	var metrics SystemMetrics
	metrics.Timestamp = time.Now()
	metrics.ServerID = "real-server-001"
	metrics.ServerName = "Production Server"
	metrics.ServerIP = c.getServerIP()

	// CPU
	cpuPercentages, err := cpu.Percent(time.Second, false)
	if err == nil && len(cpuPercentages) > 0 {
		metrics.CPU = cpuPercentages[0]
	} else {
		log.Printf("Warning: Failed to get CPU metrics: %v", err)
		metrics.CPU = 0
	}

	// Memory
	vm, err := mem.VirtualMemory()
	if err == nil {
		metrics.Memory = vm.UsedPercent
	} else {
		log.Printf("Warning: Failed to get memory metrics: %v", err)
		metrics.Memory = 0
	}

	// Disk
	du, err := disk.Usage("/")
	if err == nil {
		metrics.Disk = du.UsedPercent
	} else {
		log.Printf("Warning: Failed to get disk metrics: %v", err)
		metrics.Disk = 0
	}

	// Network
	netIO, err := psnet.IOCounters(false)
	if err == nil && len(netIO) > 0 {
		metrics.Network.BytesSent = netIO[0].BytesSent
		metrics.Network.BytesRecv = netIO[0].BytesRecv
		metrics.Network.PacketsSent = netIO[0].PacketsSent
		metrics.Network.PacketsRecv = netIO[0].PacketsRecv
	} else {
		log.Printf("Warning: Failed to get network metrics: %v", err)
	}

	// Status
	if metrics.CPU > 80 || metrics.Memory > 80 {
		metrics.Status = "critical"
	} else if metrics.CPU > 60 || metrics.Memory > 60 {
		metrics.Status = "warning"
	} else {
		metrics.Status = "healthy"
	}

	return metrics, nil
}

// GetNetworkConnections returns a list of current network connections
func (c *RealDataCollector) GetNetworkConnections() ([]NetworkConnection, error) {
	c.mu.RLock()
	enabled := c.enabled
	c.mu.RUnlock()

	if !enabled {
		return c.getMockNetworkConnections(), nil
	}

	connections, err := psnet.Connections("all")
	if err != nil {
		log.Printf("Warning: Failed to get network connections: %v", err)
		return c.getMockNetworkConnections(), nil
	}

	var results []NetworkConnection
	for _, conn := range connections {
		if conn.Laddr.IP == "" || conn.Status == "NONE" {
			continue
		}

		var procName string
		if conn.Pid > 0 {
			if p, err := process.NewProcess(conn.Pid); err == nil {
				procName, _ = p.Name()
			}
		}

		results = append(results, NetworkConnection{
			Protocol:    strings.ToLower(conn.Type.String()),
			LocalAddr:   fmt.Sprintf("%s:%d", conn.Laddr.IP, conn.Laddr.Port),
			RemoteAddr:  fmt.Sprintf("%s:%d", conn.Raddr.IP, conn.Raddr.Port),
			State:       conn.Status,
			Port:        conn.Laddr.Port,
			ProcessName: procName,
			PID:         conn.Pid,
			Timestamp:   time.Now(),
		})
	}
	return results, nil
}

// GetProcesses returns a list of running processes
func (c *RealDataCollector) GetProcesses() ([]ProcessInfo, error) {
	c.mu.RLock()
	enabled := c.enabled
	c.mu.RUnlock()

	if !enabled {
		return c.getMockProcesses(), nil
	}

	pids, err := process.Pids()
	if err != nil {
		log.Printf("Warning: Failed to get process list: %v", err)
		return c.getMockProcesses(), nil
	}

	var results []ProcessInfo
	for _, pid := range pids {
		p, err := process.NewProcess(pid)
		if err != nil {
			continue
		}

		name, _ := p.Name()
		cpuPercent, _ := p.CPUPercent()
		memPercent, _ := p.MemoryPercent()
		status, _ := p.Status()

		var statusStr string
		if len(status) > 0 {
			statusStr = status[0]
		} else {
			statusStr = "unknown"
		}

		results = append(results, ProcessInfo{
			PID:       pid,
			Name:      name,
			CPUUsage:  cpuPercent,
			Memory:    memPercent,
			Status:    statusStr,
			Timestamp: time.Now(),
		})

		// Limit to top 100 processes to avoid overwhelming the UI
		if len(results) >= 100 {
			break
		}
	}
	return results, nil
}

// GetSystemInfo returns static system information
func (c *RealDataCollector) GetSystemInfo() (SystemInfo, error) {
	c.mu.RLock()
	enabled := c.enabled
	c.mu.RUnlock()

	if !enabled {
		info := c.getMockSystemInfo()
		info.RealDataEnabled = false
		return info, nil
	}

	hostInfo, err := host.Info()
	if err != nil {
		log.Printf("Warning: Failed to get host info: %v", err)
		return c.getMockSystemInfo(), nil
	}

	cpuInfo, err := cpu.Info()
	if err != nil {
		log.Printf("Warning: Failed to get CPU info: %v", err)
	}

	memInfo, err := mem.VirtualMemory()
	if err != nil {
		log.Printf("Warning: Failed to get memory info: %v", err)
	}

	var cpuModel string
	if len(cpuInfo) > 0 {
		cpuModel = cpuInfo[0].ModelName
	} else {
		cpuModel = "Unknown CPU"
	}

	var totalMemory uint64
	if memInfo != nil {
		totalMemory = memInfo.Total
	}

	return SystemInfo{
		Hostname:        hostInfo.Hostname,
		OS:              hostInfo.OS,
		Platform:        hostInfo.Platform,
		Uptime:          hostInfo.Uptime,
		CPUModel:        cpuModel,
		CPUCores:        runtime.NumCPU(),
		TotalMemory:     totalMemory,
		RealDataEnabled: true,
	}, nil
}

// getServerIP gets the server's IP address
func (c *RealDataCollector) getServerIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// Mock data functions for development/testing
func (c *RealDataCollector) getMockSystemMetrics() SystemMetrics {
	// Generate realistic fluctuating values
	baseTime := time.Now().Unix()
	cpuVariation := 10.0 + 15.0*rand.Float64() + 5.0*float64(baseTime%60)/60.0
	memVariation := 35.0 + 25.0*rand.Float64() + 10.0*float64(baseTime%120)/120.0

	return SystemMetrics{
		ServerID:   "mock-server-001",
		ServerName: "Mock Development Server",
		ServerIP:   "127.0.0.1",
		Timestamp:  time.Now(),
		CPU:        cpuVariation,
		Memory:     memVariation,
		Disk:       33.8 + 2.0*rand.Float64(),
		Network: NetworkStats{
			BytesSent:   uint64(123456789 + baseTime*1000),
			BytesRecv:   uint64(987654321 + baseTime*1500),
			PacketsSent: uint64(12345 + baseTime/10),
			PacketsRecv: uint64(54321 + baseTime/8),
		},
		Status: func() string {
			if cpuVariation > 70 || memVariation > 80 {
				return "critical"
			} else if cpuVariation > 50 || memVariation > 60 {
				return "warning"
			}
			return "healthy"
		}(),
	}
}

func (c *RealDataCollector) getMockNetworkConnections() []NetworkConnection {
	connections := []NetworkConnection{
		{
			Protocol:    "tcp",
			LocalAddr:   "127.0.0.1:8080",
			RemoteAddr:  "127.0.0.1:54321",
			State:       "ESTABLISHED",
			Port:        8080,
			ProcessName: "network-monitor",
			PID:         1234,
			Timestamp:   time.Now(),
		},
		{
			Protocol:    "tcp",
			LocalAddr:   "0.0.0.0:22",
			RemoteAddr:  "0.0.0.0:0",
			State:       "LISTEN",
			Port:        22,
			ProcessName: "sshd",
			PID:         567,
			Timestamp:   time.Now(),
		},
		{
			Protocol:    "tcp",
			LocalAddr:   "0.0.0.0:80",
			RemoteAddr:  "0.0.0.0:0",
			State:       "LISTEN",
			Port:        80,
			ProcessName: "nginx",
			PID:         890,
			Timestamp:   time.Now(),
		},
	}

	// Add some random connections
	for i := 0; i < 3; i++ {
		connections = append(connections, NetworkConnection{
			Protocol:    "tcp",
			LocalAddr:   fmt.Sprintf("192.168.1.%d:%d", 100+rand.Intn(50), 40000+rand.Intn(20000)),
			RemoteAddr:  fmt.Sprintf("203.%d.%d.%d:%d", rand.Intn(255), rand.Intn(255), rand.Intn(255), 80+rand.Intn(8000)),
			State:       "ESTABLISHED",
			Port:        uint32(40000 + rand.Intn(20000)),
			ProcessName: fmt.Sprintf("process-%d", rand.Intn(1000)),
			PID:         int32(1000 + rand.Intn(9000)),
			Timestamp:   time.Now(),
		})
	}

	return connections
}

func (c *RealDataCollector) getMockProcesses() []ProcessInfo {
	processes := []ProcessInfo{
		{
			PID:       1234,
			Name:      "network-monitor",
			CPUUsage:  2.5 + rand.Float64()*3.0,
			Memory:    5.1 + rand.Float32()*2.0,
			Status:    "R",
			Timestamp: time.Now(),
		},
		{
			PID:       567,
			Name:      "sshd",
			CPUUsage:  0.1 + rand.Float64()*0.5,
			Memory:    1.2 + rand.Float32()*0.8,
			Status:    "S",
			Timestamp: time.Now(),
		},
		{
			PID:       890,
			Name:      "nginx",
			CPUUsage:  1.5 + rand.Float64()*2.0,
			Memory:    3.2 + rand.Float32()*1.5,
			Status:    "S",
			Timestamp: time.Now(),
		},
	}

	// Add some random processes
	processNames := []string{"chrome", "firefox", "code", "docker", "mysql", "redis", "node", "python", "java"}
	for i := 0; i < 10; i++ {
		processes = append(processes, ProcessInfo{
			PID:       int32(2000 + rand.Intn(8000)),
			Name:      processNames[rand.Intn(len(processNames))],
			CPUUsage:  rand.Float64() * 10.0,
			Memory:    rand.Float32() * 15.0,
			Status:    []string{"R", "S", "D", "Z"}[rand.Intn(4)],
			Timestamp: time.Now(),
		})
	}

	return processes
}

func (c *RealDataCollector) getMockSystemInfo() SystemInfo {
	return SystemInfo{
		Hostname:        "mock-development-host",
		OS:              "linux",
		Platform:        "ubuntu",
		Uptime:          86400 + uint64(time.Now().Unix()%86400),
		CPUModel:        "Mock CPU @ 3.0GHz (Development Mode)",
		CPUCores:        runtime.NumCPU(),
		TotalMemory:     8 * 1024 * 1024 * 1024, // 8GB
		RealDataEnabled: false,
	}
}
