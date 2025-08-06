package main

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/process"
	psnet "github.com/shirou/gopsutil/v3/net"
)

// RealDataCollector collects real system data
type RealDataCollector struct {
	hostname string
}

// NewRealDataCollector creates a new real data collector
func NewRealDataCollector() *RealDataCollector {
	hostname, _ := os.Hostname()
	return &RealDataCollector{
		hostname: hostname,
	}
}

// GetSystemMetrics returns current system metrics
func (r *RealDataCollector) GetSystemMetrics() (*SystemMetrics, error) {
	// Get CPU usage
	cpuPercent, err := cpu.Percent(time.Second, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get CPU usage: %v", err)
	}
	
	var cpuUsage float64
	if len(cpuPercent) > 0 {
		cpuUsage = cpuPercent[0]
	}

	// Get memory usage
	memInfo, err := mem.VirtualMemory()
	if err != nil {
		return nil, fmt.Errorf("failed to get memory info: %v", err)
	}

	// Get disk usage
	diskInfo, err := disk.Usage("/")
	if err != nil {
		return nil, fmt.Errorf("failed to get disk info: %v", err)
	}

	// Get network stats
	netStats, err := psnet.IOCounters(false)
	if err != nil {
		return nil, fmt.Errorf("failed to get network stats: %v", err)
	}

	var networkStats NetworkStats
	if len(netStats) > 0 {
		networkStats = NetworkStats{
			BytesSent:   netStats[0].BytesSent,
			BytesRecv:   netStats[0].BytesRecv,
			PacketsSent: netStats[0].PacketsSent,
			PacketsRecv: netStats[0].PacketsRecv,
		}
	}

	// Determine status based on resource usage
	status := "healthy"
	if cpuUsage > 80 || memInfo.UsedPercent > 90 || diskInfo.UsedPercent > 95 {
		status = "critical"
	} else if cpuUsage > 60 || memInfo.UsedPercent > 75 || diskInfo.UsedPercent > 85 {
		status = "warning"
	}

	// Get local IP
	localIP := r.getLocalIP()

	return &SystemMetrics{
		ServerID:   r.hostname,
		ServerName: r.hostname,
		ServerIP:   localIP,
		Timestamp:  time.Now(),
		CPU:        cpuUsage,
		Memory:     memInfo.UsedPercent,
		Disk:       diskInfo.UsedPercent,
		Network:    networkStats,
		Status:     status,
	}, nil
}

// GetNetworkConnections returns current network connections
func (r *RealDataCollector) GetNetworkConnections() ([]NetworkConnection, error) {
	connections, err := psnet.Connections("all")
	if err != nil {
		return nil, fmt.Errorf("failed to get network connections: %v", err)
	}

	var result []NetworkConnection
	for _, conn := range connections {
		if len(result) >= 50 { // Limit to 50 connections
			break
		}

		processName := "unknown"
		if conn.Pid != 0 {
			if proc, err := process.NewProcess(conn.Pid); err == nil {
				if name, err := proc.Name(); err == nil {
					processName = name
				}
			}
		}

		localAddr := fmt.Sprintf("%s:%d", conn.Laddr.IP, conn.Laddr.Port)
		remoteAddr := ""
		if conn.Raddr.IP != "" {
			remoteAddr = fmt.Sprintf("%s:%d", conn.Raddr.IP, conn.Raddr.Port)
		}

		result = append(result, NetworkConnection{
			Protocol:    strings.ToUpper(conn.Type),
			LocalAddr:   localAddr,
			RemoteAddr:  remoteAddr,
			State:       conn.Status,
			Port:        int(conn.Laddr.Port),
			ProcessName: processName,
			Timestamp:   time.Now(),
		})
	}

	return result, nil
}

// GetProcesses returns current running processes
func (r *RealDataCollector) GetProcesses() ([]ProcessInfo, error) {
	processes, err := process.Processes()
	if err != nil {
		return nil, fmt.Errorf("failed to get processes: %v", err)
	}

	var result []ProcessInfo
	for _, proc := range processes {
		if len(result) >= 30 { // Limit to 30 processes
			break
		}

		name, err := proc.Name()
		if err != nil {
			continue
		}

		cpuPercent, err := proc.CPUPercent()
		if err != nil {
			cpuPercent = 0
		}

		memPercent, err := proc.MemoryPercent()
		if err != nil {
			memPercent = 0
		}

		status, err := proc.Status()
		if err != nil {
			status = "unknown"
		}

		result = append(result, ProcessInfo{
			PID:       proc.Pid,
			Name:      name,
			CPUUsage:  cpuPercent,
			Memory:    float64(memPercent),
			Status:    status,
			Timestamp: time.Now(),
		})
	}

	return result, nil
}

// GetSystemInfo returns system information
func (r *RealDataCollector) GetSystemInfo() (*SystemInfo, error) {
	hostInfo, err := host.Info()
	if err != nil {
		return nil, fmt.Errorf("failed to get host info: %v", err)
	}

	memInfo, err := mem.VirtualMemory()
	if err != nil {
		return nil, fmt.Errorf("failed to get memory info: %v", err)
	}

	cpuInfo, err := cpu.Info()
	if err != nil {
		return nil, fmt.Errorf("failed to get CPU info: %v", err)
	}

	var cpuModel string
	var cpuCores int
	if len(cpuInfo) > 0 {
		cpuModel = cpuInfo[0].ModelName
		cpuCores = int(cpuInfo[0].Cores)
	}

	if cpuCores == 0 {
		cpuCores = runtime.NumCPU()
	}

	return &SystemInfo{
		Hostname:        hostInfo.Hostname,
		OS:              hostInfo.OS,
		Platform:        hostInfo.Platform,
		Uptime:          hostInfo.Uptime,
		CPUModel:        cpuModel,
		CPUCores:        cpuCores,
		TotalMemory:     memInfo.Total,
		RealDataEnabled: true,
	}, nil
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
