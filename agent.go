package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

func runAgent() {
	log.Println("🤖 启动天眼代理模式...")
	
	// 从环境变量获取配置
	serverURL := os.Getenv("MONITOR_SERVER_URL")
	if serverURL == "" {
		serverURL = "http://localhost:8080"
	}
	
	serverID := os.Getenv("SERVER_ID")
	if serverID == "" {
		serverID = "agent-001"
	}
	
	serverName := os.Getenv("SERVER_NAME")
	if serverName == "" {
		serverName = "Agent Server"
	}
	
	serverIP := os.Getenv("SERVER_IP")
	if serverIP == "" {
		serverIP = "127.0.0.1"
	}
	
	log.Printf("📡 连接到监控服务器: %s", serverURL)
	log.Printf("🏷️ 服务器标识: %s (%s)", serverName, serverID)
	
	// 定期收集和发送指标
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			metrics := collectSystemMetrics(serverID, serverName, serverIP)
			if err := sendMetrics(serverURL, metrics); err != nil {
				log.Printf("❌ 发送指标失败: %v", err)
			} else {
				log.Printf("✅ 指标发送成功 - CPU: %.1f%%, 内存: %.1f%%", 
					metrics.CPU, metrics.Memory)
			}
		}
	}
}

func collectSystemMetrics(serverID, serverName, serverIP string) SystemMetrics {
	metrics := SystemMetrics{
		ServerID:   serverID,
		ServerName: serverName,
		ServerIP:   serverIP,
		Timestamp:  time.Now(),
	}
	
	// 收集CPU使用率
	if cpuPercent, err := cpu.Percent(time.Second, false); err == nil && len(cpuPercent) > 0 {
		metrics.CPU = cpuPercent[0]
	}
	
	// 收集内存使用率
	if memInfo, err := mem.VirtualMemory(); err == nil {
		metrics.Memory = memInfo.UsedPercent
	}
	
	// 收集磁盘使用率
	if diskInfo, err := disk.Usage("/"); err == nil {
		metrics.Disk = diskInfo.UsedPercent
	}
	
	// 收集网络统计
	if netStats, err := net.IOCounters(false); err == nil && len(netStats) > 0 {
		metrics.Network.BytesSent = netStats[0].BytesSent
		metrics.Network.BytesRecv = netStats[0].BytesRecv
		metrics.Network.PacketsSent = netStats[0].PacketsSent
		metrics.Network.PacketsRecv = netStats[0].PacketsRecv
	}
	
	// 确定服务器状态
	if metrics.CPU > 90 || metrics.Memory > 90 {
		metrics.Status = "critical"
	} else if metrics.CPU > 70 || metrics.Memory > 80 {
		metrics.Status = "warning"
	} else {
		metrics.Status = "healthy"
	}
	
	return metrics
}

func sendMetrics(serverURL string, metrics SystemMetrics) error {
	jsonData, err := json.Marshal(metrics)
	if err != nil {
		return fmt.Errorf("序列化指标失败: %v", err)
	}
	
	url := fmt.Sprintf("%s/api/agent/metrics", serverURL)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("发送HTTP请求失败: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("服务器返回错误状态: %d", resp.StatusCode)
	}
	
	return nil
}
