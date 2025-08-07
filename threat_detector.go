package main

import (
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/shirou/gopsutil/v3/net"
)

// ThreatDetector 威胁检测器
type ThreatDetector struct {
	threats           []Threat
	connectionHistory map[string]int
	lastCheck         time.Time
}

// NewThreatDetector 创建新的威胁检测器
func NewThreatDetector() *ThreatDetector {
	return &ThreatDetector{
		threats:           make([]Threat, 0),
		connectionHistory: make(map[string]int),
		lastCheck:         time.Now(),
	}
}

// Start 启动威胁检测
func (td *ThreatDetector) Start() {
	log.Println("🛡️ 启动威胁检测器...")
	
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				td.detectThreats()
			}
		}
	}()
	
	log.Println("✅ 威胁检测器启动成功")
}

// detectThreats 检测威胁
func (td *ThreatDetector) detectThreats() {
	now := time.Now()
	
	// 检测网络异常
	td.detectNetworkAnomalies()
	
	// 检测可疑连接
	td.detectSuspiciousConnections()
	
	// 生成一些示例威胁（用于演示）
	td.generateSampleThreats()
	
	// 清理过期威胁
	td.cleanupOldThreats()
	
	td.lastCheck = now
}

// detectNetworkAnomalies 检测网络异常
func (td *ThreatDetector) detectNetworkAnomalies() {
	connections, err := net.Connections("inet")
	if err != nil {
		return
	}
	
	// 统计连接数
	connectionCount := len(connections)
	
	// 如果连接数异常高，生成威胁警报
	if connectionCount > 1000 {
		threat := Threat{
			ID:          fmt.Sprintf("net-anomaly-%d", time.Now().Unix()),
			Type:        "network_anomaly",
			Level:       "high",
			Source:      "system",
			Target:      "localhost",
			Description: fmt.Sprintf("检测到异常高的网络连接数: %d", connectionCount),
			Timestamp:   time.Now(),
			Count:       connectionCount,
			Status:      "active",
		}
		td.addThreat(threat)
	}
}

// detectSuspiciousConnections 检测可疑连接
func (td *ThreatDetector) detectSuspiciousConnections() {
	connections, err := net.Connections("inet")
	if err != nil {
		return
	}
	
	suspiciousPorts := map[uint32]string{
		22:   "SSH暴力破解尝试",
		3389: "RDP暴力破解尝试",
		21:   "FTP暴力破解尝试",
		23:   "Telnet连接尝试",
	}
	
	for _, conn := range connections {
		if conn.Status == "ESTABLISHED" {
			if description, exists := suspiciousPorts[conn.Laddr.Port]; exists {
				// 检查是否为外部连接
				if conn.Raddr.IP != "127.0.0.1" && conn.Raddr.IP != "::1" {
					threat := Threat{
						ID:          fmt.Sprintf("suspicious-conn-%s-%d", conn.Raddr.IP, time.Now().Unix()),
						Type:        "suspicious_connection",
						Level:       "medium",
						Source:      conn.Raddr.IP,
						Target:      fmt.Sprintf("%s:%d", conn.Laddr.IP, conn.Laddr.Port),
						Description: description,
						Timestamp:   time.Now(),
						Count:       1,
						Status:      "active",
					}
					td.addThreat(threat)
				}
			}
		}
	}
}

// generateSampleThreats 生成示例威胁（用于演示）
func (td *ThreatDetector) generateSampleThreats() {
	// 随机生成一些威胁用于演示
	if rand.Intn(10) < 3 { // 30%概率生成威胁
		sampleThreats := []Threat{
			{
				ID:          fmt.Sprintf("ddos-%d", time.Now().Unix()),
				Type:        "ddos_attack",
				Level:       "critical",
				Source:      fmt.Sprintf("192.168.1.%d", rand.Intn(255)),
				Target:      "localhost:80",
				Description: "检测到DDoS攻击尝试",
				Timestamp:   time.Now(),
				Count:       rand.Intn(1000) + 100,
				Status:      "active",
			},
			{
				ID:          fmt.Sprintf("brute-force-%d", time.Now().Unix()),
				Type:        "brute_force",
				Level:       "high",
				Source:      fmt.Sprintf("10.0.0.%d", rand.Intn(255)),
				Target:      "localhost:22",
				Description: "SSH暴力破解尝试",
				Timestamp:   time.Now(),
				Count:       rand.Intn(50) + 10,
				Status:      "active",
			},
			{
				ID:          fmt.Sprintf("port-scan-%d", time.Now().Unix()),
				Type:        "port_scan",
				Level:       "medium",
				Source:      fmt.Sprintf("172.16.0.%d", rand.Intn(255)),
				Target:      "localhost",
				Description: "端口扫描活动",
				Timestamp:   time.Now(),
				Count:       rand.Intn(100) + 20,
				Status:      "active",
			},
		}
		
		// 随机选择一个威胁
		threat := sampleThreats[rand.Intn(len(sampleThreats))]
		td.addThreat(threat)
	}
}

// addThreat 添加威胁
func (td *ThreatDetector) addThreat(threat Threat) {
	// 检查是否已存在相同的威胁
	for i, existingThreat := range td.threats {
		if existingThreat.Source == threat.Source && existingThreat.Type == threat.Type {
			// 更新现有威胁
			td.threats[i].Count += threat.Count
			td.threats[i].Timestamp = threat.Timestamp
			return
		}
	}
	
	// 添加新威胁
	td.threats = append(td.threats, threat)
	
	// 限制威胁数量
	if len(td.threats) > 100 {
		td.threats = td.threats[1:]
	}
	
	log.Printf("🚨 检测到威胁: %s - %s", threat.Type, threat.Description)
}

// cleanupOldThreats 清理过期威胁
func (td *ThreatDetector) cleanupOldThreats() {
	cutoff := time.Now().Add(-1 * time.Hour) // 保留1小时内的威胁
	
	var activeThreat []Threat
	for _, threat := range td.threats {
		if threat.Timestamp.After(cutoff) {
			activeThreat = append(activeThreat, threat)
		}
	}
	
	td.threats = activeThreat
}

// GetThreats 获取威胁列表
func (td *ThreatDetector) GetThreats() []Threat {
	return td.threats
}

// GetThreatStats 获取威胁统计
func (td *ThreatDetector) GetThreatStats() map[string]int {
	stats := make(map[string]int)
	
	for _, threat := range td.threats {
		stats[threat.Level]++
	}
	
	return stats
}
