package main

import (
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"
)

// NewThreatDetector creates a new threat detector
func NewThreatDetector() *ThreatDetector {
	return &ThreatDetector{
		enabled:       true,
		threats:       make([]Threat, 0),
		suspiciousIPs: make(map[string]int),
		blockedIPs:    make(map[string]bool),
	}
}

// Start starts the threat detector
func (td *ThreatDetector) Start() {
	log.Println("🛡️ 启动威胁检测器...")
	td.enabled = true
	log.Println("✅ 威胁检测器启动成功")
}

// Stop stops the threat detector
func (td *ThreatDetector) Stop() {
	td.enabled = false
	log.Println("🛑 威胁检测器已停止")
}

// DetectThreats detects threats from system data
func (td *ThreatDetector) DetectThreats(data SystemData) []Threat {
	if !td.enabled {
		return []Threat{}
	}

	var threats []Threat

	// 检测CPU异常
	if data.CPU.Usage > 90 {
		threat := Threat{
			ID:          fmt.Sprintf("cpu-%d", time.Now().Unix()),
			Type:        "performance",
			Level:       "high",
			Source:      "system",
			Target:      "cpu",
			Description: fmt.Sprintf("CPU使用率异常高: %.1f%%", data.CPU.Usage),
			Timestamp:   time.Now(),
			Count:       1,
			Status:      "active",
		}
		threats = append(threats, threat)
	}

	// 检测内存异常
	if data.Memory.UsedPercent > 90 {
		threat := Threat{
			ID:          fmt.Sprintf("memory-%d", time.Now().Unix()),
			Type:        "performance",
			Level:       "high",
			Source:      "system",
			Target:      "memory",
			Description: fmt.Sprintf("内存使用率异常高: %.1f%%", data.Memory.UsedPercent),
			Timestamp:   time.Now(),
			Count:       1,
			Status:      "active",
		}
		threats = append(threats, threat)
	}

	// 检测磁盘异常
	if data.Disk.UsagePercent > 95 {
		threat := Threat{
			ID:          fmt.Sprintf("disk-%d", time.Now().Unix()),
			Type:        "performance",
			Level:       "critical",
			Source:      "system",
			Target:      "disk",
			Description: fmt.Sprintf("磁盘使用率异常高: %.1f%%", data.Disk.UsagePercent),
			Timestamp:   time.Now(),
			Count:       1,
			Status:      "active",
		}
		threats = append(threats, threat)
	}

	// 检测可疑连接
	for _, conn := range data.Connections {
		if td.isSuspiciousConnection(conn) {
			threat := Threat{
				ID:          fmt.Sprintf("conn-%s-%d", conn.RemoteAddr, time.Now().Unix()),
				Type:        "security",
				Level:       "medium",
				Source:      conn.RemoteAddr,
				Target:      conn.LocalAddr,
				Description: fmt.Sprintf("检测到可疑连接: %s -> %s", conn.RemoteAddr, conn.LocalAddr),
				Timestamp:   time.Now(),
				Count:       1,
				Status:      "active",
			}
			threats = append(threats, threat)
		}
	}

	// 模拟一些随机威胁用于演示
	if rand.Intn(100) < 10 { // 10% 概率
		mockThreat := td.generateMockThreat()
		threats = append(threats, mockThreat)
	}

	// 更新威胁列表
	td.threats = append(td.threats, threats...)

	// 保持威胁列表大小
	if len(td.threats) > 100 {
		td.threats = td.threats[len(td.threats)-100:]
	}

	return threats
}

// GetThreats returns current threats
func (td *ThreatDetector) GetThreats() []Threat {
	return td.threats
}

// isSuspiciousConnection checks if a connection is suspicious
func (td *ThreatDetector) isSuspiciousConnection(conn ConnectionInfo) bool {
	// 检查是否为已知的可疑IP
	if td.blockedIPs[conn.RemoteAddr] {
		return true
	}

	// 检查端口扫描行为
	if strings.Contains(conn.State, "SYN") {
		td.suspiciousIPs[conn.RemoteAddr]++
		if td.suspiciousIPs[conn.RemoteAddr] > 10 {
			td.blockedIPs[conn.RemoteAddr] = true
			return true
		}
	}

	// 检查异常端口
	suspiciousPorts := []string{":1337", ":4444", ":6666", ":31337"}
	for _, port := range suspiciousPorts {
		if strings.Contains(conn.LocalAddr, port) || strings.Contains(conn.RemoteAddr, port) {
			return true
		}
	}

	return false
}

// generateMockThreat generates a mock threat for demonstration
func (td *ThreatDetector) generateMockThreat() Threat {
	threatTypes := []string{"sql_injection", "xss", "brute_force", "port_scan", "malware"}
	levels := []string{"low", "medium", "high", "critical"}
	sources := []string{"192.168.1.100", "10.0.0.50", "172.16.0.25", "203.0.113.10"}

	threatType := threatTypes[rand.Intn(len(threatTypes))]
	level := levels[rand.Intn(len(levels))]
	source := sources[rand.Intn(len(sources))]

	descriptions := map[string]string{
		"sql_injection": "检测到SQL注入攻击尝试",
		"xss":           "检测到跨站脚本攻击",
		"brute_force":   "检测到暴力破解攻击",
		"port_scan":     "检测到端口扫描行为",
		"malware":       "检测到恶意软件活动",
	}

	return Threat{
		ID:          fmt.Sprintf("%s-%s-%d", threatType, source, time.Now().Unix()),
		Type:        threatType,
		Level:       level,
		Source:      source,
		Target:      "server",
		Description: descriptions[threatType],
		Timestamp:   time.Now(),
		Count:       rand.Intn(10) + 1,
		Status:      "active",
	}
}

// BlockIP blocks an IP address
func (td *ThreatDetector) BlockIP(ip string) {
	td.blockedIPs[ip] = true
	log.Printf("🚫 已封禁IP: %s", ip)
}

// UnblockIP unblocks an IP address
func (td *ThreatDetector) UnblockIP(ip string) {
	delete(td.blockedIPs, ip)
	log.Printf("✅ 已解封IP: %s", ip)
}

// IsBlocked checks if an IP is blocked
func (td *ThreatDetector) IsBlocked(ip string) bool {
	return td.blockedIPs[ip]
}

// GetBlockedIPs returns all blocked IPs
func (td *ThreatDetector) GetBlockedIPs() []string {
	var ips []string
	for ip := range td.blockedIPs {
		ips = append(ips, ip)
	}
	return ips
}

// ClearThreats clears all threats
func (td *ThreatDetector) ClearThreats() {
	td.threats = make([]Threat, 0)
	log.Println("🧹 已清空威胁列表")
}
