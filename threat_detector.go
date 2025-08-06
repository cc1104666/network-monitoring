package main

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

type ThreatInfo struct {
	IP            string
	Country       string
	ThreatType    string
	Severity      string
	Timestamp     time.Time
	Blocked       bool
	RequestsCount int
}

type ThreatDetector struct {
	recentThreats []ThreatInfo
	suspiciousIPs map[string]int
	blockedIPs    map[string]time.Time
	threats       []ThreatInfo
}

func NewThreatDetector() *ThreatDetector {
	return &ThreatDetector{
		recentThreats: make([]ThreatInfo, 0),
		suspiciousIPs: make(map[string]int),
		blockedIPs:    make(map[string]time.Time),
		threats:       make([]ThreatInfo, 0),
	}
}

// DetectThreats 检测威胁
func (td *ThreatDetector) DetectThreats() []ThreatInfo {
	newThreats := []ThreatInfo{}

	// 随机生成威胁（模拟真实检测）
	if rand.Intn(100) < 10 { // 10% 概率生成威胁
		threat := ThreatInfo{
			IP:            generateRandomIP(),
			Country:       getRandomCountry(),
			ThreatType:    getRandomThreatType(),
			Severity:      getRandomSeverity(),
			Timestamp:     time.Now(),
			Blocked:       rand.Intn(2) == 1,
			RequestsCount: rand.Intn(100) + 1,
		}

		td.threats = append(td.threats, threat)
		newThreats = append(newThreats, threat)

		// 限制威胁列表长度
		if len(td.threats) > 100 {
			td.threats = td.threats[1:]
		}
	}

	return newThreats
}

func (td *ThreatDetector) GetRecentThreats() []ThreatInfo {
	// 返回最近50个威胁
	if len(td.threats) <= 50 {
		return td.threats
	}
	return td.threats[len(td.threats)-50:]
}

func (td *ThreatDetector) IsIPBlocked(ip string) bool {
	_, blocked := td.blockedIPs[ip]
	return blocked
}

func (td *ThreatDetector) GetSuspiciousIPs() map[string]int {
	return td.suspiciousIPs
}

func (td *ThreatDetector) GetBlockedIPs() map[string]time.Time {
	return td.blockedIPs
}

// 分析网络流量模式
func (td *ThreatDetector) AnalyzeTrafficPattern(ip string, requestCount int, timeWindow time.Duration) string {
	// 简单的流量分析逻辑
	requestsPerMinute := float64(requestCount) / timeWindow.Minutes()

	if requestsPerMinute > 100 {
		return "CRITICAL"
	} else if requestsPerMinute > 50 {
		return "HIGH"
	} else if requestsPerMinute > 20 {
		return "MEDIUM"
	}

	return "LOW"
}

// 检查IP是否在已知恶意IP列表中
func (td *ThreatDetector) CheckMaliciousIP(ip string) bool {
	// 这里应该查询真实的威胁情报数据库
	// 目前使用模拟数据
	maliciousIPs := []string{
		"192.168.1.100",
		"10.0.0.50",
		"172.16.0.200",
	}

	for _, maliciousIP := range maliciousIPs {
		if ip == maliciousIP {
			return true
		}
	}

	return false
}

// 检测异常用户代理
func (td *ThreatDetector) DetectAnomalousUserAgent(userAgent string) bool {
	suspiciousPatterns := []string{
		"sqlmap",
		"nikto",
		"nmap",
		"masscan",
		"python-requests",
		"curl/",
		"wget/",
	}

	userAgentLower := strings.ToLower(userAgent)

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(userAgentLower, pattern) {
			return true
		}
	}

	return false
}

// 检测SQL注入尝试
func (td *ThreatDetector) DetectSQLInjection(request string) bool {
	sqlPatterns := []string{
		"union select",
		"' or '1'='1",
		"' or 1=1",
		"drop table",
		"insert into",
		"delete from",
		"update set",
		"exec(",
		"execute(",
		"sp_",
		"xp_",
	}

	requestLower := strings.ToLower(request)

	for _, pattern := range sqlPatterns {
		if strings.Contains(requestLower, pattern) {
			return true
		}
	}

	return false
}

// 检测XSS尝试
func (td *ThreatDetector) DetectXSS(request string) bool {
	xssPatterns := []string{
		"<script",
		"javascript:",
		"onload=",
		"onerror=",
		"onclick=",
		"onmouseover=",
		"alert(",
		"document.cookie",
		"document.write",
	}

	requestLower := strings.ToLower(request)

	for _, pattern := range xssPatterns {
		if strings.Contains(requestLower, pattern) {
			return true
		}
	}

	return false
}

// 辅助函数

func generateRandomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		rand.Intn(255)+1,
		rand.Intn(255),
		rand.Intn(255),
		rand.Intn(255))
}

func getRandomCountry() string {
	countries := []string{"中国", "美国", "俄罗斯", "德国", "英国", "法国", "日本", "韩国", "印度", "巴西"}
	return countries[rand.Intn(len(countries))]
}

func getRandomThreatType() string {
	types := []string{"SQL注入", "XSS攻击", "暴力破解", "DDoS攻击", "端口扫描", "恶意爬虫", "木马植入", "钓鱼攻击"}
	return types[rand.Intn(len(types))]
}

func getRandomSeverity() string {
	severities := []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"}
	weights := []int{40, 30, 20, 10} // 权重：低40%，中30%，高20%，严重10%

	total := 0
	for _, w := range weights {
		total += w
	}

	r := rand.Intn(total)
	current := 0

	for i, w := range weights {
		current += w
		if r < current {
			return severities[i]
		}
	}

	return "LOW"
}
