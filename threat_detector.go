package main

import (
	"math/rand"
	"net"
	"strings"
	"time"
)

type ThreatDetector struct {
	recentThreats []ThreatInfo
	suspiciousIPs map[string]int
	blockedIPs    map[string]time.Time
}

func NewThreatDetector() *ThreatDetector {
	return &ThreatDetector{
		recentThreats: make([]ThreatInfo, 0),
		suspiciousIPs: make(map[string]int),
		blockedIPs:    make(map[string]time.Time),
	}
}

func (td *ThreatDetector) DetectThreats() []ThreatInfo {
	var newThreats []ThreatInfo
	
	// 模拟威胁检测（在实际环境中应该分析真实的网络流量）
	if rand.Float32() < 0.15 { // 15% 概率检测到威胁
		threat := td.generateSimulatedThreat()
		newThreats = append(newThreats, threat)
		
		// 添加到最近威胁列表
		td.recentThreats = append([]ThreatInfo{threat}, td.recentThreats...)
		if len(td.recentThreats) > 100 {
			td.recentThreats = td.recentThreats[:100]
		}
		
		// 更新可疑IP计数
		td.suspiciousIPs[threat.IP]++
		
		// 如果IP过于可疑，加入黑名单
		if td.suspiciousIPs[threat.IP] > 5 {
			td.blockedIPs[threat.IP] = time.Now()
		}
	}
	
	return newThreats
}

func (td *ThreatDetector) generateSimulatedThreat() ThreatInfo {
	// 生成随机IP地址
	ip := td.generateRandomIP()
	
	// 威胁类型列表
	threatTypes := []string{
		"SQL注入尝试",
		"暴力破解攻击",
		"XSS攻击尝试",
		"端口扫描",
		"DDoS攻击",
		"恶意爬虫",
		"未授权访问",
		"文件包含攻击",
		"命令注入",
		"路径遍历",
	}
	
	// 严重程度列表
	severities := []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"}
	
	// 国家列表
	countries := []string{
		"中国", "美国", "俄罗斯", "德国", "英国", 
		"法国", "日本", "韩国", "印度", "巴西",
		"未知", "本地",
	}
	
	threat := ThreatInfo{
		IP:            ip,
		Country:       countries[rand.Intn(len(countries))],
		ThreatType:    threatTypes[rand.Intn(len(threatTypes))],
		Severity:      severities[rand.Intn(len(severities))],
		Timestamp:     time.Now(),
		Blocked:       rand.Float32() < 0.7, // 70% 概率被阻止
		RequestsCount: rand.Intn(20) + 1,
	}
	
	return threat
}

func (td *ThreatDetector) generateRandomIP() string {
	// 生成一些常见的可疑IP段
	suspiciousRanges := []string{
		"192.168.1.%d",
		"10.0.0.%d",
		"172.16.0.%d",
		"203.%d.%d.%d",
		"61.%d.%d.%d",
		"123.%d.%d.%d",
		"185.%d.%d.%d",
	}
	
	rangeTemplate := suspiciousRanges[rand.Intn(len(suspiciousRanges))]
	
	// 根据模板生成IP
	switch strings.Count(rangeTemplate, "%d") {
	case 1:
		return strings.Replace(rangeTemplate, "%d", 
			string(rune(rand.Intn(254)+1)), 1)
	case 3:
		return strings.Replace(
			strings.Replace(
				strings.Replace(rangeTemplate, "%d", 
					string(rune(rand.Intn(254)+1)), 1), "%d", 
				string(rune(rand.Intn(254)+1)), 1), "%d", 
			string(rune(rand.Intn(254)+1)), 1)
	default:
		// 生成完全随机的IP
		return net.IPv4(
			byte(rand.Intn(254)+1),
			byte(rand.Intn(254)+1),
			byte(rand.Intn(254)+1),
			byte(rand.Intn(254)+1),
		).String()
	}
}

func (td *ThreatDetector) GetRecentThreats() []ThreatInfo {
	return td.recentThreats
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
