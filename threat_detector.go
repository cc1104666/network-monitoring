package main

import (
	"fmt"
	"log"
	"math/rand"
	"time"
)

// ThreatDetector 威胁检测器
type ThreatDetector struct {
	threats []Threat
	rules   []ThreatRule
	enabled bool
}

// ThreatRule 威胁检测规则
type ThreatRule struct {
	ID          string
	Name        string
	Pattern     string
	ThreatType  string
	Severity    string
	Description string
	Enabled     bool
}

// NewThreatDetector 创建新的威胁检测器
func NewThreatDetector() *ThreatDetector {
	detector := &ThreatDetector{
		threats: make([]Threat, 0),
		enabled: true,
	}
	
	// 初始化默认规则
	detector.initializeRules()
	
	return detector
}

// initializeRules 初始化威胁检测规则
func (td *ThreatDetector) initializeRules() {
	td.rules = []ThreatRule{
		{
			ID:          "rule-001",
			Name:        "SQL注入检测",
			Pattern:     "(?i)(union|select|insert|update|delete|drop|create|alter)",
			ThreatType:  "sql_injection",
			Severity:    "high",
			Description: "检测SQL注入攻击模式",
			Enabled:     true,
		},
		{
			ID:          "rule-002",
			Name:        "XSS攻击检测",
			Pattern:     "(?i)(<script|javascript:|onload=|onerror=)",
			ThreatType:  "xss",
			Severity:    "medium",
			Description: "检测跨站脚本攻击",
			Enabled:     true,
		},
		{
			ID:          "rule-003",
			Name:        "路径遍历检测",
			Pattern:     "(\\.\\.[\\/\\\\]|\\.\\.%2f|\\.\\.%5c)",
			ThreatType:  "path_traversal",
			Severity:    "high",
			Description: "检测目录遍历攻击",
			Enabled:     true,
		},
		{
			ID:          "rule-004",
			Name:        "暴力破解检测",
			Pattern:     "multiple_failed_attempts",
			ThreatType:  "brute_force",
			Severity:    "medium",
			Description: "检测暴力破解攻击",
			Enabled:     true,
		},
		{
			ID:          "rule-005",
			Name:        "命令注入检测",
			Pattern:     "(?i)(;|\\||&|`|\\$\\(|\\${)",
			ThreatType:  "command_injection",
			Severity:    "critical",
			Description: "检测命令注入攻击",
			Enabled:     true,
		},
	}
}

// Start 启动威胁检测器
func (td *ThreatDetector) Start() {
	log.Println("🛡️ 启动威胁检测器...")
	
	// 启动后台检测任务
	go td.backgroundDetection()
	
	log.Println("✅ 威胁检测器启动成功")
}

// backgroundDetection 后台威胁检测
func (td *ThreatDetector) backgroundDetection() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			td.performDetection()
		}
	}
}

// performDetection 执行威胁检测
func (td *ThreatDetector) performDetection() {
	if !td.enabled {
		return
	}
	
	// 模拟威胁检测
	if rand.Float32() < 0.3 { // 30% 概率检测到威胁
		threat := td.generateMockThreat()
		td.addThreat(threat)
		log.Printf("🚨 检测到威胁: %s from %s", threat.Type, threat.Source)
	}
}

// generateMockThreat 生成模拟威胁数据
func (td *ThreatDetector) generateMockThreat() Threat {
	threatTypes := []string{"sql_injection", "xss", "path_traversal", "brute_force", "command_injection", "scanning_tool"}
	severities := []string{"low", "medium", "high", "critical"}
	sources := []string{"192.168.1.100", "10.0.0.50", "172.16.0.25", "203.0.113.10", "198.51.100.20"}
	
	threatType := threatTypes[rand.Intn(len(threatTypes))]
	severity := severities[rand.Intn(len(severities))]
	source := sources[rand.Intn(len(sources))]
	
	descriptions := map[string]string{
		"sql_injection":     "检测到SQL注入攻击尝试",
		"xss":              "检测到跨站脚本攻击",
		"path_traversal":   "检测到目录遍历攻击",
		"brute_force":      "检测到暴力破解攻击",
		"command_injection": "检测到命令注入攻击",
		"scanning_tool":    "检测到端口扫描活动",
	}
	
	return Threat{
		ID:          fmt.Sprintf("threat-%d", time.Now().Unix()),
		Type:        threatType,
		Level:       severity,
		Source:      source,
		Target:      "localhost:8080",
		Description: descriptions[threatType],
		Timestamp:   time.Now(),
		Count:       rand.Intn(10) + 1,
		Status:      "active",
	}
}

// addThreat 添加威胁到列表
func (td *ThreatDetector) addThreat(threat Threat) {
	td.threats = append(td.threats, threat)
	
	// 保持威胁列表大小限制
	if len(td.threats) > 100 {
		td.threats = td.threats[1:]
	}
}

// GetThreats 获取威胁列表
func (td *ThreatDetector) GetThreats() []Threat {
	return td.threats
}

// GetRecentThreats 获取最近的威胁
func (td *ThreatDetector) GetRecentThreats() []Threat {
	if len(td.threats) == 0 {
		return []Threat{}
	}
	
	// 返回最近20个威胁
	start := 0
	if len(td.threats) > 20 {
		start = len(td.threats) - 20
	}
	
	return td.threats[start:]
}

// DetectThreats 检测威胁（兼容旧接口）
func (td *ThreatDetector) DetectThreats() []ThreatInfo {
	threats := td.GetRecentThreats()
	var threatInfos []ThreatInfo
	
	for _, threat := range threats {
		threatInfo := ThreatInfo{
			IP:            threat.Source,
			Country:       "Unknown",
			ThreatType:    threat.Type,
			Severity:      threat.Level,
			Timestamp:     threat.Timestamp,
			Blocked:       threat.Status == "blocked",
			RequestsCount: threat.Count,
		}
		threatInfos = append(threatInfos, threatInfo)
	}
	
	return threatInfos
}

// GetThreatStats 获取威胁统计
func (td *ThreatDetector) GetThreatStats() map[string]interface{} {
	stats := make(map[string]interface{})
	
	// 统计威胁类型
	typeCount := make(map[string]int)
	severityCount := make(map[string]int)
	
	for _, threat := range td.threats {
		typeCount[threat.Type]++
		severityCount[threat.Level]++
	}
	
	stats["total_threats"] = len(td.threats)
	stats["threat_types"] = typeCount
	stats["severity_levels"] = severityCount
	stats["last_detection"] = time.Now().Format("2006-01-02 15:04:05")
	
	return stats
}

// BlockThreat 阻止威胁
func (td *ThreatDetector) BlockThreat(threatID string) error {
	for i, threat := range td.threats {
		if threat.ID == threatID {
			td.threats[i].Status = "blocked"
			log.Printf("🚫 威胁已阻止: %s", threatID)
			return nil
		}
	}
	
	return fmt.Errorf("威胁未找到: %s", threatID)
}

// IgnoreThreat 忽略威胁
func (td *ThreatDetector) IgnoreThreat(threatID string) error {
	for i, threat := range td.threats {
		if threat.ID == threatID {
			td.threats[i].Status = "ignored"
			log.Printf("⚠️ 威胁已忽略: %s", threatID)
			return nil
		}
	}
	
	return fmt.Errorf("威胁未找到: %s", threatID)
}

// AddRule 添加威胁检测规则
func (td *ThreatDetector) AddRule(rule ThreatRule) {
	td.rules = append(td.rules, rule)
	log.Printf("📋 添加威胁检测规则: %s", rule.Name)
}

// RemoveRule 移除威胁检测规则
func (td *ThreatDetector) RemoveRule(ruleID string) error {
	for i, rule := range td.rules {
		if rule.ID == ruleID {
			td.rules = append(td.rules[:i], td.rules[i+1:]...)
			log.Printf("🗑️ 移除威胁检测规则: %s", ruleID)
			return nil
		}
	}
	
	return fmt.Errorf("规则未找到: %s", ruleID)
}

// GetRules 获取威胁检测规则
func (td *ThreatDetector) GetRules() []ThreatRule {
	return td.rules
}

// Enable 启用威胁检测
func (td *ThreatDetector) Enable() {
	td.enabled = true
	log.Println("✅ 威胁检测已启用")
}

// Disable 禁用威胁检测
func (td *ThreatDetector) Disable() {
	td.enabled = false
	log.Println("❌ 威胁检测已禁用")
}

// IsEnabled 检查威胁检测是否启用
func (td *ThreatDetector) IsEnabled() bool {
	return td.enabled
}

// ClearThreats 清空威胁列表
func (td *ThreatDetector) ClearThreats() {
	td.threats = make([]Threat, 0)
	log.Println("🧹 威胁列表已清空")
}
