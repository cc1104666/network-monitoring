package main

import (
	"log"
	"math/rand"
	"sync"
	"time"
)

func NewThreatDetector() *ThreatDetector {
	return &ThreatDetector{
		alerts:       make([]ThreatAlert, 0),
		requestCount: make(map[string]map[string]int),
		timeWindows:  make(map[string]time.Time),
		alertID:      1,
	}
}

func (td *ThreatDetector) Start() {
	go td.generateThreats()
	go td.cleanupOldAlerts()
	log.Println("威胁检测器已启动")
}

func (td *ThreatDetector) generateThreats() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	threatTypes := []string{"DDoS", "BruteForce", "RateLimit", "SQLInjection", "XSS"}
	severities := []string{"critical", "high", "medium", "low"}
	endpoints := []string{"/api/login", "/api/users", "/api/data", "/api/upload", "/api/search"}
	sourceIPs := []string{"203.45.67.89", "192.168.1.100", "10.0.0.50", "172.16.0.25", "45.123.45.67"}

	for range ticker.C {
		// 30%概率生成新威胁
		if rand.Float32() < 0.3 {
			td.mu.Lock()
			
			alert := ThreatAlert{
				ID:          td.alertID,
				Type:        threatTypes[rand.Intn(len(threatTypes))],
				Severity:    severities[rand.Intn(len(severities))],
				Endpoint:    endpoints[rand.Intn(len(endpoints))],
				Requests:    rand.Intn(10000) + 1000,
				TimeWindow:  "5分钟",
				SourceIP:    sourceIPs[rand.Intn(len(sourceIPs))],
				Timestamp:   time.Now(),
				Description: td.generateThreatDescription(),
				Active:      true,
			}
			
			td.alerts = append(td.alerts, alert)
			td.alertID++
			
			td.mu.Unlock()
			
			log.Printf("🚨 检测到威胁: %s - %s (%s)", alert.Type, alert.Severity, alert.SourceIP)
		}
	}
}

func (td *ThreatDetector) generateThreatDescription() string {
	descriptions := []string{
		"检测到异常高频请求，可能存在DDoS攻击",
		"发现多次登录失败尝试，疑似暴力破解",
		"请求频率超过正常阈值，触发限流保护",
		"检测到可疑的SQL注入尝试",
		"发现潜在的跨站脚本攻击",
		"异常的API调用模式，可能存在恶意行为",
		"检测到来自可疑IP的大量请求",
		"发现异常的用户代理字符串",
	}
	return descriptions[rand.Intn(len(descriptions))]
}

func (td *ThreatDetector) cleanupOldAlerts() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		td.mu.Lock()
		
		// 移除超过1小时的告警
		cutoff := time.Now().Add(-1 * time.Hour)
		var activeAlerts []ThreatAlert
		
		for _, alert := range td.alerts {
			if alert.Timestamp.After(cutoff) {
				activeAlerts = append(activeAlerts, alert)
			}
		}
		
		td.alerts = activeAlerts
		td.mu.Unlock()
	}
}

func (td *ThreatDetector) GetAllThreats() []ThreatAlert {
	td.mu.RLock()
	defer td.mu.RUnlock()
	
	threats := make([]ThreatAlert, len(td.alerts))
	copy(threats, td.alerts)
	return threats
}

func (td *ThreatDetector) GetActiveThreats() []ThreatAlert {
	td.mu.RLock()
	defer td.mu.RUnlock()
	
	var activeThreats []ThreatAlert
	for _, alert := range td.alerts {
		if alert.Active {
			activeThreats = append(activeThreats, alert)
		}
	}
	return activeThreats
}

func (td *ThreatDetector) AddThreat(alert ThreatAlert) {
	td.mu.Lock()
	defer td.mu.Unlock()
	
	alert.ID = td.alertID
	alert.Timestamp = time.Now()
	alert.Active = true
	
	td.alerts = append(td.alerts, alert)
	td.alertID++
}

func (td *ThreatDetector) DeactivateThreat(id int) {
	td.mu.Lock()
	defer td.mu.Unlock()
	
	for i := range td.alerts {
		if td.alerts[i].ID == id {
			td.alerts[i].Active = false
			break
		}
	}
}
