package main

import (
	"fmt"
	"log"
	"time"
)

type ThreatDetector struct {
	mu           sync.RWMutex
	alerts       []ThreatAlert
	requestCount map[string]map[string]int
	timeWindows  map[string]time.Time
	alertID      int
}

type ThreatAlert struct {
	ID          int
	Type        string
	Severity    string
	Endpoint    string
	Requests    int
	TimeWindow  string
	SourceIP    string
	Timestamp   time.Time
	Description string
	Active      bool
}

func NewThreatDetector() *ThreatDetector {
	return &ThreatDetector{
		mu:           sync.RWMutex{},
		alerts:       make([]ThreatAlert, 0),
		requestCount: make(map[string]map[string]int),
		timeWindows:  make(map[string]time.Time),
		alertID:      1,
	}
}

func (td *ThreatDetector) Start() {
	go td.monitorThreats()
	log.Println("威胁检测器已启动")
}

func (td *ThreatDetector) monitorThreats() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		td.detectThreats()
		td.cleanupOldAlerts()
	}
}

func (td *ThreatDetector) detectThreats() {
	td.mu.Lock()
	defer td.mu.Unlock()

	// 模拟威胁检测
	threats := []struct {
		endpoint   string
		requests   int
		ip         string
		threatType string
	}{
		{"/api/search", 45000, "多个IP地址", "DDoS Attack"},
		{"/api/login", 8950, "203.45.67.89", "Brute Force"},
		{"/api/users", 15420, "192.168.1.100", "Rate Limit Exceeded"},
	}

	for _, threat := range threats {
		// 检查是否已存在相同的活跃告警
		exists := false
		for _, alert := range td.alerts {
			if alert.Endpoint == threat.endpoint && alert.Active && alert.Type == threat.threatType {
				exists = true
				break
			}
		}

		if !exists && td.shouldTriggerAlert(threat.endpoint, threat.requests) {
			alert := ThreatAlert{
				ID:          td.alertID,
				Type:        threat.threatType,
				Severity:    td.calculateSeverity(threat.requests),
				Endpoint:    threat.endpoint,
				Requests:    threat.requests,
				TimeWindow:  "5分钟",
				SourceIP:    threat.ip,
				Timestamp:   time.Now(),
				Description: fmt.Sprintf("检测到%s攻击，目标: %s", threat.threatType, threat.endpoint),
				Active:      true,
			}

			td.alerts = append(td.alerts, alert)
			td.alertID++

			log.Printf("新威胁告警: %s - %s (%s)", alert.Type, alert.Endpoint, alert.Severity)
		}
	}
}

func (td *ThreatDetector) shouldTriggerAlert(endpoint string, requests int) bool {
	// 简单的阈值检测
	thresholds := map[string]int{
		"/api/search": 40000,
		"/api/login":  8000,
		"/api/users":  15000,
		"/api/data":   20000,
		"/api/upload": 5000,
	}

	if threshold, exists := thresholds[endpoint]; exists {
		return requests > threshold
	}

	return requests > 10000 // 默认阈值
}

func (td *ThreatDetector) calculateSeverity(requests int) string {
	if requests > 50000 {
		return "critical"
	} else if requests > 20000 {
		return "high"
	} else if requests > 10000 {
		return "medium"
	}
	return "low"
}

func (td *ThreatDetector) cleanupOldAlerts() {
	td.mu.Lock()
	defer td.mu.Unlock()

	// 将超过30分钟的告警标记为非活跃
	cutoff := time.Now().Add(-30 * time.Minute)
	for i := range td.alerts {
		if td.alerts[i].Timestamp.Before(cutoff) {
			td.alerts[i].Active = false
		}
	}
}

func (td *ThreatDetector) GetActiveThreats() []ThreatAlert {
	td.mu.RLock()
	defer td.mu.RUnlock()

	activeThreats := make([]ThreatAlert, 0)
	for _, alert := range td.alerts {
		if alert.Active {
			activeThreats = append(activeThreats, alert)
		}
	}

	return activeThreats
}

func (td *ThreatDetector) GetAllThreats() []ThreatAlert {
	td.mu.RLock()
	defer td.mu.RUnlock()

	threats := make([]ThreatAlert, len(td.alerts))
	copy(threats, td.alerts)
	return threats
}
