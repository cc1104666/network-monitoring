package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// 全局数据收集器
var dataCollector *RealDataCollector

func main() {
	// 初始化数据收集器
	dataCollector = NewRealDataCollector()
	
	// 启动实时数据收集
	dataCollector.StartRealTimeCollection()

	// 创建路由
	r := mux.NewRouter()

	// API路由
	api := r.PathPrefix("/api").Subrouter()
	api.HandleFunc("/system", dataCollector.HandleSystemMetrics).Methods("GET")
	api.HandleFunc("/network", dataCollector.HandleNetworkConnections).Methods("GET")
	api.HandleFunc("/requests", dataCollector.HandleHTTPRequests).Methods("GET")
	api.HandleFunc("/processes", dataCollector.HandleProcesses).Methods("GET")
	api.HandleFunc("/info", dataCollector.HandleSystemInfo).Methods("GET")
	api.HandleFunc("/threats", handleThreats).Methods("GET")
	api.HandleFunc("/alerts", handleAlerts).Methods("GET")
	api.HandleFunc("/ws", handleWebSocket).Methods("GET")

	// 静态文件服务
	staticDir := "./static"
	if _, err := os.Stat(staticDir); os.IsNotExist(err) {
		log.Printf("静态文件目录不存在: %s", staticDir)
	}
	r.PathPrefix("/").Handler(http.FileServer(http.Dir(staticDir)))

	// 启动服务器
	port := "8080"
	if p := os.Getenv("PORT"); p != "" {
		port = p
	}

	log.Printf("🚀 网络监控系统启动")
	log.Printf("📊 监控面板: http://localhost:%s", port)
	log.Printf("🔍 真实数据收集: %v", os.Getenv("ENABLE_REAL_DATA") == "true")
	log.Printf("📡 WebSocket端点: ws://localhost:%s/api/ws", port)

	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal("服务器启动失败:", err)
	}
}

func handleThreats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// 获取HTTP请求并分析威胁
	requests := dataCollector.CollectHTTPRequests()
	threats := []Threat{}

	for _, req := range requests {
		if req.ThreatScore > 20 {
			threat := Threat{
				ID:          fmt.Sprintf("threat_%d", time.Now().Unix()),
				Type:        determineThreatType(req),
				Severity:    determineSeverity(req.ThreatScore),
				Source:      req.IP,
				Target:      req.Path,
				Description: fmt.Sprintf("可疑%s请求到%s", req.Method, req.Path),
				Timestamp:   req.Timestamp,
				Status:      "active",
			}
			threats = append(threats, threat)
		}
	}

	json.NewEncoder(w).Encode(threats)
}

func handleAlerts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	alerts := []Alert{
		{
			ID:          "alert_1",
			Type:        "security",
			Message:     "检测到可疑登录尝试",
			Severity:    "high",
			Timestamp:   time.Now().Add(-5 * time.Minute),
			Acknowledged: false,
		},
		{
			ID:          "alert_2",
			Type:        "performance",
			Message:     "CPU使用率超过80%",
			Severity:    "medium",
			Timestamp:   time.Now().Add(-10 * time.Minute),
			Acknowledged: true,
		},
	}

	json.NewEncoder(w).Encode(alerts)
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket升级失败: %v", err)
		return
	}
	defer conn.Close()

	log.Printf("WebSocket连接建立: %s", r.RemoteAddr)

	// 发送实时数据
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// 发送系统指标
			metrics := dataCollector.CollectSystemMetrics()
			data := map[string]interface{}{
				"type": "metrics",
				"data": metrics,
			}

			if err := conn.WriteJSON(data); err != nil {
				log.Printf("WebSocket发送失败: %v", err)
				return
			}

		default:
			// 检查连接是否关闭
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Printf("WebSocket连接关闭: %v", err)
				return
			}
			time.Sleep(1 * time.Second)
		}
	}
}

func determineThreatType(req HTTPRequest) string {
	if req.ThreatScore > 50 {
		return "high_risk"
	} else if req.ThreatScore > 30 {
		return "medium_risk"
	}
	return "low_risk"
}

func determineSeverity(score int) string {
	if score > 70 {
		return "critical"
	} else if score > 50 {
		return "high"
	} else if score > 30 {
		return "medium"
	}
	return "low"
}

// 确保静态文件目录存在
func ensureStaticDir() {
	staticDir := "./static"
	if _, err := os.Stat(staticDir); os.IsNotExist(err) {
		os.MkdirAll(staticDir, 0755)
		
		// 创建基本的index.html
		indexHTML := `<!DOCTYPE html>
<html>
<head>
    <title>网络监控系统</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .metric { background: #f5f5f5; padding: 20px; margin: 10px 0; border-radius: 5px; }
        .status { color: green; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ 网络监控系统</h1>
        <div class="status">✅ 系统运行正常</div>
        
        <div class="metric">
            <h3>📊 系统指标</h3>
            <p>访问 <a href="/api/system">/api/system</a> 查看系统指标</p>
        </div>
        
        <div class="metric">
            <h3>🌐 网络连接</h3>
            <p>访问 <a href="/api/network">/api/network</a> 查看网络连接</p>
        </div>
        
        <div class="metric">
            <h3>🔍 HTTP请求</h3>
            <p>访问 <a href="/api/requests">/api/requests</a> 查看HTTP请求</p>
        </div>
        
        <div class="metric">
            <h3>⚡ 进程信息</h3>
            <p>访问 <a href="/api/processes">/api/processes</a> 查看进程信息</p>
        </div>
        
        <div class="metric">
            <h3>🚨 威胁检测</h3>
            <p>访问 <a href="/api/threats">/api/threats</a> 查看威胁信息</p>
        </div>
    </div>
    
    <script>
        // 简单的实时更新
        setInterval(() => {
            fetch('/api/system')
                .then(r => r.json())
                .then(data => {
                    console.log('系统指标:', data);
                })
                .catch(e => console.error('获取数据失败:', e));
        }, 5000);
    </script>
</body>
</html>`
		
		indexPath := filepath.Join(staticDir, "index.html")
		if err := os.WriteFile(indexPath, []byte(indexHTML), 0644); err != nil {
			log.Printf("创建index.html失败: %v", err)
		}
	}
}

func init() {
	ensureStaticDir()
}
