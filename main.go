package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

func main() {
	// 检查运行模式
	if len(os.Args) > 1 && os.Args[1] == "agent" {
		runAgent()
		return
	}

	// 初始化监控系统
	monitor := NewNetworkMonitor()
	threatDetector := NewThreatDetector()
	
	// 启动监控协程
	go monitor.Start()
	go threatDetector.Start()
	
	// 启动真实数据收集器
	realDataCollector := NewRealDataCollector(monitor, threatDetector)
	go realDataCollector.Start()
	
	// 创建路由
	r := mux.NewRouter()
	
	// API路由
	r.HandleFunc("/api/stats", getStatsHandler(monitor)).Methods("GET")
	r.HandleFunc("/api/servers", getServersHandler(monitor)).Methods("GET")
	r.HandleFunc("/api/threats", getThreatsHandler(threatDetector)).Methods("GET")
	r.HandleFunc("/api/endpoints", getEndpointsHandler(monitor)).Methods("GET")
	r.HandleFunc("/api/request-details", getRequestDetailsHandler(monitor)).Methods("GET")
	
	// 代理数据接收接口
	r.HandleFunc("/api/agent/metrics", receiveAgentMetrics(monitor)).Methods("POST")
	
	// WebSocket路由
	r.HandleFunc("/ws", websocketHandler(monitor, threatDetector))
	
	// 静态文件服务
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./static/")))
	
	// 启动服务器
	log.Println("🚀 天眼网络监控系统启动在端口 :8080")
	log.Println("📊 监控面板: http://localhost:8080")
	log.Println("🔍 真实数据收集器已启用")
	log.Fatal(http.ListenAndServe(":8080", r))
}

// 接收代理指标数据
func receiveAgentMetrics(monitor *NetworkMonitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		
		var metrics SystemMetrics
		if err := json.NewDecoder(r.Body).Decode(&metrics); err != nil {
			http.Error(w, "解析数据失败", http.StatusBadRequest)
			return
		}
		
		// 更新服务器状态
		monitor.UpdateServerFromAgent(&metrics)
		
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "指标接收成功",
		})
	}
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func websocketHandler(monitor *NetworkMonitor, detector *ThreatDetector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("WebSocket升级失败: %v", err)
			return
		}
		defer conn.Close()
		
		// 创建客户端连接
		client := &WSClient{
			conn:     conn,
			send:     make(chan []byte, 256),
			monitor:  monitor,
			detector: detector,
			done:     make(chan struct{}),
		}
		
		// 注册客户端
		monitor.RegisterClient(client)
		defer monitor.UnregisterClient(client)
		
		// 启动读写协程
		go client.writePump()
		go client.readPump()
		
		// 定期发送数据
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				data := map[string]interface{}{
					"type":            "update",
					"stats":           monitor.GetCurrentStats(),
					"servers":         monitor.GetServerStatus(),
					"threats":         detector.GetActiveThreats(),
					"endpoints":       monitor.GetEndpointStats(),
					"request_details": monitor.GetRequestDetails(),
					"timestamp":       time.Now().Unix(),
				}
				client.SendJSON(data)
			case <-client.done:
				return
			}
		}
	}
}
