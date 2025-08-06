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
	"github.com/rs/cors"
)

var (
	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			// 允许所有来源的WebSocket连接
			return true
		},
	}
	
	clients    = make(map[*websocket.Conn]bool)
	broadcast  = make(chan []byte)
	
	// 全局组件
	systemMonitor   *SystemMonitor
	threatDetector  *ThreatDetector
	dataCollector   *RealDataCollector
)

func main() {
	log.Println("🚀 启动天眼网络监控系统...")

	// 初始化组件
	systemMonitor = NewSystemMonitor()
	threatDetector = NewThreatDetector()
	dataCollector = NewRealDataCollector()

	// 启动后台服务
	go handleMessages()
	go startDataCollection()

	// 设置路由
	router := mux.NewRouter()

	// API 路由
	api := router.PathPrefix("/api").Subrouter()
	api.HandleFunc("/system/info", getSystemInfo).Methods("GET")
	api.HandleFunc("/network/stats", getNetworkStats).Methods("GET")
	api.HandleFunc("/threats", getThreats).Methods("GET")
	api.HandleFunc("/logs", getLogs).Methods("GET")

	// WebSocket 路由
	router.HandleFunc("/ws", handleWebSocket)

	// 静态文件服务
	staticDir := "./static"
	if _, err := os.Stat(staticDir); os.IsNotExist(err) {
		staticDir = "."
	}
	
	router.PathPrefix("/").Handler(http.FileServer(http.Dir(staticDir)))

	// CORS 配置
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"*"},
		AllowCredentials: true,
	})

	handler := c.Handler(router)

	// 启动服务器
	port := "8080"
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}

	log.Printf("🌐 服务器启动在端口 %s", port)
	log.Printf("📊 Web界面: http://localhost:%s", port)
	log.Printf("🔌 WebSocket: ws://localhost:%s/ws", port)
	
	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatal("❌ 服务器启动失败:", err)
	}
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket升级失败: %v", err)
		return
	}
	defer conn.Close()

	clients[conn] = true
	log.Printf("✅ 新的WebSocket连接: %s", r.RemoteAddr)

	// 发送初始数据
	sendInitialData(conn)

	// 保持连接活跃
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			log.Printf("WebSocket连接断开: %v", err)
			delete(clients, conn)
			break
		}
	}
}

func sendInitialData(conn *websocket.Conn) {
	// 发送系统信息
	if systemInfo := systemMonitor.GetSystemInfo(); systemInfo != nil {
		data := map[string]interface{}{
			"type": "system_info",
			"data": systemInfo,
		}
		if jsonData, err := json.Marshal(data); err == nil {
			conn.WriteMessage(websocket.TextMessage, jsonData)
		}
	}

	// 发送网络统计
	if networkStats := dataCollector.GetNetworkStats(); networkStats != nil {
		data := map[string]interface{}{
			"type": "network_stats",
			"data": networkStats,
		}
		if jsonData, err := json.Marshal(data); err == nil {
			conn.WriteMessage(websocket.TextMessage, jsonData)
		}
	}
}

func handleMessages() {
	for {
		msg := <-broadcast
		for client := range clients {
			err := client.WriteMessage(websocket.TextMessage, msg)
			if err != nil {
				log.Printf("WebSocket写入错误: %v", err)
				client.Close()
				delete(clients, client)
			}
		}
	}
}

func startDataCollection() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// 收集系统信息
			if systemInfo := systemMonitor.GetSystemInfo(); systemInfo != nil {
				data := map[string]interface{}{
					"type": "system_info",
					"data": systemInfo,
				}
				if jsonData, err := json.Marshal(data); err == nil {
					broadcast <- jsonData
				}
			}

			// 收集网络统计
			if networkStats := dataCollector.GetNetworkStats(); networkStats != nil {
				data := map[string]interface{}{
					"type": "network_stats",
					"data": networkStats,
				}
				if jsonData, err := json.Marshal(data); err == nil {
					broadcast <- jsonData
				}
			}

			// 检测威胁
			if threats := threatDetector.DetectThreats(); len(threats) > 0 {
				for _, threat := range threats {
					data := map[string]interface{}{
						"type": "threat_detected",
						"data": threat,
					}
					if jsonData, err := json.Marshal(data); err == nil {
						broadcast <- jsonData
					}
				}
			}
		}
	}
}

// API 处理函数
func getSystemInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	systemInfo := systemMonitor.GetSystemInfo()
	if systemInfo == nil {
		http.Error(w, "无法获取系统信息", http.StatusInternalServerError)
		return
	}
	
	json.NewEncoder(w).Encode(systemInfo)
}

func getNetworkStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	networkStats := dataCollector.GetNetworkStats()
	if networkStats == nil {
		http.Error(w, "无法获取网络统计", http.StatusInternalServerError)
		return
	}
	
	json.NewEncoder(w).Encode(networkStats)
}

func getThreats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	threats := threatDetector.GetRecentThreats()
	json.NewEncoder(w).Encode(threats)
}

func getLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	logs := []LogEntry{
		{
			Timestamp: time.Now().Format(time.RFC3339),
			Level:     "INFO",
			Message:   "系统正常运行",
		},
	}
	
	json.NewEncoder(w).Encode(logs)
}

// 辅助函数
func getExecutableDir() string {
	ex, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(ex)
}
