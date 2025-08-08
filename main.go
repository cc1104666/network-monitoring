package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/rs/cors"
)

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	
	dataCollector   *RealDataCollector
	threatDetector  *ThreatDetector
	clients         = make(map[*websocket.Conn]bool)
	broadcast       = make(chan []byte)
)

func main() {
	log.Println("🚀 启动网络监控系统...")

	// 初始化组件
	dataCollector = NewRealDataCollector()
	threatDetector = NewThreatDetector()

	// 启动组件
	dataCollector.Start()
	threatDetector.Start()

	// 启动WebSocket广播
	go handleMessages()

	// 启动数据收集循环
	go dataCollectionLoop()

	// 设置路由
	router := setupRoutes()

	// 设置CORS
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"*"},
	})

	handler := c.Handler(router)

	// 启动服务器
	port := "8080"
	log.Printf("🌐 服务器启动在端口 %s", port)
	log.Printf("📊 监控面板: http://localhost:%s", port)
	log.Printf("🔌 WebSocket: ws://localhost:%s/ws", port)

	// 优雅关闭
	go func() {
		if err := http.ListenAndServe(":"+port, handler); err != nil {
			log.Fatal("服务器启动失败:", err)
		}
	}()

	// 等待中断信号
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	log.Println("🛑 正在关闭服务器...")
	threatDetector.Stop()
	log.Println("✅ 服务器已关闭")
}

func setupRoutes() *mux.Router {
	router := mux.NewRouter()

	// API路由
	api := router.PathPrefix("/api").Subrouter()
	api.HandleFunc("/metrics", getMetricsHandler).Methods("GET")
	api.HandleFunc("/threats", getThreatsHandler).Methods("GET")
	api.HandleFunc("/network-stats", getNetworkStatsHandler).Methods("GET")
	api.HandleFunc("/system-data", getSystemDataHandler).Methods("GET")

	// WebSocket路由
	router.HandleFunc("/ws", handleWebSocket)

	// 静态文件服务
	router.PathPrefix("/").Handler(http.HandlerFunc(serveStaticFiles))

	return router
}

func serveStaticFiles(w http.ResponseWriter, r *http.Request) {
	// 检查是否存在Next.js构建文件
	if _, err := os.Stat("app"); err == nil {
		// 如果存在app目录，说明是Next.js项目
		if r.URL.Path == "/" {
			http.ServeFile(w, r, "static/index.html")
			return
		}
	}

	// 默认静态文件服务
	path := r.URL.Path
	if path == "/" {
		path = "/index.html"
	}

	filePath := filepath.Join("static", path)
	
	// 检查文件是否存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		// 如果文件不存在，返回index.html（用于SPA路由）
		http.ServeFile(w, r, "static/index.html")
		return
	}

	http.ServeFile(w, r, filePath)
}

func getMetricsHandler(w http.ResponseWriter, r *http.Request) {
	metrics, err := dataCollector.GetSystemMetrics()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

func getThreatsHandler(w http.ResponseWriter, r *http.Request) {
	threats := threatDetector.GetThreats()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(threats)
}

func getNetworkStatsHandler(w http.ResponseWriter, r *http.Request) {
	stats := dataCollector.GetNetworkStats()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func getSystemDataHandler(w http.ResponseWriter, r *http.Request) {
	data := dataCollector.GetSystemData()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket升级失败: %v", err)
		return
	}
	defer conn.Close()

	clients[conn] = true
	log.Printf("🔌 新的WebSocket连接，当前连接数: %d", len(clients))

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			log.Printf("WebSocket读取错误: %v", err)
			delete(clients, conn)
			break
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

func dataCollectionLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// 收集系统数据
			systemData := dataCollector.GetSystemData()
			
			// 检测威胁
			threats := threatDetector.DetectThreats(systemData)
			systemData.Threats = threats

			// 广播数据到WebSocket客户端
			if len(clients) > 0 {
				data, err := json.Marshal(map[string]interface{}{
					"type": "system_update",
					"data": systemData,
				})
				if err == nil {
					select {
					case broadcast <- data:
					default:
					}
				}
			}
		}
	}
}
