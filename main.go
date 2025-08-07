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
		return true // 允许所有来源的WebSocket连接
	},
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

// 全局变量
var (
	clients    = make(map[*websocket.Conn]bool)
	broadcast  = make(chan SystemData)
	collector  *RealDataCollector
	detector   *ThreatDetector
)

func main() {
	fmt.Println("🚀 启动天眼网络监控系统...")
	
	// 初始化数据收集器和威胁检测器
	collector = NewRealDataCollector()
	detector = NewThreatDetector()
	
	// 启动数据收集
	go collector.Start()
	go detector.Start()
	
	// 启动WebSocket广播处理
	go handleMessages()
	
	// 定期发送系统数据
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				data := collector.GetSystemData()
				broadcast <- data
			}
		}
	}()
	
	// 设置路由
	router := mux.NewRouter()
	
	// API路由
	api := router.PathPrefix("/api").Subrouter()
	api.HandleFunc("/system/info", handleSystemInfo).Methods("GET")
	api.HandleFunc("/agents", handleAgents).Methods("GET")
	api.HandleFunc("/threats", handleThreats).Methods("GET")
	api.HandleFunc("/ws", handleWebSocket)
	
	// 静态文件服务
	// 首先尝试服务Next.js构建的文件
	if _, err := os.Stat("out"); err == nil {
		fmt.Println("📁 使用Next.js构建文件 (out目录)")
		router.PathPrefix("/").Handler(http.FileServer(http.Dir("out/")))
	} else if _, err := os.Stat(".next"); err == nil {
		fmt.Println("📁 使用Next.js开发文件 (.next目录)")
		router.PathPrefix("/").Handler(http.FileServer(http.Dir(".next/")))
	} else if _, err := os.Stat("static"); err == nil {
		fmt.Println("📁 使用静态HTML文件")
		router.PathPrefix("/").Handler(http.FileServer(http.Dir("static/")))
	} else {
		// 创建一个简单的默认页面
		router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			html := `
<!DOCTYPE html>
<html>
<head>
    <title>天眼网络监控系统</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; }
        .status { background: #e8f5e8; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .api-list { background: #f8f9fa; padding: 15px; border-radius: 5px; }
        .api-item { margin: 10px 0; }
        a { color: #007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 天眼网络监控系统</h1>
        <div class="status">
            <h3>✅ 系统状态：运行中</h3>
            <p>监控服务已启动，WebSocket连接可用</p>
        </div>
        
        <div class="api-list">
            <h3>📊 API接口</h3>
            <div class="api-item">
                <strong>系统信息:</strong> <a href="/api/system/info">/api/system/info</a>
            </div>
            <div class="api-item">
                <strong>代理列表:</strong> <a href="/api/agents">/api/agents</a>
            </div>
            <div class="api-item">
                <strong>威胁数据:</strong> <a href="/api/threats">/api/threats</a>
            </div>
            <div class="api-item">
                <strong>WebSocket:</strong> ws://localhost:8080/api/ws
            </div>
        </div>
        
        <div style="margin-top: 30px; text-align: center; color: #666;">
            <p>前端界面构建中... 请使用API接口访问数据</p>
        </div>
    </div>
</body>
</html>`
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(html))
		})
	}
	
	// 启动服务器
	port := "8080"
	fmt.Printf("🌐 服务器启动在端口 %s\n", port)
	fmt.Printf("📊 访问地址: http://localhost:%s\n", port)
	fmt.Printf("🔌 WebSocket: ws://localhost:%s/api/ws\n", port)
	
	log.Fatal(http.ListenAndServe(":"+port, router))
}

func handleMessages() {
	for {
		msg := <-broadcast
		for client := range clients {
			err := client.WriteJSON(msg)
			if err != nil {
				log.Printf("WebSocket写入错误: %v", err)
				client.Close()
				delete(clients, client)
			}
		}
	}
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// 升级HTTP连接为WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket升级失败: %v", err)
		return
	}
	defer conn.Close()
	
	// 注册新客户端
	clients[conn] = true
	log.Printf("新的WebSocket连接，当前连接数: %d", len(clients))
	
	// 发送初始数据
	initialData := collector.GetSystemData()
	if err := conn.WriteJSON(initialData); err != nil {
		log.Printf("发送初始数据失败: %v", err)
		delete(clients, conn)
		return
	}
	
	// 保持连接并处理消息
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			log.Printf("WebSocket读取错误: %v", err)
			delete(clients, conn)
			break
		}
	}
}

func handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	
	data := collector.GetSystemData()
	json.NewEncoder(w).Encode(data)
}

func handleAgents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	
	agents := []Agent{
		{
			ID:       "agent-1",
			Name:     "本地服务器",
			Host:     "localhost",
			Port:     8080,
			Status:   "online",
			LastSeen: time.Now(),
		},
		{
			ID:       "agent-2", 
			Name:     "Web服务器-1",
			Host:     "192.168.1.10",
			Port:     8080,
			Status:   "online",
			LastSeen: time.Now().Add(-30 * time.Second),
		},
	}
	
	json.NewEncoder(w).Encode(agents)
}

func handleThreats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	
	threats := detector.GetThreats()
	json.NewEncoder(w).Encode(threats)
}

// 辅助函数：检查文件是否存在
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// 辅助函数：获取静态文件路径
func getStaticPath() string {
	paths := []string{"out", ".next", "static", "public"}
	
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			absPath, _ := filepath.Abs(path)
			return absPath
		}
	}
	
	return ""
}
