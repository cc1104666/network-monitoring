package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
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
	
	// 检查是否启用真实数据收集
	enableRealData := os.Getenv("ENABLE_REAL_DATA")
	if enableRealData == "true" {
		log.Println("🔍 启用真实数据收集器...")
		realDataCollector := NewRealDataCollector(monitor, threatDetector)
		go realDataCollector.Start()
	} else {
		log.Println("📊 使用模拟数据模式...")
	}
	
	// 创建路由
	r := mux.NewRouter()
	
	// 添加CORS中间件
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
			
			next.ServeHTTP(w, r)
		})
	})
	
	// API路由
	r.HandleFunc("/api/stats", getStatsHandler(monitor)).Methods("GET")
	r.HandleFunc("/api/servers", getServersHandler(monitor)).Methods("GET")
	r.HandleFunc("/api/threats", getThreatsHandler(threatDetector)).Methods("GET")
	r.HandleFunc("/api/endpoints", getEndpointsHandler(monitor)).Methods("GET")
	r.HandleFunc("/api/request-details", getRequestDetailsHandler(monitor)).Methods("GET")
	
	// 威胁处理API
	r.HandleFunc("/api/threats/{id}/{action}", handleThreatActionHandler(threatDetector)).Methods("POST")
	
	// 代理数据接收接口
	r.HandleFunc("/api/agent/metrics", receiveAgentMetrics(monitor)).Methods("POST")
	
	// WebSocket路由
	r.HandleFunc("/ws", websocketHandler(monitor, threatDetector))
	
	// 静态文件服务
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./static/")))
	
	// 启动服务器
	log.Println("🚀 天眼网络监控系统启动在端口 :8080")
	log.Println("📊 监控面板: http://localhost:8080")
	
	if enableRealData == "true" {
		log.Println("🔍 真实数据收集器已启用")
	} else {
		log.Println("📊 模拟数据模式已启用")
	}
	
	log.Fatal(http.ListenAndServe(":8080", r))
}

// 获取统计数据处理器
func getStatsHandler(monitor *NetworkMonitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		
		stats := monitor.GetCurrentStats()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    stats,
		})
	}
}

// 获取服务器状态处理器
func getServersHandler(monitor *NetworkMonitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		
		servers := monitor.GetServerStatus()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    servers,
		})
	}
}

// 获取威胁信息处理器
func getThreatsHandler(detector *ThreatDetector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		
		threats := detector.GetAllThreats()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    threats,
		})
	}
}

// 获取端点信息处理器
func getEndpointsHandler(monitor *NetworkMonitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		
		endpoints := monitor.GetEndpointStats()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    endpoints,
		})
	}
}

// 获取请求详情处理器
func getRequestDetailsHandler(monitor *NetworkMonitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		
		details := monitor.GetRequestDetails()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    details,
		})
	}
}

// 威胁处理API
func handleThreatActionHandler(detector *ThreatDetector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		
		vars := mux.Vars(r)
		threatIDStr := vars["id"]
		action := vars["action"]
		
		threatID, err := strconv.Atoi(threatIDStr)
		if err != nil {
			http.Error(w, "无效的威胁ID", http.StatusBadRequest)
			return
		}
		
		// 处理威胁操作
		var message string
		switch action {
		case "block":
			message = "IP已被封禁"
		case "whitelist":
			message = "IP已加入白名单"
		case "ignore":
			message = "威胁已忽略"
		default:
			message = "威胁已处理"
		}
		
		// 标记威胁为已处理
		detector.HandleThreat(threatID)
		
		log.Printf("处理威胁 %d: %s", threatID, action)
		
		response := map[string]interface{}{
			"success": true,
			"message": message,
		}
		
		json.NewEncoder(w).Encode(response)
	}
}

// 接收代理指标数据
func receiveAgentMetrics(monitor *NetworkMonitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		
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

// 运行代理模式
func runAgent() {
	log.Println("🤖 启动代理模式...")
	// 这里可以实现代理功能
}
