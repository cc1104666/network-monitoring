package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// Hub maintains the set of active clients and broadcasts messages to them.
type Hub struct {
	clients    map[*websocket.Conn]bool
	broadcast  chan []byte
	register   chan *websocket.Conn
	unregister chan *websocket.Conn
	mu         sync.Mutex
}

func newHub() *Hub {
	return &Hub{
		broadcast:  make(chan []byte),
		register:   make(chan *websocket.Conn),
		unregister: make(chan *websocket.Conn),
		clients:    make(map[*websocket.Conn]bool),
	}
}

func (h *Hub) run() {
	for {
		select {
		case conn := <-h.register:
			h.mu.Lock()
			h.clients[conn] = true
			h.mu.Unlock()
			log.Printf("✅ WebSocket client connected. Total clients: %d", len(h.clients))

		case conn := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[conn]; ok {
				delete(h.clients, conn)
				conn.Close()
			}
			h.mu.Unlock()
			log.Printf("❌ WebSocket client disconnected. Total clients: %d", len(h.clients))

		case message := <-h.broadcast:
			h.mu.Lock()
			// Create a slice of connections to iterate over
			conns := make([]*websocket.Conn, 0, len(h.clients))
			for c := range h.clients {
				conns = append(conns, c)
			}
			h.mu.Unlock()

			// Send message to all clients with timeout
			for _, conn := range conns {
				select {
				case <-time.After(time.Second):
					// Timeout after 1 second
					log.Printf("⚠️ WebSocket write timeout, removing client")
					go func(c *websocket.Conn) { h.unregister <- c }(conn)
				default:
					if err := conn.WriteMessage(websocket.TextMessage, message); err != nil {
						log.Printf("❌ WebSocket write error: %v", err)
						go func(c *websocket.Conn) { h.unregister <- c }(conn)
					}
				}
			}
		}
	}
}

var (
	dataCollector   *RealDataCollector
	threatDetector  *ThreatDetector
	hub             *Hub
	upgrader        = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	wsConnections   = make(map[*websocket.Conn]bool)
	wsConnectionsMu = make(chan bool, 1)
)

func init() {
	wsConnectionsMu <- true
}

func main() {
	log.Println("🚀 启动天眼网络监控系统...")

	// Initialize components
	dataCollector = NewRealDataCollector()
	threatDetector = NewThreatDetector()
	hub = newHub()
	go hub.run()

	// Generate some mock threats for demonstration
	threatDetector.GenerateMockThreats()

	// Setup routes
	r := mux.NewRouter()

	// WebSocket endpoint - MUST be defined first and be very specific
	r.HandleFunc("/ws", serveWs).Methods("GET")
	log.Println("📡 WebSocket endpoint registered: /ws")

	// API routes - also very specific, must come before static files
	api := r.PathPrefix("/api").Subrouter()
	api.HandleFunc("/system/info", getSystemInfo).Methods("GET")
	api.HandleFunc("/threats", getThreats).Methods("GET")
	api.HandleFunc("/alerts", getAlerts).Methods("GET")
	api.HandleFunc("/system/metrics", handleSystemMetrics).Methods("GET")
	api.HandleFunc("/network/connections", handleNetworkConnections).Methods("GET")
	api.HandleFunc("/processes", handleProcesses).Methods("GET")
	api.HandleFunc("/agent/metrics", handleAgentMetrics).Methods("POST")
	log.Println("🔌 API endpoints registered: /api/system/info, /api/threats, /api/alerts, /api/system/metrics, /api/network/connections, /api/processes, /api/agent/metrics")

	// Static file serving - this should be LAST
	staticDir := "./out"
	if _, err := os.Stat(staticDir); os.IsNotExist(err) {
		staticDir = "./static"
	}
	
	r.PathPrefix("/").Handler(http.FileServer(http.Dir(staticDir)))
	log.Printf("📁 Static files served from: %s", staticDir)

	// Start background tasks
	go runDataBroadcaster()
	go cleanupOldThreats()

	// Server configuration
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("🌐 服务器启动在端口 %s", port)
	log.Printf("📊 访问监控面板: http://localhost:%s", port)
	log.Printf("🔌 WebSocket端点: ws://localhost:%s/ws", port)
	log.Printf("📡 API端点: http://localhost:%s/api/", port)

	// Start the server
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal("❌ 服务器启动失败:", err)
	}
}

// ensureStaticFiles ensures the static directory exists with fallback content
func ensureStaticFiles(staticDir string) error {
	if _, err := os.Stat(staticDir); os.IsNotExist(err) {
		log.Printf("📁 Static directory %s does not exist, creating with fallback content", staticDir)
		
		if err := os.MkdirAll(staticDir, 0755); err != nil {
			return err
		}

		// Create a simple fallback HTML page
		fallbackHTML := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>天眼网络监控系统</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #007acc; padding-bottom: 10px; }
        .status { background: #e7f3ff; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .endpoints { background: #f8f9fa; padding: 15px; border-radius: 5px; }
        .endpoints a { color: #007acc; text-decoration: none; }
        .endpoints a:hover { text-decoration: underline; }
        .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; color: #856404; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 天眼网络监控系统</h1>
        
        <div class="warning">
            <strong>⚠️ 前端未构建</strong><br>
            请运行: <code>npm run build</code>
        </div>
        
        <div class="status">
            <strong>✅ 后端服务器运行</strong><br>
            Go后端服务器正在运行并准备提供数据。
        </div>
        
        <div class="endpoints">
            <h3>可用端点:</h3>
            <ul>
                <li><strong>WebSocket:</strong> <a href="/ws">/ws</a> (实时数据流)</li>
                <li><strong>系统信息:</strong> <a href="/api/system/info">/api/system/info</a></li>
                <li><strong>威胁:</strong> <a href="/api/threats">/api/threats</a></li>
                <li><strong>警报:</strong> <a href="/api/alerts">/api/alerts</a></li>
                <li><strong>系统指标:</strong> <a href="/api/system/metrics">/api/system/metrics</a></li>
                <li><strong>网络连接:</strong> <a href="/api/network/connections">/api/network/connections</a></li>
                <li><strong>进程:</strong> <a href="/api/processes">/api/processes</a></li>
                <li><strong>代理指标:</strong> <a href="/api/agent/metrics">/api/agent/metrics</a></li>
            </ul>
        </div>
        
        <div class="status">
            <h3>🔧 开发说明:</h3>
            <ol>
                <li>安装Node.js依赖: <code>npm install</code></li>
                <li>构建前端: <code>npm run build</code></li>
                <li>重启Go服务器以提供构建后的前端</li>
            </ol>
        </div>
    </div>
    
    <script>
        // Test WebSocket connection
        console.log('测试WebSocket连接...');
        const ws = new WebSocket('ws://localhost:8080/ws');
        ws.onopen = () => console.log('✅ WebSocket连接成功');
        ws.onerror = (error) => console.error('❌ WebSocket错误:', error);
        ws.onmessage = (event) => console.log('📨 WebSocket消息:', event.data);
    </script>
</body>
</html>`

		if err := os.WriteFile(filepath.Join(staticDir, "index.html"), []byte(fallbackHTML), 0644); err != nil {
			return err
		}
		
		log.Printf("✅ 创建回退HTML在 %s/index.html", staticDir)
	}
	return nil
}

// serveWs handles websocket requests from clients
func serveWs(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔌 WebSocket连接尝试来自 %s", r.RemoteAddr)
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("❌ WebSocket升级失败: %v", err)
		http.Error(w, "WebSocket升级失败", http.StatusBadRequest)
		return
	}

	log.Printf("✅ WebSocket连接建立来自 %s", r.RemoteAddr)
	hub.register <- conn

	// Handle client messages and disconnection
	go func() {
		defer func() {
			hub.unregister <- conn
		}()
		
		// Set read deadline and pong handler for keepalive
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		conn.SetPongHandler(func(string) error {
			conn.SetReadDeadline(time.Now().Add(60 * time.Second))
			return nil
		})

		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("❌ WebSocket错误: %v", err)
				}
				break
			}
		}
	}()

	// Send ping messages to keep connection alive
	go func() {
		ticker := time.NewTicker(54 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			}
		}
	}()
}

// runDataBroadcaster periodically collects and broadcasts data
func runDataBroadcaster() {
	log.Println("📡 启动数据广播器...")
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Only broadcast if there are connected clients
		hub.mu.Lock()
		clientCount := len(hub.clients)
		hub.mu.Unlock()

		if clientCount == 0 {
			continue
		}

		// System Metrics
		if metrics, err := dataCollector.GetSystemMetrics(); err == nil {
			broadcastMessage("SYSTEM_METRICS_UPDATE", metrics)
		} else {
			log.Printf("⚠️ 获取系统指标错误: %v", err)
		}

		// Network Connections
		if connections, err := dataCollector.GetNetworkConnections(); err == nil {
			broadcastMessage("NETWORK_CONNECTIONS_UPDATE", connections)
		} else {
			log.Printf("⚠️ 获取网络连接错误: %v", err)
		}

		// Processes
		if processes, err := dataCollector.GetProcesses(); err == nil {
			broadcastMessage("PROCESSES_UPDATE", processes)
		} else {
			log.Printf("⚠️ 获取进程错误: %v", err)
		}
	}
}

func broadcastMessage(msgType string, payload interface{}) {
	msg := WebSocketMessage{Type: msgType, Payload: payload}
	if jsonMsg, err := json.Marshal(msg); err == nil {
		select {
		case hub.broadcast <- jsonMsg:
		case <-time.After(time.Second):
			log.Printf("⚠️ 广播超时，消息类型: %s", msgType)
		}
	} else {
		log.Printf("❌ 序列化 %s 错误: %v", msgType, err)
	}
}

// API Handlers
func getSystemInfo(w http.ResponseWriter, r *http.Request) {
	log.Printf("📊 API请求: %s %s 来自 %s", r.Method, r.URL.Path, getClientIP(r))
	
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	
	data, err := dataCollector.GetSystemInfo()
	if err != nil {
		log.Printf("❌ 获取系统信息错误: %v", err)
		http.Error(w, fmt.Sprintf(`{"error": "%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("❌ 编码系统信息错误: %v", err)
		http.Error(w, `{"error": "响应编码失败"}`, http.StatusInternalServerError)
		return
	}
	
	log.Printf("✅ 系统信息成功发送")
}

func getThreats(w http.ResponseWriter, r *http.Request) {
	log.Printf("🚨 API请求: %s %s 来自 %s", r.Method, r.URL.Path, getClientIP(r))
	
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	
	threats := threatDetector.GetThreats()
	
	if err := json.NewEncoder(w).Encode(threats); err != nil {
		log.Printf("❌ 编码威胁错误: %v", err)
		http.Error(w, `{"error": "响应编码失败"}`, http.StatusInternalServerError)
		return
	}
	
	log.Printf("✅ 威胁成功发送 (%d 威胁)", len(threats))
}

func getAlerts(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔔 API请求: %s %s 来自 %s", r.Method, r.URL.Path, getClientIP(r))
	
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	
	alerts := threatDetector.GetAlerts()
	
	if err := json.NewEncoder(w).Encode(alerts); err != nil {
		log.Printf("❌ 编码警报错误: %v", err)
		http.Error(w, `{"error": "响应编码失败"}`, http.StatusInternalServerError)
		return
	}
	
	log.Printf("✅ 警报成功发送 (%d 警报)", len(alerts))
}

func handleSystemMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	metrics, err := dataCollector.GetSystemMetrics()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get system metrics: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(metrics)
}

func handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	info, err := dataCollector.GetSystemInfo()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get system info: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(info)
}

func handleNetworkConnections(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	connections, err := dataCollector.GetNetworkConnections()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get network connections: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(connections)
}

func handleProcesses(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	processes, err := dataCollector.GetProcesses()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get processes: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(processes)
}

func handleThreats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	threats := threatDetector.GetThreats()
	json.NewEncoder(w).Encode(threats)
}

func handleAlerts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	alerts := threatDetector.GetAlerts()
	json.NewEncoder(w).Encode(alerts)
}

func handleAgentMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	var metrics SystemMetrics
	if err := json.NewDecoder(r.Body).Decode(&metrics); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	log.Printf("📊 收到代理指标: %s - CPU: %.1f%%, 内存: %.1f%%", 
		metrics.ServerName, metrics.CPU, metrics.Memory)

	// Broadcast to WebSocket clients
	broadcastToClients(WebSocketMessage{
		Type:    "agent_metrics",
		Payload: metrics,
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// WebSocket handler
func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("❌ WebSocket升级失败: %v", err)
		return
	}
	defer conn.Close()

	// Add connection to pool
	<-wsConnectionsMu
	wsConnections[conn] = true
	wsConnectionsMu <- true

	log.Printf("🔌 新的WebSocket连接: %s", r.RemoteAddr)

	// Send initial data
	if metrics, err := dataCollector.GetSystemMetrics(); err == nil {
		conn.WriteJSON(WebSocketMessage{
			Type:    "system_metrics",
			Payload: metrics,
		})
	}

	// Keep connection alive and handle messages
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			log.Printf("🔌 WebSocket连接断开: %v", err)
			break
		}
	}

	// Remove connection from pool
	<-wsConnectionsMu
	delete(wsConnections, conn)
	wsConnectionsMu <- true
}

// Background tasks
func broadcastMetrics() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		metrics, err := dataCollector.GetSystemMetrics()
		if err != nil {
			log.Printf("❌ 获取系统指标失败: %v", err)
			continue
		}

		broadcastToClients(WebSocketMessage{
			Type:    "system_metrics",
			Payload: metrics,
		})
	}
}

func cleanupOldThreats() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		threatDetector.ClearOldThreats(24 * time.Hour)
	}
}

func broadcastToClients(message WebSocketMessage) {
	<-wsConnectionsMu
	defer func() { wsConnectionsMu <- true }()

	for conn := range wsConnections {
		if err := conn.WriteJSON(message); err != nil {
			log.Printf("❌ WebSocket发送失败: %v", err)
			conn.Close()
			delete(wsConnections, conn)
		}
	}
}

// Middleware
func corsMiddleware(next http.Handler) http.Handler {
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
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		clientIP := getClientIP(r)

		// Use a response writer wrapper to capture status code
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)

		duration := time.Since(start)
		
		// Only log non-static file requests to reduce noise
		if !strings.HasPrefix(r.URL.Path, "/_next/") && 
		   !strings.HasSuffix(r.URL.Path, ".js") && 
		   !strings.HasSuffix(r.URL.Path, ".css") && 
		   !strings.HasSuffix(r.URL.Path, ".ico") {
			log.Printf("🌐 [%s] %s %s %d %v", clientIP, r.Method, r.URL.Path, rw.statusCode, duration)
		}

		// Threat detection for suspicious requests
		if !strings.HasPrefix(r.URL.Path, "/api/") && 
		   !strings.HasPrefix(r.URL.Path, "/ws") && 
		   r.URL.Path != "/" && 
		   !strings.HasPrefix(r.URL.Path, "/_next/") {
			
			httpReq := HTTPRequest{
				Method:     r.Method,
				Path:       r.URL.Path,
				IP:         clientIP,
				UserAgent:  r.UserAgent(),
				StatusCode: rw.statusCode,
				Size:       0, // Could be implemented if needed
				Timestamp:  time.Now(),
			}
			
			if isThreat, threat := threatDetector.AnalyzeHTTPRequest(httpReq); isThreat && threat != nil {
				broadcastMessage("NEW_THREAT", *threat)
			}
		}
	})
}

// Helper functions
func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.Split(xff, ",")[0]
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

type WebSocketMessage struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

type SystemMetrics struct {
	ServerName string  `json:"server_name"`
	CPU        float64 `json:"cpu"`
	Memory     float64 `json:"memory"`
}

type HTTPRequest struct {
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	IP         string    `json:"ip"`
	UserAgent  string    `json:"user_agent"`
	StatusCode int       `json:"status_code"`
	Size       int       `json:"size"`
	Timestamp  time.Time `json:"timestamp"`
}
