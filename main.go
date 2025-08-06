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
	dataCollector  *RealDataCollector
	threatDetector *ThreatDetector
	hub            *Hub
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins for development
		},
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
)

func main() {
	log.Println("🚀 Starting Network Monitoring System...")

	// Initialize components
	dataCollector = NewRealDataCollector()
	threatDetector = NewThreatDetector()
	hub = newHub()
	go hub.run()

	// Start background data collection and broadcasting
	go runDataBroadcaster()

	// Create router with proper ordering
	r := mux.NewRouter()

	// WebSocket endpoint - MUST be defined first and be very specific
	r.HandleFunc("/ws", serveWs).Methods("GET")
	log.Println("📡 WebSocket endpoint registered: /ws")

	// API routes - also very specific, must come before static files
	api := r.PathPrefix("/api").Subrouter()
	api.HandleFunc("/system/info", getSystemInfo).Methods("GET")
	api.HandleFunc("/threats", getThreats).Methods("GET")
	api.HandleFunc("/alerts", getAlerts).Methods("GET")
	log.Println("🔌 API endpoints registered: /api/system/info, /api/threats, /api/alerts")

	// Static file serving - this should be LAST
	staticDir := "./out"
	if err := ensureStaticFiles(staticDir); err != nil {
		log.Printf("⚠️ Warning: %v", err)
	}

	// Serve static files with proper handling
	fs := http.FileServer(http.Dir(staticDir))
	r.PathPrefix("/").Handler(http.StripPrefix("/", fs))
	log.Printf("📁 Static files served from: %s", staticDir)

	// Apply middleware
	r.Use(corsMiddleware)
	r.Use(loggingMiddleware)

	// Server configuration
	server := &http.Server{
		Addr:         ":8080",
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Println("🚀 Network Monitoring System started successfully")
	log.Printf("🌐 Access URL: http://localhost:8080")
	log.Printf("🔌 WebSocket URL: ws://localhost:8080/ws")
	log.Printf("📊 API Base URL: http://localhost:8080/api")

	// Start the server
	if err := server.ListenAndServe(); err != nil {
		log.Fatal("❌ Server startup failed:", err)
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
    <title>Network Monitoring System</title>
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
        <h1>🔍 Network Monitoring System</h1>
        
        <div class="warning">
            <strong>⚠️ Frontend Not Built</strong><br>
            The React frontend has not been built yet. Please run: <code>npm run build</code>
        </div>
        
        <div class="status">
            <strong>✅ Backend Server Running</strong><br>
            The Go backend server is running successfully and ready to serve data.
        </div>
        
        <div class="endpoints">
            <h3>Available Endpoints:</h3>
            <ul>
                <li><strong>WebSocket:</strong> <a href="/ws">/ws</a> (Real-time data stream)</li>
                <li><strong>System Info:</strong> <a href="/api/system/info">/api/system/info</a></li>
                <li><strong>Threats:</strong> <a href="/api/threats">/api/threats</a></li>
                <li><strong>Alerts:</strong> <a href="/api/alerts">/api/alerts</a></li>
            </ul>
        </div>
        
        <div class="status">
            <h3>🔧 Development Instructions:</h3>
            <ol>
                <li>Install Node.js dependencies: <code>npm install</code></li>
                <li>Build the frontend: <code>npm run build</code></li>
                <li>Restart the Go server to serve the built frontend</li>
            </ol>
        </div>
    </div>
    
    <script>
        // Test WebSocket connection
        console.log('Testing WebSocket connection...');
        const ws = new WebSocket('ws://localhost:8080/ws');
        ws.onopen = () => console.log('✅ WebSocket connected successfully');
        ws.onerror = (error) => console.error('❌ WebSocket error:', error);
        ws.onmessage = (event) => console.log('📨 WebSocket message:', event.data);
    </script>
</body>
</html>`

		if err := os.WriteFile(filepath.Join(staticDir, "index.html"), []byte(fallbackHTML), 0644); err != nil {
			return err
		}
		
		log.Printf("✅ Created fallback HTML at %s/index.html", staticDir)
	}
	return nil
}

// serveWs handles websocket requests from clients
func serveWs(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔌 WebSocket connection attempt from %s", r.RemoteAddr)
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("❌ WebSocket upgrade failed: %v", err)
		http.Error(w, "WebSocket upgrade failed", http.StatusBadRequest)
		return
	}

	log.Printf("✅ WebSocket connection established from %s", r.RemoteAddr)
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
					log.Printf("❌ WebSocket error: %v", err)
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
	log.Println("📡 Starting data broadcaster...")
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
			log.Printf("⚠️ Error getting system metrics: %v", err)
		}

		// Network Connections
		if connections, err := dataCollector.GetNetworkConnections(); err == nil {
			broadcastMessage("NETWORK_CONNECTIONS_UPDATE", connections)
		} else {
			log.Printf("⚠️ Error getting network connections: %v", err)
		}

		// Processes
		if processes, err := dataCollector.GetProcesses(); err == nil {
			broadcastMessage("PROCESSES_UPDATE", processes)
		} else {
			log.Printf("⚠️ Error getting processes: %v", err)
		}
	}
}

func broadcastMessage(msgType string, payload interface{}) {
	msg := WebSocketMessage{Type: msgType, Payload: payload}
	if jsonMsg, err := json.Marshal(msg); err == nil {
		select {
		case hub.broadcast <- jsonMsg:
		case <-time.After(time.Second):
			log.Printf("⚠️ Broadcast timeout for message type: %s", msgType)
		}
	} else {
		log.Printf("❌ Error marshalling %s: %v", msgType, err)
	}
}

// API Handlers
func getSystemInfo(w http.ResponseWriter, r *http.Request) {
	log.Printf("📊 API request: %s %s from %s", r.Method, r.URL.Path, getClientIP(r))
	
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	
	data, err := dataCollector.GetSystemInfo()
	if err != nil {
		log.Printf("❌ Error getting system info: %v", err)
		http.Error(w, fmt.Sprintf(`{"error": "%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("❌ Error encoding system info: %v", err)
		http.Error(w, `{"error": "Failed to encode response"}`, http.StatusInternalServerError)
		return
	}
	
	log.Printf("✅ System info sent successfully")
}

func getThreats(w http.ResponseWriter, r *http.Request) {
	log.Printf("🚨 API request: %s %s from %s", r.Method, r.URL.Path, getClientIP(r))
	
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	
	threats := threatDetector.GetThreats()
	
	if err := json.NewEncoder(w).Encode(threats); err != nil {
		log.Printf("❌ Error encoding threats: %v", err)
		http.Error(w, `{"error": "Failed to encode response"}`, http.StatusInternalServerError)
		return
	}
	
	log.Printf("✅ Threats sent successfully (%d threats)", len(threats))
}

func getAlerts(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔔 API request: %s %s from %s", r.Method, r.URL.Path, getClientIP(r))
	
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	
	alerts := threatDetector.GetAlerts()
	
	if err := json.NewEncoder(w).Encode(alerts); err != nil {
		log.Printf("❌ Error encoding alerts: %v", err)
		http.Error(w, `{"error": "Failed to encode response"}`, http.StatusInternalServerError)
		return
	}
	
	log.Printf("✅ Alerts sent successfully (%d alerts)", len(alerts))
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
