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
	dataCollector  *RealDataCollector
	threatDetector *ThreatDetector
	upgrader       = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // 允许所有来源的WebSocket连接
		},
	}
)

func main() {
	log.Println("🚀 启动网络监控系统...")

	// 初始化组件
	dataCollector = NewRealDataCollector()
	threatDetector = NewThreatDetector()

	// 启动组件
	dataCollector.Start()
	threatDetector.Start()

	// 设置路由
	router := mux.NewRouter()

	// API路由
	api := router.PathPrefix("/api").Subrouter()
	api.HandleFunc("/metrics", handleMetrics).Methods("GET")
	api.HandleFunc("/threats", handleThreats).Methods("GET")
	api.HandleFunc("/connections", handleConnections).Methods("GET")
	api.HandleFunc("/processes", handleProcesses).Methods("GET")
	api.HandleFunc("/system", handleSystemInfo).Methods("GET")
	api.HandleFunc("/ws", handleWebSocket)

	// 静态文件服务
	staticDir := "./static"
	if _, err := os.Stat(staticDir); os.IsNotExist(err) {
		staticDir = "."
	}
	router.PathPrefix("/").Handler(http.FileServer(http.Dir(staticDir)))

	// 设置CORS
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"*"},
	})

	handler := c.Handler(router)

	// 启动HTTP服务器
	port := "8080"
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}

	server := &http.Server{
		Addr:    ":" + port,
		Handler: handler,
	}

	// 优雅关闭
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Println("🛑 正在关闭服务器...")
		if err := server.Close(); err != nil {
			log.Printf("服务器关闭错误: %v", err)
		}
	}()

	log.Printf("🌐 服务器启动在端口 %s", port)
	log.Printf("📊 访问 http://localhost:%s 查看监控面板", port)

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("服务器启动失败: %v", err)
	}

	log.Println("✅ 服务器已关闭")
}

// handleMetrics 处理系统指标请求
func handleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics, err := dataCollector.GetSystemMetrics()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// handleThreats 处理威胁信息请求
func handleThreats(w http.ResponseWriter, r *http.Request) {
	threats := threatDetector.GetThreats()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(threats)
}

// handleConnections 处理网络连接请求
func handleConnections(w http.ResponseWriter, r *http.Request) {
	connections, err := dataCollector.GetNetworkConnections()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(connections)
}

// handleProcesses 处理进程信息请求
func handleProcesses(w http.ResponseWriter, r *http.Request) {
	data := dataCollector.GetSystemData()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data.Processes)
}

// handleSystemInfo 处理系统信息请求
func handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	data := dataCollector.GetSystemData()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data.SystemInfo)
}

// handleWebSocket 处理WebSocket连接
func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket升级失败: %v", err)
		return
	}
	defer conn.Close()

	log.Println("🔌 新的WebSocket连接")

	// 发送实时数据
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// 获取系统数据
			systemData := dataCollector.GetSystemData()
			
			// 检测威胁
			threats := threatDetector.DetectThreats(systemData)
			
			// 构建响应数据
			response := map[string]interface{}{
				"timestamp": time.Now().Format(time.RFC3339),
				"system":    systemData,
				"threats":   threats,
				"stats":     dataCollector.GetNetworkStats(),
			}

			// 发送数据
			if err := conn.WriteJSON(response); err != nil {
				log.Printf("WebSocket写入错误: %v", err)
				return
			}

		default:
			// 检查连接是否还活着
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Printf("WebSocket ping失败: %v", err)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// ensureStaticFiles 确保静态文件存在
func ensureStaticFiles() {
	staticDir := "./static"
	if err := os.MkdirAll(staticDir, 0755); err != nil {
		log.Printf("创建静态文件目录失败: %v", err)
		return
	}

	indexFile := filepath.Join(staticDir, "index.html")
	if _, err := os.Stat(indexFile); os.IsNotExist(err) {
		// 创建基本的HTML文件
		html := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>网络监控系统</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .card { background: #f5f5f5; padding: 20px; margin: 10px 0; border-radius: 5px; }
        .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
        .metric { background: white; padding: 15px; border-radius: 5px; text-align: center; }
        .metric h3 { margin: 0 0 10px 0; color: #333; }
        .metric .value { font-size: 2em; font-weight: bold; color: #007bff; }
        .status { padding: 5px 10px; border-radius: 3px; color: white; }
        .status.healthy { background: #28a745; }
        .status.warning { background: #ffc107; }
        .status.critical { background: #dc3545; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🖥️ 网络监控系统</h1>
        
        <div class="card">
            <h2>系统状态</h2>
            <div id="status" class="status healthy">系统正常</div>
        </div>

        <div class="card">
            <h2>系统指标</h2>
            <div class="metrics" id="metrics">
                <div class="metric">
                    <h3>CPU使用率</h3>
                    <div class="value" id="cpu">0%</div>
                </div>
                <div class="metric">
                    <h3>内存使用率</h3>
                    <div class="value" id="memory">0%</div>
                </div>
                <div class="metric">
                    <h3>磁盘使用率</h3>
                    <div class="value" id="disk">0%</div>
                </div>
                <div class="metric">
                    <h3>网络连接</h3>
                    <div class="value" id="connections">0</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>威胁检测</h2>
            <div id="threats">暂无威胁</div>
        </div>
    </div>

    <script>
        // 获取系统指标
        function updateMetrics() {
            fetch('/api/metrics')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('cpu').textContent = data.cpu.toFixed(1) + '%';
                    document.getElementById('memory').textContent = data.memory.toFixed(1) + '%';
                    document.getElementById('disk').textContent = data.disk.toFixed(1) + '%';
                    document.getElementById('connections').textContent = data.network.connections;
                    
                    // 更新状态
                    const statusEl = document.getElementById('status');
                    statusEl.textContent = data.status === 'healthy' ? '系统正常' : 
                                          data.status === 'warning' ? '系统警告' : '系统异常';
                    statusEl.className = 'status ' + data.status;
                })
                .catch(error => console.error('获取指标失败:', error));
        }

        // 获取威胁信息
        function updateThreats() {
            fetch('/api/threats')
                .then(response => response.json())
                .then(data => {
                    const threatsEl = document.getElementById('threats');
                    if (data.length === 0) {
                        threatsEl.innerHTML = '暂无威胁';
                    } else {
                        threatsEl.innerHTML = data.map(threat => 
                            '<div style="margin: 5px 0; padding: 10px; background: #fff3cd; border-left: 4px solid #ffc107;">' +
                            '<strong>' + threat.type + '</strong> - ' + threat.description +
                            '</div>'
                        ).join('');
                    }
                })
                .catch(error => console.error('获取威胁信息失败:', error));
        }

        // 定期更新数据
        updateMetrics();
        updateThreats();
        setInterval(updateMetrics, 2000);
        setInterval(updateThreats, 5000);
    </script>
</body>
</html>`

		if err := os.WriteFile(indexFile, []byte(html), 0644); err != nil {
			log.Printf("创建index.html失败: %v", err)
		}
	}
}

func init() {
	ensureStaticFiles()
}
