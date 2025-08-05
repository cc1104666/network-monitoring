"use client"

import { useState, useEffect } from "react"
import {
  AlertTriangle,
  Activity,
  Shield,
  Server,
  Eye,
  Bell,
  TrendingUp,
  Zap,
  ChevronDown,
  ChevronRight,
  Copy,
} from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Progress } from "@/components/ui/progress"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

// 模拟数据生成
const generateTrafficData = () => {
  return Array.from({ length: 20 }, (_, i) => ({
    time: new Date(Date.now() - (19 - i) * 30000).toLocaleTimeString(),
    requests: Math.floor(Math.random() * 1000) + 200,
    threats: Math.floor(Math.random() * 10),
  }))
}

const generateServerData = () => {
  return [
    { id: "web-01", name: "Web Server 01", ip: "192.168.1.10", status: "healthy", cpu: 45, memory: 62, requests: 1250 },
    { id: "web-02", name: "Web Server 02", ip: "192.168.1.11", status: "warning", cpu: 78, memory: 85, requests: 890 },
    { id: "api-01", name: "API Server 01", ip: "192.168.1.20", status: "healthy", cpu: 32, memory: 48, requests: 2100 },
    { id: "db-01", name: "Database 01", ip: "192.168.1.30", status: "critical", cpu: 92, memory: 95, requests: 450 },
  ]
}

const generateApiEndpoints = () => {
  return [
    { endpoint: "/api/users", requests: 15420, avgResponse: 120, status: "normal" },
    { endpoint: "/api/login", requests: 8950, avgResponse: 250, status: "suspicious" },
    { endpoint: "/api/data", requests: 25600, avgResponse: 80, status: "normal" },
    { endpoint: "/api/upload", requests: 3200, avgResponse: 1200, status: "normal" },
    { endpoint: "/api/search", requests: 45000, avgResponse: 300, status: "alert" },
  ]
}

const generateThreatAlerts = () => {
  return [
    {
      id: 1,
      type: "DDoS Attack",
      severity: "critical",
      endpoint: "/api/search",
      requests: 45000,
      timeWindow: "5分钟",
      source: "多个IP地址",
      timestamp: new Date(Date.now() - 120000),
    },
    {
      id: 2,
      type: "Brute Force",
      severity: "high",
      endpoint: "/api/login",
      requests: 8950,
      timeWindow: "10分钟",
      source: "203.45.67.89",
      timestamp: new Date(Date.now() - 300000),
    },
    {
      id: 3,
      type: "Rate Limit Exceeded",
      severity: "medium",
      endpoint: "/api/users",
      requests: 15420,
      timeWindow: "1分钟",
      source: "192.168.1.100",
      timestamp: new Date(Date.now() - 600000),
    },
  ]
}

const generateDetailedRequests = () => {
  const requests = [
    {
      id: 1,
      timestamp: new Date(Date.now() - 300000),
      ip: "203.45.67.89",
      method: "POST",
      endpoint: "/api/login",
      statusCode: 401,
      responseTime: 245,
      userAgent: "Mozilla/5.0 (compatible; Bot/1.0)",
      country: "俄罗斯",
      isSuspicious: true,
      requestHeaders: {
        Host: "api.example.com",
        "User-Agent": "Mozilla/5.0 (compatible; Bot/1.0)",
        Accept: "application/json",
        "Content-Type": "application/json",
        "Content-Length": "45",
        "X-Forwarded-For": "203.45.67.89",
        "X-Real-IP": "203.45.67.89",
      },
      requestBody: JSON.stringify(
        {
          username: "admin",
          password: "123456",
        },
        null,
        2,
      ),
      responseHeaders: {
        "Content-Type": "application/json",
        "Content-Length": "87",
        "X-RateLimit-Remaining": "0",
        "X-RateLimit-Reset": "1640995200",
        Server: "nginx/1.18.0",
      },
      responseBody: JSON.stringify(
        {
          error: "Invalid credentials",
          code: 401,
          message: "用户名或密码错误",
        },
        null,
        2,
      ),
      requestSize: 45,
      responseSize: 87,
      referer: "-",
      cookies: "session_id=abc123; csrf_token=xyz789",
    },
    {
      id: 2,
      timestamp: new Date(Date.now() - 280000),
      ip: "203.45.67.89",
      method: "POST",
      endpoint: "/api/login",
      statusCode: 429,
      responseTime: 156,
      userAgent: "Mozilla/5.0 (compatible; Bot/1.0)",
      country: "俄罗斯",
      isSuspicious: true,
      requestHeaders: {
        Host: "api.example.com",
        "User-Agent": "Mozilla/5.0 (compatible; Bot/1.0)",
        Accept: "application/json",
        "Content-Type": "application/json",
        "Content-Length": "47",
        "X-Forwarded-For": "203.45.67.89",
        "X-Real-IP": "203.45.67.89",
      },
      requestBody: JSON.stringify(
        {
          username: "admin",
          password: "password",
        },
        null,
        2,
      ),
      responseHeaders: {
        "Content-Type": "application/json",
        "Content-Length": "95",
        "X-RateLimit-Remaining": "0",
        "X-RateLimit-Reset": "1640995200",
        "Retry-After": "60",
        Server: "nginx/1.18.0",
      },
      responseBody: JSON.stringify(
        {
          error: "Too Many Requests",
          code: 429,
          message: "请求过于频繁，请稍后再试",
          retry_after: 60,
        },
        null,
        2,
      ),
      requestSize: 47,
      responseSize: 95,
      referer: "-",
      cookies: "session_id=abc123; csrf_token=xyz789",
    },
    {
      id: 3,
      timestamp: new Date(Date.now() - 260000),
      ip: "192.168.1.100",
      method: "GET",
      endpoint: "/api/login",
      statusCode: 200,
      responseTime: 89,
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      country: "中国",
      isSuspicious: false,
      requestHeaders: {
        Host: "api.example.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding": "gzip, deflate",
        Referer: "https://example.com/login",
        Cookie: "session_id=def456; csrf_token=abc123",
      },
      requestBody: "",
      responseHeaders: {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Length": "2048",
        "Set-Cookie": "session_id=def456; Path=/; HttpOnly",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        Server: "nginx/1.18.0",
      },
      responseBody: `<!DOCTYPE html>
<html>
<head>
    <title>登录页面</title>
    <meta charset="utf-8">
</head>
<body>
    <form action="/api/login" method="post">
        <input type="text" name="username" placeholder="用户名">
        <input type="password" name="password" placeholder="密码">
        <button type="submit">登录</button>
    </form>
</body>
</html>`,
      requestSize: 0,
      responseSize: 2048,
      referer: "https://example.com/login",
      cookies: "session_id=def456; csrf_token=abc123",
    },
  ]

  return requests
}

export default function NetworkMonitoringSystem() {
  const [trafficData, setTrafficData] = useState(generateTrafficData())
  const [serverData, setServerData] = useState(generateServerData())
  const [apiEndpoints, setApiEndpoints] = useState(generateApiEndpoints())
  const [threatAlerts, setThreatAlerts] = useState(generateThreatAlerts())
  const [currentTime, setCurrentTime] = useState(new Date())
  const [selectedThreat, setSelectedThreat] = useState(null)
  const [showRequestModal, setShowRequestModal] = useState(false)
  const [detailedRequests, setDetailedRequests] = useState(generateDetailedRequests())
  const [expandedRequest, setExpandedRequest] = useState(null)

  // 模拟实时数据更新
  useEffect(() => {
    const interval = setInterval(() => {
      setTrafficData((prev) => {
        const newData = [...prev.slice(1)]
        newData.push({
          time: new Date().toLocaleTimeString(),
          requests: Math.floor(Math.random() * 1000) + 200,
          threats: Math.floor(Math.random() * 10),
        })
        return newData
      })
      setCurrentTime(new Date())
    }, 3000)

    return () => clearInterval(interval)
  }, [])

  const totalRequests = trafficData.reduce((sum, data) => sum + data.requests, 0)
  const totalThreats = trafficData.reduce((sum, data) => sum + data.threats, 0)
  const activeAlerts = threatAlerts.filter((alert) => alert.severity === "critical" || alert.severity === "high").length

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text)
  }

  return (
    <div className="min-h-screen bg-slate-950 text-white p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-600 rounded-lg">
              <Eye className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold">天眼网络监控系统</h1>
              <p className="text-slate-400">实时流量监控与威胁感知平台</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-right">
              <div className="text-sm text-slate-400">系统时间</div>
              <div className="font-mono">{currentTime.toLocaleString()}</div>
            </div>
            <Button variant="outline" size="sm" className="gap-2 bg-transparent">
              <Bell className="w-4 h-4" />
              告警中心
            </Button>
          </div>
        </div>

        {/* 关键指标 */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card className="bg-slate-900 border-slate-800">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-slate-400">总请求数</CardTitle>
              <Activity className="h-4 w-4 text-blue-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{totalRequests.toLocaleString()}</div>
              <p className="text-xs text-green-400 flex items-center gap-1">
                <TrendingUp className="w-3 h-3" />
                +12.5% 较上小时
              </p>
            </CardContent>
          </Card>

          <Card className="bg-slate-900 border-slate-800">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-slate-400">威胁检测</CardTitle>
              <Shield className="h-4 w-4 text-red-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{totalThreats}</div>
              <p className="text-xs text-red-400 flex items-center gap-1">
                <AlertTriangle className="w-3 h-3" />
                {activeAlerts} 个高危告警
              </p>
            </CardContent>
          </Card>

          <Card className="bg-slate-900 border-slate-800">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-slate-400">在线服务器</CardTitle>
              <Server className="h-4 w-4 text-green-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">
                {serverData.filter((s) => s.status === "healthy").length}/{serverData.length}
              </div>
              <p className="text-xs text-slate-400">
                {serverData.filter((s) => s.status === "critical").length} 个异常
              </p>
            </CardContent>
          </Card>

          <Card className="bg-slate-900 border-slate-800">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-slate-400">平均响应时间</CardTitle>
              <Zap className="h-4 w-4 text-yellow-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">245ms</div>
              <p className="text-xs text-green-400">优秀 (-15ms)</p>
            </CardContent>
          </Card>
        </div>

        {/* 威胁告警 */}
        {threatAlerts.filter((alert) => alert.severity === "critical").length > 0 && (
          <Alert className="border-red-500 bg-red-950/50">
            <AlertTriangle className="h-4 w-4 text-red-400" />
            <AlertTitle className="text-red-400">紧急威胁告警</AlertTitle>
            <AlertDescription className="text-red-300">
              检测到 {threatAlerts.filter((alert) => alert.severity === "critical").length} 个严重威胁，请立即处理！
            </AlertDescription>
          </Alert>
        )}

        <Tabs defaultValue="overview" className="space-y-4">
          <TabsList className="bg-slate-900 border-slate-800">
            <TabsTrigger value="overview">总览</TabsTrigger>
            <TabsTrigger value="traffic">流量监控</TabsTrigger>
            <TabsTrigger value="servers">服务器状态</TabsTrigger>
            <TabsTrigger value="threats">威胁分析</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* 实时流量图表 */}
              <Card className="bg-slate-900 border-slate-800">
                <CardHeader>
                  <CardTitle className="text-white">实时流量监控</CardTitle>
                  <CardDescription>过去10分钟的请求量变化</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="h-64 flex items-end justify-between gap-1">
                    {trafficData.map((data, index) => (
                      <div key={index} className="flex flex-col items-center gap-1 flex-1">
                        <div
                          className="bg-blue-500 w-full rounded-t transition-all duration-300"
                          style={{ height: `${(data.requests / 1200) * 100}%` }}
                        />
                        <div className="text-xs text-slate-400 rotate-45 origin-left">
                          {data.time.split(":").slice(1).join(":")}
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* API接口监控 */}
              <Card className="bg-slate-900 border-slate-800">
                <CardHeader>
                  <CardTitle className="text-white">API接口监控</CardTitle>
                  <CardDescription>热门接口请求统计</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  {apiEndpoints.map((api, index) => (
                    <div key={index} className="flex items-center justify-between p-3 bg-slate-800 rounded-lg">
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <code className="text-sm text-blue-400">{api.endpoint}</code>
                          <Badge
                            variant={
                              api.status === "alert"
                                ? "destructive"
                                : api.status === "suspicious"
                                  ? "secondary"
                                  : "outline"
                            }
                            className="text-xs"
                          >
                            {api.status === "alert" ? "告警" : api.status === "suspicious" ? "可疑" : "正常"}
                          </Badge>
                        </div>
                        <div className="text-xs text-slate-400 mt-1">
                          {api.requests.toLocaleString()} 请求 | 平均 {api.avgResponse}ms
                        </div>
                      </div>
                      <div className="text-right">
                        <div className="text-sm font-medium text-white">{api.requests.toLocaleString()}</div>
                      </div>
                    </div>
                  ))}
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="traffic" className="space-y-4">
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white">详细流量分析</CardTitle>
                <CardDescription>实时网络流量监控与分析</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-96 flex items-end justify-between gap-2">
                  {trafficData.map((data, index) => (
                    <div key={index} className="flex flex-col items-center gap-2 flex-1">
                      <div className="text-xs text-white font-medium">{data.requests}</div>
                      <div
                        className="bg-gradient-to-t from-blue-600 to-blue-400 w-full rounded-t transition-all duration-500"
                        style={{ height: `${(data.requests / 1200) * 80}%` }}
                      />
                      <div className="text-xs text-slate-400">{data.time}</div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="servers" className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {serverData.map((server) => (
                <Card key={server.id} className="bg-slate-900 border-slate-800">
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-white">{server.name}</CardTitle>
                      <Badge
                        variant={
                          server.status === "healthy"
                            ? "outline"
                            : server.status === "warning"
                              ? "secondary"
                              : "destructive"
                        }
                      >
                        {server.status === "healthy" ? "正常" : server.status === "warning" ? "警告" : "异常"}
                      </Badge>
                    </div>
                    <CardDescription>{server.ip}</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div>
                      <div className="flex justify-between text-sm mb-1">
                        <span className="text-slate-400">CPU使用率</span>
                        <span className="text-white">{server.cpu}%</span>
                      </div>
                      <Progress value={server.cpu} className="h-2" />
                    </div>
                    <div>
                      <div className="flex justify-between text-sm mb-1">
                        <span className="text-slate-400">内存使用率</span>
                        <span className="text-white">{server.memory}%</span>
                      </div>
                      <Progress value={server.memory} className="h-2" />
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-slate-400">当前请求数</span>
                      <span className="text-white">{server.requests.toLocaleString()}</span>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </TabsContent>

          <TabsContent value="threats" className="space-y-4">
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white">威胁告警列表</CardTitle>
                <CardDescription>实时威胁检测与告警信息</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {threatAlerts.map((alert) => (
                  <div key={alert.id} className="p-4 bg-slate-800 rounded-lg border-l-4 border-l-red-500">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-2">
                          <AlertTriangle className="w-4 h-4 text-red-400" />
                          <span className="font-medium text-white">{alert.type}</span>
                          <Badge
                            variant={
                              alert.severity === "critical"
                                ? "destructive"
                                : alert.severity === "high"
                                  ? "secondary"
                                  : "outline"
                            }
                          >
                            {alert.severity === "critical" ? "严重" : alert.severity === "high" ? "高危" : "中等"}
                          </Badge>
                        </div>
                        <div className="space-y-1 text-sm text-slate-300">
                          <div>
                            目标接口: <code className="text-blue-400">{alert.endpoint}</code>
                          </div>
                          <div>
                            请求数量:{" "}
                            <span className="text-red-400 font-medium">{alert.requests.toLocaleString()}</span> 次/
                            {alert.timeWindow}
                          </div>
                          <div>
                            来源: <span className="text-yellow-400">{alert.source}</span>
                          </div>
                          <div>检测时间: {alert.timestamp.toLocaleString()}</div>
                        </div>
                      </div>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          setSelectedThreat(alert)
                          setShowRequestModal(true)
                        }}
                      >
                        查看详情
                      </Button>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        {/* 完整请求详情模态框 */}
        {showRequestModal && selectedThreat && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
            <div className="bg-slate-900 rounded-lg max-w-7xl w-full max-h-[95vh] overflow-hidden">
              <div className="p-6 border-b border-slate-700">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-xl font-bold text-white">威胁详情分析</h2>
                    <p className="text-slate-400 mt-1">
                      {selectedThreat.type} - {selectedThreat.endpoint}
                    </p>
                  </div>
                  <Button variant="outline" size="sm" onClick={() => setShowRequestModal(false)}>
                    关闭
                  </Button>
                </div>
              </div>

              <div className="p-6 overflow-y-auto max-h-[calc(95vh-120px)]">
                {/* 威胁概览 */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
                  <Card className="bg-slate-800 border-slate-700">
                    <CardHeader>
                      <CardTitle className="text-white text-sm">威胁概览</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div className="flex justify-between">
                        <span className="text-slate-400">威胁类型</span>
                        <span className="text-white">{selectedThreat.type}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">严重程度</span>
                        <Badge variant={selectedThreat.severity === "critical" ? "destructive" : "secondary"}>
                          {selectedThreat.severity === "critical" ? "严重" : "高危"}
                        </Badge>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">请求总数</span>
                        <span className="text-red-400 font-medium">{selectedThreat.requests.toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">时间窗口</span>
                        <span className="text-white">{selectedThreat.timeWindow}</span>
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="bg-slate-800 border-slate-700">
                    <CardHeader>
                      <CardTitle className="text-white text-sm">IP地址分析</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div className="space-y-2">
                        <div className="flex justify-between items-center">
                          <span className="text-slate-400">203.45.67.89</span>
                          <div className="flex items-center gap-2">
                            <span className="text-red-400">15,420</span>
                            <Badge variant="destructive" className="text-xs">
                              高危
                            </Badge>
                          </div>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-slate-400">192.168.1.100</span>
                          <div className="flex items-center gap-2">
                            <span className="text-yellow-400">8,950</span>
                            <Badge variant="secondary" className="text-xs">
                              可疑
                            </Badge>
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="bg-slate-800 border-slate-700">
                    <CardHeader>
                      <CardTitle className="text-white text-sm">请求模式分析</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div className="flex justify-between">
                        <span className="text-slate-400">请求频率</span>
                        <span className="text-red-400">3000/分钟</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">成功率</span>
                        <span className="text-white">15%</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">平均响应时间</span>
                        <span className="text-white">245ms</span>
                      </div>
                    </CardContent>
                  </Card>
                </div>

                {/* 详细请求日志 */}
                <Card className="bg-slate-800 border-slate-700">
                  <CardHeader>
                    <CardTitle className="text-white">详细请求日志</CardTitle>
                    <CardDescription>完整的HTTP请求和响应信息</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      {detailedRequests.map((request) => (
                        <div
                          key={request.id}
                          className={`border rounded-lg ${request.isSuspicious ? "border-red-500 bg-red-950/10" : "border-slate-600"}`}
                        >
                          {/* 请求概览 */}
                          <div
                            className="p-4 cursor-pointer hover:bg-slate-700/50 transition-colors"
                            onClick={() => setExpandedRequest(expandedRequest === request.id ? null : request.id)}
                          >
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-4">
                                {expandedRequest === request.id ? (
                                  <ChevronDown className="w-4 h-4" />
                                ) : (
                                  <ChevronRight className="w-4 h-4" />
                                )}
                                <div className="flex items-center gap-2">
                                  <Badge variant="outline" className="text-xs">
                                    {request.method}
                                  </Badge>
                                  <code className="text-blue-400">{request.endpoint}</code>
                                  <Badge
                                    variant={request.statusCode >= 400 ? "destructive" : "outline"}
                                    className="text-xs"
                                  >
                                    {request.statusCode}
                                  </Badge>
                                </div>
                              </div>
                              <div className="flex items-center gap-4 text-sm">
                                <span className="text-slate-400">{request.timestamp.toLocaleTimeString()}</span>
                                <span className="text-blue-400 font-mono">{request.ip}</span>
                                <span className="text-slate-300">{request.responseTime}ms</span>
                                {request.isSuspicious && (
                                  <Badge variant="destructive" className="text-xs">
                                    可疑
                                  </Badge>
                                )}
                              </div>
                            </div>
                          </div>

                          {/* 展开的详细信息 */}
                          {expandedRequest === request.id && (
                            <div className="border-t border-slate-600">
                              <Tabs defaultValue="request" className="w-full">
                                <TabsList className="w-full bg-slate-700 m-4 mb-0">
                                  <TabsTrigger value="request" className="flex-1">
                                    请求信息
                                  </TabsTrigger>
                                  <TabsTrigger value="response" className="flex-1">
                                    响应信息
                                  </TabsTrigger>
                                  <TabsTrigger value="headers" className="flex-1">
                                    请求头
                                  </TabsTrigger>
                                  <TabsTrigger value="analysis" className="flex-1">
                                    风险分析
                                  </TabsTrigger>
                                </TabsList>

                                <TabsContent value="request" className="p-4">
                                  <div className="space-y-4">
                                    <div>
                                      <div className="flex items-center justify-between mb-2">
                                        <h4 className="text-sm font-medium text-white">请求基本信息</h4>
                                      </div>
                                      <div className="bg-slate-900 p-3 rounded text-sm space-y-2">
                                        <div className="flex justify-between">
                                          <span className="text-slate-400">请求方法:</span>
                                          <span className="text-white">{request.method}</span>
                                        </div>
                                        <div className="flex justify-between">
                                          <span className="text-slate-400">请求路径:</span>
                                          <span className="text-blue-400 font-mono">{request.endpoint}</span>
                                        </div>
                                        <div className="flex justify-between">
                                          <span className="text-slate-400">来源IP:</span>
                                          <span className="text-white font-mono">{request.ip}</span>
                                        </div>
                                        <div className="flex justify-between">
                                          <span className="text-slate-400">地理位置:</span>
                                          <span className="text-white">{request.country}</span>
                                        </div>
                                        <div className="flex justify-between">
                                          <span className="text-slate-400">请求大小:</span>
                                          <span className="text-white">{request.requestSize} bytes</span>
                                        </div>
                                      </div>
                                    </div>

                                    {request.requestBody && (
                                      <div>
                                        <div className="flex items-center justify-between mb-2">
                                          <h4 className="text-sm font-medium text-white">请求体</h4>
                                          <Button
                                            variant="outline"
                                            size="sm"
                                            onClick={() => copyToClipboard(request.requestBody)}
                                            className="h-6 px-2"
                                          >
                                            <Copy className="w-3 h-3" />
                                          </Button>
                                        </div>
                                        <pre className="bg-slate-900 p-3 rounded text-xs overflow-x-auto">
                                          <code className="text-green-400">{request.requestBody}</code>
                                        </pre>
                                      </div>
                                    )}
                                  </div>
                                </TabsContent>

                                <TabsContent value="response" className="p-4">
                                  <div className="space-y-4">
                                    <div>
                                      <h4 className="text-sm font-medium text-white mb-2">响应信息</h4>
                                      <div className="bg-slate-900 p-3 rounded text-sm space-y-2">
                                        <div className="flex justify-between">
                                          <span className="text-slate-400">状态码:</span>
                                          <Badge variant={request.statusCode >= 400 ? "destructive" : "outline"}>
                                            {request.statusCode}
                                          </Badge>
                                        </div>
                                        <div className="flex justify-between">
                                          <span className="text-slate-400">响应时间:</span>
                                          <span className="text-white">{request.responseTime}ms</span>
                                        </div>
                                        <div className="flex justify-between">
                                          <span className="text-slate-400">响应大小:</span>
                                          <span className="text-white">{request.responseSize} bytes</span>
                                        </div>
                                      </div>
                                    </div>

                                    <div>
                                      <div className="flex items-center justify-between mb-2">
                                        <h4 className="text-sm font-medium text-white">响应头</h4>
                                        <Button
                                          variant="outline"
                                          size="sm"
                                          onClick={() =>
                                            copyToClipboard(JSON.stringify(request.responseHeaders, null, 2))
                                          }
                                          className="h-6 px-2"
                                        >
                                          <Copy className="w-3 h-3" />
                                        </Button>
                                      </div>
                                      <div className="bg-slate-900 p-3 rounded text-xs space-y-1">
                                        {Object.entries(request.responseHeaders).map(([key, value]) => (
                                          <div key={key} className="flex">
                                            <span className="text-blue-400 w-40 flex-shrink-0">{key}:</span>
                                            <span className="text-white">{value}</span>
                                          </div>
                                        ))}
                                      </div>
                                    </div>

                                    <div>
                                      <div className="flex items-center justify-between mb-2">
                                        <h4 className="text-sm font-medium text-white">响应体</h4>
                                        <Button
                                          variant="outline"
                                          size="sm"
                                          onClick={() => copyToClipboard(request.responseBody)}
                                          className="h-6 px-2"
                                        >
                                          <Copy className="w-3 h-3" />
                                        </Button>
                                      </div>
                                      <pre className="bg-slate-900 p-3 rounded text-xs overflow-x-auto max-h-40">
                                        <code className="text-yellow-400">{request.responseBody}</code>
                                      </pre>
                                    </div>
                                  </div>
                                </TabsContent>

                                <TabsContent value="headers" className="p-4">
                                  <div className="space-y-4">
                                    <div>
                                      <div className="flex items-center justify-between mb-2">
                                        <h4 className="text-sm font-medium text-white">请求头</h4>
                                        <Button
                                          variant="outline"
                                          size="sm"
                                          onClick={() =>
                                            copyToClipboard(JSON.stringify(request.requestHeaders, null, 2))
                                          }
                                          className="h-6 px-2"
                                        >
                                          <Copy className="w-3 h-3" />
                                        </Button>
                                      </div>
                                      <div className="bg-slate-900 p-3 rounded text-xs space-y-1">
                                        {Object.entries(request.requestHeaders).map(([key, value]) => (
                                          <div key={key} className="flex">
                                            <span className="text-blue-400 w-40 flex-shrink-0">{key}:</span>
                                            <span className="text-white break-all">{value}</span>
                                          </div>
                                        ))}
                                      </div>
                                    </div>

                                    {request.cookies && (
                                      <div>
                                        <h4 className="text-sm font-medium text-white mb-2">Cookies</h4>
                                        <div className="bg-slate-900 p-3 rounded text-xs">
                                          <span className="text-green-400">{request.cookies}</span>
                                        </div>
                                      </div>
                                    )}
                                  </div>
                                </TabsContent>

                                <TabsContent value="analysis" className="p-4">
                                  <div className="space-y-4">
                                    <div>
                                      <h4 className="text-sm font-medium text-white mb-2">风险评估</h4>
                                      <div className="bg-slate-900 p-3 rounded text-sm space-y-2">
                                        <div className="flex justify-between">
                                          <span className="text-slate-400">风险等级:</span>
                                          <Badge variant={request.isSuspicious ? "destructive" : "outline"}>
                                            {request.isSuspicious ? "高危" : "正常"}
                                          </Badge>
                                        </div>
                                        <div className="flex justify-between">
                                          <span className="text-slate-400">User-Agent类型:</span>
                                          <span className="text-white">
                                            {request.userAgent.includes("Bot") ? "机器人" : "正常浏览器"}
                                          </span>
                                        </div>
                                        <div className="flex justify-between">
                                          <span className="text-slate-400">请求频率:</span>
                                          <span className="text-red-400">异常高频</span>
                                        </div>
                                      </div>
                                    </div>

                                    <div>
                                      <h4 className="text-sm font-medium text-white mb-2">威胁指标</h4>
                                      <div className="space-y-2">
                                        {request.isSuspicious && (
                                          <>
                                            <div className="flex items-center gap-2 text-sm">
                                              <AlertTriangle className="w-4 h-4 text-red-400" />
                                              <span className="text-red-400">检测到暴力破解行为</span>
                                            </div>
                                            <div className="flex items-center gap-2 text-sm">
                                              <AlertTriangle className="w-4 h-4 text-yellow-400" />
                                              <span className="text-yellow-400">异常User-Agent</span>
                                            </div>
                                            <div className="flex items-center gap-2 text-sm">
                                              <AlertTriangle className="w-4 h-4 text-red-400" />
                                              <span className="text-red-400">高频请求模式</span>
                                            </div>
                                          </>
                                        )}
                                      </div>
                                    </div>
                                  </div>
                                </TabsContent>
                              </Tabs>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>

                {/* 操作按钮 */}
                <div className="flex gap-4 mt-6">
                  <Button variant="destructive" className="flex-1">
                    <AlertTriangle className="w-4 h-4 mr-2" />
                    确认威胁并封禁IP
                  </Button>
                  <Button variant="outline" className="flex-1 bg-transparent">
                    标记为误报
                  </Button>
                  <Button variant="secondary" className="flex-1">
                    添加白名单
                  </Button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
