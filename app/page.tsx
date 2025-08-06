"use client"

import { useState, useEffect } from "react"
import { AlertTriangle, Activity, Shield, Server, Eye, Bell, TrendingUp, Zap, ChevronDown, ChevronRight, Copy } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Progress } from "@/components/ui/progress"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

// 数据类型定义
interface TrafficStats {
  timestamp: string
  requests: number
  threats: number
  response_time: number
}

interface ServerStatus {
  id: string
  name: string
  ip: string
  status: string
  cpu: number
  memory: number
  requests: number
  last_seen: string
}

interface EndpointStats {
  endpoint: string
  requests: number
  avg_response: number
  status: string
  last_request: string
  request_rate: number
}

interface ThreatAlert {
  id: number
  type: string
  severity: string
  endpoint: string
  requests: number
  time_window: string
  source_ip: string
  timestamp: string
  description: string
  active: boolean
}

interface RequestDetail {
  id: number
  timestamp: string
  ip: string
  method: string
  endpoint: string
  status_code: number
  response_time: number
  user_agent: string
  request_size: number
  response_size: number
  referer: string
  country: string
  is_suspicious: boolean
}

export default function NetworkMonitoringSystem() {
  const [trafficData, setTrafficData] = useState<TrafficStats[]>([])
  const [serverData, setServerData] = useState<ServerStatus[]>([])
  const [apiEndpoints, setApiEndpoints] = useState<EndpointStats[]>([])
  const [threatAlerts, setThreatAlerts] = useState<ThreatAlert[]>([])
  const [requestDetails, setRequestDetails] = useState<RequestDetail[]>([])
  const [currentTime, setCurrentTime] = useState(new Date())
  const [selectedThreat, setSelectedThreat] = useState<ThreatAlert | null>(null)
  const [showRequestModal, setShowRequestModal] = useState(false)
  const [expandedRequest, setExpandedRequest] = useState<number | null>(null)
  const [connectionStatus, setConnectionStatus] = useState<'connecting' | 'connected' | 'disconnected'>('connecting')
  const [wsConnection, setWsConnection] = useState<WebSocket | null>(null)

  // 获取API数据
  const fetchApiData = async () => {
    try {
      // 获取流量统计
      const statsResponse = await fetch('/api/stats')
      if (statsResponse.ok) {
        const statsData = await statsResponse.json()
        if (statsData.success && statsData.data) {
          setTrafficData(statsData.data.slice(-20)) // 保留最近20个数据点
        }
      }

      // 获取服务器状态
      const serversResponse = await fetch('/api/servers')
      if (serversResponse.ok) {
        const serversData = await serversResponse.json()
        if (serversData.success && serversData.data) {
          setServerData(serversData.data)
        }
      }

      // 获取API端点统计
      const endpointsResponse = await fetch('/api/endpoints')
      if (endpointsResponse.ok) {
        const endpointsData = await endpointsResponse.json()
        if (endpointsData.success && endpointsData.data) {
          setApiEndpoints(endpointsData.data)
        }
      }

      // 获取威胁告警
      const threatsResponse = await fetch('/api/threats')
      if (threatsResponse.ok) {
        const threatsData = await threatsResponse.json()
        if (threatsData.success && threatsData.data) {
          setThreatAlerts(threatsData.data)
        }
      }

      // 获取请求详情
      const requestsResponse = await fetch('/api/request-details')
      if (requestsResponse.ok) {
        const requestsData = await requestsResponse.json()
        if (requestsData.success && requestsData.data) {
          setRequestDetails(requestsData.data)
        }
      }

    } catch (error) {
      console.error('获取API数据失败:', error)
    }
  }

  // WebSocket连接
  const connectWebSocket = () => {
    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const wsUrl = `${protocol}//${window.location.host}/ws`
      const ws = new WebSocket(wsUrl)

      ws.onopen = () => {
        console.log('WebSocket连接已建立')
        setConnectionStatus('connected')
        setWsConnection(ws)
      }

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          
          if (data.type === 'update') {
            // 更新所有数据
            if (data.stats) setTrafficData(data.stats.slice(-20))
            if (data.servers) setServerData(data.servers)
            if (data.threats) setThreatAlerts(data.threats)
            if (data.endpoints) setApiEndpoints(data.endpoints)
            if (data.request_details) setRequestDetails(data.request_details)
          } else if (data.type === 'traffic') {
            // 更新流量数据
            setTrafficData(prev => {
              const newData = [...prev, data.data].slice(-20)
              return newData
            })
          } else if (data.type === 'servers') {
            setServerData(data.data)
          } else if (data.type === 'threats') {
            setThreatAlerts(data.data)
          } else if (data.type === 'endpoints') {
            setApiEndpoints(data.data)
          } else if (data.type === 'requests') {
            setRequestDetails(prev => [...data.data, ...prev].slice(0, 100))
          }
        } catch (error) {
          console.error('解析WebSocket消息失败:', error)
        }
      }

      ws.onclose = () => {
        console.log('WebSocket连接已关闭')
        setConnectionStatus('disconnected')
        setWsConnection(null)
        // 5秒后重连
        setTimeout(connectWebSocket, 5000)
      }

      ws.onerror = (error) => {
        console.error('WebSocket连接错误:', error)
        setConnectionStatus('disconnected')
      }

    } catch (error) {
      console.error('创建WebSocket连接失败:', error)
      setConnectionStatus('disconnected')
      // 5秒后重试
      setTimeout(connectWebSocket, 5000)
    }
  }

  // 初始化数据和连接
  useEffect(() => {
    // 首次加载数据
    fetchApiData()
    
    // 建立WebSocket连接
    connectWebSocket()

    // 定时更新时间
    const timeInterval = setInterval(() => {
      setCurrentTime(new Date())
    }, 1000)

    // 如果WebSocket连接失败，使用轮询作为备选方案
    const pollInterval = setInterval(() => {
      if (connectionStatus === 'disconnected') {
        fetchApiData()
      }
    }, 5000)

    return () => {
      clearInterval(timeInterval)
      clearInterval(pollInterval)
      if (wsConnection) {
        wsConnection.close()
      }
    }
  }, [])

  // 处理威胁操作
  const handleThreatAction = async (alertId: number, action: string) => {
    try {
      const response = await fetch(`/api/threats/${alertId}/${action}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ action, alertId })
      })
      
      if (response.ok) {
        // 更新威胁状态
        setThreatAlerts(prev => 
          prev.map(alert => 
            alert.id === alertId 
              ? { ...alert, active: false }
              : alert
          )
        )
        alert(`威胁 ${alertId} 已${action === 'block' ? '封禁' : action === 'whitelist' ? '加入白名单' : '处理'}`)
      } else {
        throw new Error('服务器响应错误')
      }
    } catch (error) {
      console.error('处理威胁失败:', error)
      alert('处理失败，请重试')
    }
  }

  // 刷新数据
  const refreshData = () => {
    fetchApiData()
  }

  // 计算统计数据
  const totalRequests = trafficData.reduce((sum, data) => sum + data.requests, 0)
  const totalThreats = threatAlerts.filter(alert => alert.active).length
  const activeAlerts = threatAlerts.filter((alert) => alert.severity === "critical" || alert.severity === "high").length
  const healthyServers = serverData.filter((s) => s.status === "healthy").length
  const avgResponseTime = trafficData.length > 0 
    ? Math.round(trafficData.reduce((sum, data) => sum + data.response_time, 0) / trafficData.length)
    : 0

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return 'text-green-400'
      case 'warning': return 'text-yellow-400'
      case 'critical': return 'text-red-400'
      default: return 'text-slate-400'
    }
  }

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'critical': return 'destructive'
      case 'high': return 'secondary'
      case 'medium': return 'outline'
      default: return 'outline'
    }
  }

  const getSeverityText = (severity: string) => {
    switch (severity) {
      case 'critical': return '严重'
      case 'high': return '高危'
      case 'medium': return '中等'
      case 'low': return '低危'
      default: return '未知'
    }
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
              <div className="flex items-center gap-2">
                <p className="text-slate-400">实时流量监控与威胁感知平台</p>
                <div className={`flex items-center gap-1 text-xs px-2 py-1 rounded ${
                  connectionStatus === 'connected' ? 'bg-green-900 text-green-400' :
                  connectionStatus === 'connecting' ? 'bg-yellow-900 text-yellow-400' :
                  'bg-red-900 text-red-400'
                }`}>
                  <div className={`w-2 h-2 rounded-full ${
                    connectionStatus === 'connected' ? 'bg-green-400' :
                    connectionStatus === 'connecting' ? 'bg-yellow-400' :
                    'bg-red-400'
                  }`} />
                  {connectionStatus === 'connected' ? '运行中' :
                   connectionStatus === 'connecting' ? '连接中' : '已断开'}
                </div>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-right">
              <div className="text-sm text-slate-400">系统时间</div>
              <div className="font-mono">{currentTime.toLocaleString()}</div>
            </div>
            <Button variant="outline" size="sm" className="gap-2 bg-transparent" onClick={refreshData}>
              <Bell className="w-4 h-4" />
              刷新数据
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
                实时数据
              </p>
            </CardContent>
          </Card>

          <Card className="bg-slate-900 border-slate-800">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-slate-400">活跃威胁</CardTitle>
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
              <CardTitle className="text-sm font-medium text-slate-400">健康服务器</CardTitle>
              <Server className="h-4 w-4 text-green-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">
                {healthyServers}/{serverData.length}
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
              <div className="text-2xl font-bold text-white">{avgResponseTime}ms</div>
              <p className="text-xs text-green-400">实时监控</p>
            </CardContent>
          </Card>
        </div>

        {/* 威胁告警 */}
        {threatAlerts.filter((alert) => alert.severity === "critical" && alert.active).length > 0 && (
          <Alert className="border-red-500 bg-red-950/50">
            <AlertTriangle className="h-4 w-4 text-red-400" />
            <AlertTitle className="text-red-400">紧急威胁告警</AlertTitle>
            <AlertDescription className="text-red-300">
              检测到 {threatAlerts.filter((alert) => alert.severity === "critical" && alert.active).length} 个严重威胁，请立即处理！
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
                    {trafficData.length > 0 ? trafficData.map((data, index) => (
                      <div key={index} className="flex flex-col items-center gap-1 flex-1">
                        <div
                          className="bg-blue-500 w-full rounded-t transition-all duration-300"
                          style={{ height: `${Math.max((data.requests / Math.max(...trafficData.map(d => d.requests), 1)) * 100, 2)}%` }}
                        />
                        <div className="text-xs text-slate-400 rotate-45 origin-left">
                          {new Date(data.timestamp).toLocaleTimeString().split(":").slice(1).join(":")}
                        </div>
                      </div>
                    )) : (
                      <div className="flex items-center justify-center w-full h-full text-slate-400">
                        等待数据加载...
                      </div>
                    )}
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
                  {apiEndpoints.length > 0 ? apiEndpoints.map((api, index) => (
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
                          {api.requests.toLocaleString()} 请求 | 平均 {Math.round(api.avg_response)}ms
                        </div>
                      </div>
                      <div className="text-right">
                        <div className="text-sm font-medium text-white">{api.requests.toLocaleString()}</div>
                      </div>
                    </div>
                  )) : (
                    <div className="text-center text-slate-400 py-8">
                      暂无API端点数据
                    </div>
                  )}
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
                  {trafficData.length > 0 ? trafficData.map((data, index) => (
                    <div key={index} className="flex flex-col items-center gap-2 flex-1">
                      <div className="text-xs text-white font-medium">{data.requests}</div>
                      <div
                        className="bg-gradient-to-t from-blue-600 to-blue-400 w-full rounded-t transition-all duration-500"
                        style={{ height: `${Math.max((data.requests / Math.max(...trafficData.map(d => d.requests), 1)) * 80, 2)}%` }}
                      />
                      <div className="text-xs text-slate-400">
                        {new Date(data.timestamp).toLocaleTimeString()}
                      </div>
                    </div>
                  )) : (
                    <div className="flex items-center justify-center w-full h-full text-slate-400">
                      等待流量数据...
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="servers" className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {serverData.length > 0 ? serverData.map((server) => (
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
                        <span className="text-white">{Math.round(server.cpu)}%</span>
                      </div>
                      <Progress value={server.cpu} className="h-2" />
                    </div>
                    <div>
                      <div className="flex justify-between text-sm mb-1">
                        <span className="text-slate-400">内存使用率</span>
                        <span className="text-white">{Math.round(server.memory)}%</span>
                      </div>
                      <Progress value={server.memory} className="h-2" />
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-slate-400">当前请求数</span>
                      <span className="text-white">{server.requests.toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-slate-400">最后更新</span>
                      <span className="text-white">{new Date(server.last_seen).toLocaleTimeString()}</span>
                    </div>
                  </CardContent>
                </Card>
              )) : (
                <div className="col-span-2 text-center text-slate-400 py-8">
                  暂无服务器数据
                </div>
              )}
            </div>
          </TabsContent>

          <TabsContent value="threats" className="space-y-4">
            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white">威胁告警列表</CardTitle>
                <CardDescription>实时威胁检测与告警信息</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {threatAlerts.length > 0 ? threatAlerts.filter(alert => alert.active).map((alert) => (
                  <div key={alert.id} className="p-4 bg-slate-800 rounded-lg border-l-4 border-l-red-500">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-2">
                          <AlertTriangle className="w-4 h-4 text-red-400" />
                          <span className="font-medium text-white">{alert.type}</span>
                          <Badge variant={getSeverityBadge(alert.severity)}>
                            {getSeverityText(alert.severity)}
                          </Badge>
                        </div>
                        <div className="space-y-1 text-sm text-slate-300">
                          <div>
                            目标接口: <code className="text-blue-400">{alert.endpoint}</code>
                          </div>
                          <div>
                            请求数量:{" "}
                            <span className="text-red-400 font-medium">{alert.requests.toLocaleString()}</span> 次/
                            {alert.time_window}
                          </div>
                          <div>
                            来源: <span className="text-yellow-400">{alert.source_ip}</span>
                          </div>
                          <div>检测时间: {new Date(alert.timestamp).toLocaleString()}</div>
                          <div className="text-slate-400">{alert.description}</div>
                        </div>
                      </div>
                      <div className="flex gap-2">
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
                        <Button
                          variant="destructive"
                          size="sm"
                          onClick={() => handleThreatAction(alert.id, 'block')}
                        >
                          处理
                        </Button>
                      </div>
                    </div>
                  </div>
                )) : (
                  <div className="text-center text-slate-400 py-8">
                    暂无活跃威胁告警
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        {/* 威胁详情模态框 */}
        {showRequestModal && selectedThreat && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
            <div className="bg-slate-900 rounded-lg max-w-4xl w-full max-h-[90vh] overflow-hidden">
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

              <div className="p-6 overflow-y-auto max-h-[calc(90vh-120px)]">
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
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
                        <Badge variant={getSeverityBadge(selectedThreat.severity)}>
                          {getSeverityText(selectedThreat.severity)}
                        </Badge>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">请求总数</span>
                        <span className="text-red-400 font-medium">{selectedThreat.requests.toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">时间窗口</span>
                        <span className="text-white">{selectedThreat.time_window}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">来源IP</span>
                        <span className="text-yellow-400 font-mono">{selectedThreat.source_ip}</span>
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="bg-slate-800 border-slate-700">
                    <CardHeader>
                      <CardTitle className="text-white text-sm">威胁描述</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <p className="text-slate-300 text-sm">{selectedThreat.description}</p>
                      <div className="mt-4 space-y-2">
                        <div className="text-xs text-slate-400">检测时间</div>
                        <div className="text-sm text-white">{new Date(selectedThreat.timestamp).toLocaleString()}</div>
                      </div>
                    </CardContent>
                  </Card>
                </div>

                <div className="flex gap-4">
                  <Button 
                    variant="destructive" 
                    className="flex-1"
                    onClick={() => {
                      handleThreatAction(selectedThreat.id, 'block')
                      setShowRequestModal(false)
                    }}
                  >
                    <AlertTriangle className="w-4 h-4 mr-2" />
                    确认威胁并封禁IP
                  </Button>
                  <Button 
                    variant="outline" 
                    className="flex-1 bg-transparent"
                    onClick={() => {
                      handleThreatAction(selectedThreat.id, 'ignore')
                      setShowRequestModal(false)
                    }}
                  >
                    标记为误报
                  </Button>
                  <Button 
                    variant="secondary" 
                    className="flex-1"
                    onClick={() => {
                      handleThreatAction(selectedThreat.id, 'whitelist')
                      setShowRequestModal(false)
                    }}
                  >
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
