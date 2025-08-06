'use client'

import React, { useState, useEffect } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Progress } from '@/components/ui/progress'

interface ThreatAlert {
  id: number
  type: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  endpoint: string
  source_ip: string
  requests: number
  time_window: string
  timestamp: string
  description: string
  active: boolean
}

interface ServerStatus {
  id: string
  name: string
  ip: string
  status: 'healthy' | 'warning' | 'critical'
  cpu: number
  memory: number
  requests: number
  last_seen: string
}

interface TrafficStats {
  timestamp: string
  requests: number
  threats: number
  response_time: number
}

export default function NetworkMonitoringDashboard() {
  const [threats, setThreats] = useState<ThreatAlert[]>([])
  const [servers, setServers] = useState<ServerStatus[]>([])
  const [stats, setStats] = useState<TrafficStats[]>([])
  const [isConnected, setIsConnected] = useState(false)
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date())

  useEffect(() => {
    // 初始化WebSocket连接
    const connectWebSocket = () => {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const wsUrl = `${protocol}//${window.location.host}/ws`
      
      const ws = new WebSocket(wsUrl)
      
      ws.onopen = () => {
        console.log('WebSocket连接已建立')
        setIsConnected(true)
      }
      
      ws.onmessage = (event) => {
        const data = JSON.parse(event.data)
        handleWebSocketMessage(data)
        setLastUpdate(new Date())
      }
      
      ws.onclose = () => {
        console.log('WebSocket连接已关闭')
        setIsConnected(false)
        // 5秒后重连
        setTimeout(connectWebSocket, 5000)
      }
      
      ws.onerror = (error) => {
        console.error('WebSocket错误:', error)
        setIsConnected(false)
      }
    }

    // 处理WebSocket消息
    const handleWebSocketMessage = (data: any) => {
      switch(data.type) {
        case 'update':
          if (data.stats) setStats(prev => [...prev.slice(-19), ...data.stats])
          if (data.servers) setServers(data.servers)
          if (data.threats) setThreats(data.threats)
          break
      }
    }

    // 加载初始数据
    const loadInitialData = async () => {
      try {
        // 加载威胁数据
        const threatsResponse = await fetch('/api/threats')
        const threatsResult = await threatsResponse.json()
        if (threatsResult.success) {
          setThreats(threatsResult.data)
        }

        // 加载服务器数据
        const serversResponse = await fetch('/api/servers')
        const serversResult = await serversResponse.json()
        if (serversResult.success) {
          setServers(serversResult.data)
        }

        // 加载统计数据
        const statsResponse = await fetch('/api/stats')
        const statsResult = await statsResponse.json()
        if (statsResult.success) {
          setStats(statsResult.data)
        }
      } catch (error) {
        console.error('加载初始数据失败:', error)
      }
    }

    connectWebSocket()
    loadInitialData()
  }, [])

  // 处理威胁操作
  const handleThreatAction = async (threatId: number, action: string) => {
    try {
      const response = await fetch(`/api/threats/${threatId}/${action}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        }
      })

      const result = await response.json()
      
      if (result.success) {
        // 刷新威胁数据
        const threatsResponse = await fetch('/api/threats')
        const threatsResult = await threatsResponse.json()
        if (threatsResult.success) {
          setThreats(threatsResult.data)
        }
      }
    } catch (error) {
      console.error('处理威胁失败:', error)
    }
  }

  // 获取威胁严重程度颜色
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'destructive'
      case 'high': return 'destructive'
      case 'medium': return 'default'
      case 'low': return 'secondary'
      default: return 'default'
    }
  }

  // 获取服务器状态颜色
  const getServerStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return 'bg-green-100 text-green-800'
      case 'warning': return 'bg-yellow-100 text-yellow-800'
      case 'critical': return 'bg-red-100 text-red-800'
      default: return 'bg-gray-100 text-gray-800'
    }
  }

  // 计算统计数据
  const totalRequests = stats.reduce((sum, stat) => sum + stat.requests, 0)
  const activeThreats = threats.filter(t => t.active).length
  const healthyServers = servers.filter(s => s.status === 'healthy').length
  const avgResponseTime = stats.length > 0 
    ? Math.round(stats.reduce((sum, stat) => sum + stat.response_time, 0) / stats.length)
    : 0

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-7xl mx-auto">
        {/* 头部 */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-gray-900">🔍 天眼网络监控系统</h1>
              <p className="text-gray-600 mt-1">实时网络威胁监控与防护平台</p>
            </div>
            <div className="flex items-center space-x-4">
              <Badge variant={isConnected ? "default" : "destructive"}>
                {isConnected ? "● 已连接" : "● 连接断开"}
              </Badge>
              <div className="text-sm text-gray-500">
                最后更新: {lastUpdate.toLocaleTimeString()}
              </div>
            </div>
          </div>
        </div>

        {/* 统计卡片 */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">总请求数</CardTitle>
              <span className="text-2xl">⚡</span>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{totalRequests.toLocaleString()}</div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">活跃威胁</CardTitle>
              <span className="text-2xl">🚨</span>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-600">{activeThreats}</div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">健康服务器</CardTitle>
              <span className="text-2xl">🖥️</span>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-600">
                {healthyServers}/{servers.length}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">平均响应时间</CardTitle>
              <span className="text-2xl">⏱️</span>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{avgResponseTime}ms</div>
            </CardContent>
          </Card>
        </div>

        <Tabs defaultValue="threats" className="space-y-6">
          <TabsList>
            <TabsTrigger value="threats">威胁告警</TabsTrigger>
            <TabsTrigger value="servers">服务器状态</TabsTrigger>
            <TabsTrigger value="traffic">流量监控</TabsTrigger>
          </TabsList>

          {/* 威胁告警标签页 */}
          <TabsContent value="threats">
            <Card>
              <CardHeader>
                <CardTitle>🚨 威胁告警</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {threats.filter(t => t.active).length === 0 ? (
                    <div className="text-center py-8 text-gray-500">
                      🛡️ 暂无活跃威胁
                    </div>
                  ) : (
                    threats.filter(t => t.active).map((threat) => (
                      <Alert key={threat.id} className="border-l-4 border-l-red-500">
                        <AlertDescription>
                          <div className="flex items-start justify-between">
                            <div className="flex-1">
                              <div className="flex items-center space-x-2 mb-2">
                                <Badge variant={getSeverityColor(threat.severity)}>
                                  {threat.severity.toUpperCase()}
                                </Badge>
                                <span className="font-semibold">{threat.type}</span>
                              </div>
                              
                              <p className="text-sm text-gray-600 mb-3">
                                {threat.description}
                              </p>
                              
                              <div className="grid grid-cols-2 gap-4 text-sm">
                                <div>
                                  <span className="font-medium">目标端点:</span>
                                  <code className="ml-1 px-1 bg-gray-100 rounded">
                                    {threat.endpoint}
                                  </code>
                                </div>
                                <div>
                                  <span className="font-medium">来源IP:</span>
                                  <code className="ml-1 px-1 bg-gray-100 rounded">
                                    {threat.source_ip}
                                  </code>
                                </div>
                                <div>
                                  <span className="font-medium">请求数量:</span>
                                  <span className="ml-1 text-red-600 font-semibold">
                                    {threat.requests.toLocaleString()} 次/{threat.time_window}
                                  </span>
                                </div>
                                <div>
                                  <span className="font-medium">检测时间:</span>
                                  <span className="ml-1">
                                    {new Date(threat.timestamp).toLocaleString()}
                                  </span>
                                </div>
                              </div>
                            </div>
                            
                            <div className="flex flex-col space-y-2 ml-4">
                              <Button 
                                size="sm" 
                                variant="destructive"
                                onClick={() => handleThreatAction(threat.id, 'block')}
                              >
                                🚫 封禁IP
                              </Button>
                              <Button 
                                size="sm" 
                                variant="default"
                                onClick={() => handleThreatAction(threat.id, 'whitelist')}
                              >
                                ✅ 白名单
                              </Button>
                              <Button 
                                size="sm" 
                                variant="outline"
                                onClick={() => handleThreatAction(threat.id, 'ignore')}
                              >
                                ❌ 忽略
                              </Button>
                            </div>
                          </div>
                        </AlertDescription>
                      </Alert>
                    ))
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* 服务器状态标签页 */}
          <TabsContent value="servers">
            <Card>
              <CardHeader>
                <CardTitle>🖥️ 服务器状态</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {servers.map((server) => (
                    <Card key={server.id} className="border-l-4 border-l-blue-500">
                      <CardHeader className="pb-3">
                        <div className="flex items-center justify-between">
                          <CardTitle className="text-lg">{server.name}</CardTitle>
                          <Badge className={getServerStatusColor(server.status)}>
                            {server.status === 'healthy' ? '健康' : 
                             server.status === 'warning' ? '警告' : '严重'}
                          </Badge>
                        </div>
                        <p className="text-sm text-gray-600">IP: {server.ip}</p>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-3">
                          <div>
                            <div className="flex justify-between text-sm mb-1">
                              <span>CPU使用率</span>
                              <span>{server.cpu.toFixed(1)}%</span>
                            </div>
                            <Progress value={server.cpu} className="h-2" />
                          </div>
                          
                          <div>
                            <div className="flex justify-between text-sm mb-1">
                              <span>内存使用率</span>
                              <span>{server.memory.toFixed(1)}%</span>
                            </div>
                            <Progress value={server.memory} className="h-2" />
                          </div>
                          
                          <div className="flex justify-between text-sm">
                            <span>请求数:</span>
                            <span className="font-semibold">
                              {server.requests.toLocaleString()}
                            </span>
                          </div>
                          
                          <div className="text-xs text-gray-500">
                            最后更新: {new Date(server.last_seen).toLocaleString()}
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* 流量监控标签页 */}
          <TabsContent value="traffic">
            <Card>
              <CardHeader>
                <CardTitle>📊 流量监控</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="h-64 flex items-end justify-between space-x-1">
                  {stats.slice(-20).map((stat, index) => (
                    <div key={index} className="flex flex-col items-center flex-1">
                      <div 
                        className="w-full bg-blue-500 rounded-t"
                        style={{ 
                          height: `${Math.max((stat.requests / Math.max(...stats.map(s => s.requests))) * 200, 2)}px` 
                        }}
                        title={`时间: ${new Date(stat.timestamp).toLocaleTimeString()}
请求数: ${stat.requests}
威胁数: ${stat.threats}
响应时间: ${stat.response_time.toFixed(1)}ms`}
                      />
                      <div className="text-xs text-gray-500 mt-1 transform -rotate-45 origin-left">
                        {new Date(stat.timestamp).toLocaleTimeString().slice(0, 5)}
                      </div>
                    </div>
                  ))}
                </div>
                
                <div className="mt-4 grid grid-cols-3 gap-4 text-center">
                  <div>
                    <div className="text-2xl font-bold text-blue-600">
                      {stats.length > 0 ? stats[stats.length - 1]?.requests || 0 : 0}
                    </div>
                    <div className="text-sm text-gray-500">当前请求数</div>
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-red-600">
                      {stats.length > 0 ? stats[stats.length - 1]?.threats || 0 : 0}
                    </div>
                    <div className="text-sm text-gray-500">当前威胁数</div>
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-green-600">
                      {stats.length > 0 ? Math.round(stats[stats.length - 1]?.response_time || 0) : 0}ms
                    </div>
                    <div className="text-sm text-gray-500">当前响应时间</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}
