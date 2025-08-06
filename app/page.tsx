'use client'

import { useState, useEffect, useRef } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Progress } from '@/components/ui/progress'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Shield, Activity, Users, Globe, AlertTriangle, CheckCircle, XCircle, Wifi, Server, Database, Clock, TrendingUp, Eye, Lock, Zap } from 'lucide-react'

interface SystemInfo {
  hostname: string
  uptime: string
  load_average: number[]
  memory_usage: number
  disk_usage: number
  network_interfaces: string[]
  active_connections: number
  listening_ports: number[]
}

interface NetworkStats {
  total_requests: number
  blocked_requests: number
  suspicious_ips: number
  threat_level: string
  last_attack: string
  active_connections: number
}

interface ThreatInfo {
  ip: string
  country: string
  threat_type: string
  severity: string
  timestamp: string
  blocked: boolean
  requests_count: number
}

interface LogEntry {
  timestamp: string
  level: string
  message: string
  ip?: string
  threat_type?: string
}

export default function NetworkMonitor() {
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null)
  const [networkStats, setNetworkStats] = useState<NetworkStats | null>(null)
  const [threats, setThreats] = useState<ThreatInfo[]>([])
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [isConnected, setIsConnected] = useState(false)
  const [connectionError, setConnectionError] = useState<string | null>(null)
  const wsRef = useRef<WebSocket | null>(null)

  // 获取WebSocket URL，根据当前协议选择ws或wss
  const getWebSocketUrl = () => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = window.location.hostname
    const port = process.env.NODE_ENV === 'development' ? '8080' : window.location.port || '8080'
    return `${protocol}//${host}:${port}/ws`
  }

  // 获取API基础URL
  const getApiBaseUrl = () => {
    const protocol = window.location.protocol
    const host = window.location.hostname
    const port = process.env.NODE_ENV === 'development' ? '8080' : window.location.port || '8080'
    return `${protocol}//${host}:${port}/api`
  }

  // 初始化WebSocket连接
  const initWebSocket = () => {
    try {
      const wsUrl = getWebSocketUrl()
      console.log('Connecting to WebSocket:', wsUrl)
      
      const ws = new WebSocket(wsUrl)
      wsRef.current = ws

      ws.onopen = () => {
        console.log('WebSocket connected')
        setIsConnected(true)
        setConnectionError(null)
      }

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          console.log('WebSocket data received:', data)
          
          if (data.type === 'system_info') {
            setSystemInfo(data.data)
          } else if (data.type === 'network_stats') {
            setNetworkStats(data.data)
          } else if (data.type === 'threat_detected') {
            setThreats(prev => [data.data, ...prev.slice(0, 49)])
          } else if (data.type === 'log_entry') {
            setLogs(prev => [data.data, ...prev.slice(0, 99)])
          }
        } catch (error) {
          console.error('Error parsing WebSocket message:', error)
        }
      }

      ws.onclose = (event) => {
        console.log('WebSocket disconnected:', event.code, event.reason)
        setIsConnected(false)
        
        // 自动重连
        setTimeout(() => {
          if (wsRef.current?.readyState === WebSocket.CLOSED) {
            initWebSocket()
          }
        }, 5000)
      }

      ws.onerror = (error) => {
        console.error('WebSocket error:', error)
        setConnectionError('WebSocket连接失败')
        setIsConnected(false)
      }

    } catch (error) {
      console.error('Failed to create WebSocket:', error)
      setConnectionError('无法创建WebSocket连接')
    }
  }

  // 获取初始数据
  const fetchInitialData = async () => {
    try {
      const baseUrl = getApiBaseUrl()
      
      // 获取系统信息
      const systemResponse = await fetch(`${baseUrl}/system/info`)
      if (systemResponse.ok) {
        const systemData = await systemResponse.json()
        setSystemInfo(systemData)
      }

      // 获取网络统计
      const statsResponse = await fetch(`${baseUrl}/network/stats`)
      if (statsResponse.ok) {
        const statsData = await statsResponse.json()
        setNetworkStats(statsData)
      }

      // 获取威胁列表
      const threatsResponse = await fetch(`${baseUrl}/threats`)
      if (threatsResponse.ok) {
        const threatsData = await threatsResponse.json()
        setThreats(threatsData || [])
      }

    } catch (error) {
      console.error('Error fetching initial data:', error)
      setConnectionError('无法获取初始数据')
    }
  }

  useEffect(() => {
    fetchInitialData()
    initWebSocket()

    return () => {
      if (wsRef.current) {
        wsRef.current.close()
      }
    }
  }, [])

  const getThreatLevelColor = (level: string) => {
    switch (level?.toLowerCase()) {
      case 'critical': return 'bg-red-500'
      case 'high': return 'bg-orange-500'
      case 'medium': return 'bg-yellow-500'
      case 'low': return 'bg-green-500'
      default: return 'bg-gray-500'
    }
  }

  const getThreatLevelBadge = (level: string) => {
    switch (level?.toLowerCase()) {
      case 'critical': return 'destructive'
      case 'high': return 'destructive'
      case 'medium': return 'default'
      case 'low': return 'secondary'
      default: return 'outline'
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900">
      <div className="container mx-auto p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-blue-600 rounded-lg">
              <Eye className="h-8 w-8 text-white" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-white">天眼监控系统</h1>
              <p className="text-blue-200">实时网络安全监控与威胁检测</p>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <div className={`w-3 h-3 rounded-full ${isConnected ? 'bg-green-400' : 'bg-red-400'}`}></div>
            <span className="text-white text-sm">
              {isConnected ? '已连接' : '连接中断'}
            </span>
          </div>
        </div>

        {/* Connection Error Alert */}
        {connectionError && (
          <Alert className="border-red-500 bg-red-50">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription className="text-red-700">
              {connectionError}
            </AlertDescription>
          </Alert>
        )}

        {/* System Overview Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <Card className="bg-white/10 backdrop-blur border-white/20">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-white">系统状态</CardTitle>
              <Server className="h-4 w-4 text-blue-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">
                {systemInfo ? '正常' : '检测中'}
              </div>
              <p className="text-xs text-blue-200">
                运行时间: {systemInfo?.uptime || '获取中...'}
              </p>
            </CardContent>
          </Card>

          <Card className="bg-white/10 backdrop-blur border-white/20">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-white">活跃连接</CardTitle>
              <Wifi className="h-4 w-4 text-green-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">
                {networkStats?.active_connections || 0}
              </div>
              <p className="text-xs text-blue-200">
                当前网络连接数
              </p>
            </CardContent>
          </Card>

          <Card className="bg-white/10 backdrop-blur border-white/20">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-white">威胁等级</CardTitle>
              <Shield className="h-4 w-4 text-yellow-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">
                {networkStats?.threat_level || 'LOW'}
              </div>
              <p className="text-xs text-blue-200">
                当前安全等级
              </p>
            </CardContent>
          </Card>

          <Card className="bg-white/10 backdrop-blur border-white/20">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-white">拦截请求</CardTitle>
              <Lock className="h-4 w-4 text-red-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">
                {networkStats?.blocked_requests || 0}
              </div>
              <p className="text-xs text-blue-200">
                已拦截恶意请求
              </p>
            </CardContent>
          </Card>
        </div>

        {/* Main Content Tabs */}
        <Tabs defaultValue="overview" className="space-y-6">
          <TabsList className="grid w-full grid-cols-4 bg-white/10 backdrop-blur">
            <TabsTrigger value="overview" className="text-white data-[state=active]:bg-blue-600">
              总览
            </TabsTrigger>
            <TabsTrigger value="threats" className="text-white data-[state=active]:bg-blue-600">
              威胁检测
            </TabsTrigger>
            <TabsTrigger value="system" className="text-white data-[state=active]:bg-blue-600">
              系统监控
            </TabsTrigger>
            <TabsTrigger value="logs" className="text-white data-[state=active]:bg-blue-600">
              实时日志
            </TabsTrigger>
          </TabsList>

          {/* Overview Tab */}
          <TabsContent value="overview" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card className="bg-white/10 backdrop-blur border-white/20">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <TrendingUp className="mr-2 h-5 w-5" />
                    网络统计
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex justify-between text-white">
                    <span>总请求数</span>
                    <span className="font-bold">{networkStats?.total_requests || 0}</span>
                  </div>
                  <div className="flex justify-between text-white">
                    <span>可疑IP数</span>
                    <span className="font-bold text-yellow-400">{networkStats?.suspicious_ips || 0}</span>
                  </div>
                  <div className="flex justify-between text-white">
                    <span>最后攻击</span>
                    <span className="font-bold text-red-400">{networkStats?.last_attack || '无'}</span>
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-white/10 backdrop-blur border-white/20">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Activity className="mr-2 h-5 w-5" />
                    系统资源
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <div className="flex justify-between text-white mb-2">
                      <span>内存使用率</span>
                      <span>{systemInfo?.memory_usage?.toFixed(1) || 0}%</span>
                    </div>
                    <Progress value={systemInfo?.memory_usage || 0} className="h-2" />
                  </div>
                  <div>
                    <div className="flex justify-between text-white mb-2">
                      <span>磁盘使用率</span>
                      <span>{systemInfo?.disk_usage?.toFixed(1) || 0}%</span>
                    </div>
                    <Progress value={systemInfo?.disk_usage || 0} className="h-2" />
                  </div>
                  <div className="flex justify-between text-white">
                    <span>负载平均</span>
                    <span>{systemInfo?.load_average?.[0]?.toFixed(2) || '0.00'}</span>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Threats Tab */}
          <TabsContent value="threats" className="space-y-6">
            <Card className="bg-white/10 backdrop-blur border-white/20">
              <CardHeader>
                <CardTitle className="text-white flex items-center">
                  <AlertTriangle className="mr-2 h-5 w-5" />
                  威胁检测记录
                </CardTitle>
                <CardDescription className="text-blue-200">
                  实时检测到的网络威胁和攻击尝试
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4 max-h-96 overflow-y-auto">
                  {threats.length === 0 ? (
                    <div className="text-center py-8 text-blue-200">
                      <Shield className="mx-auto h-12 w-12 mb-4 opacity-50" />
                      <p>暂无威胁检测记录</p>
                    </div>
                  ) : (
                    threats.map((threat, index) => (
                      <div key={index} className="flex items-center justify-between p-4 bg-white/5 rounded-lg border border-white/10">
                        <div className="flex items-center space-x-4">
                          <div className={`w-3 h-3 rounded-full ${getThreatLevelColor(threat.severity)}`}></div>
                          <div>
                            <div className="text-white font-medium">{threat.ip}</div>
                            <div className="text-blue-200 text-sm">{threat.threat_type}</div>
                          </div>
                        </div>
                        <div className="text-right">
                          <Badge variant={getThreatLevelBadge(threat.severity)}>
                            {threat.severity}
                          </Badge>
                          <div className="text-blue-200 text-xs mt-1">
                            {new Date(threat.timestamp).toLocaleString()}
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* System Tab */}
          <TabsContent value="system" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card className="bg-white/10 backdrop-blur border-white/20">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Database className="mr-2 h-5 w-5" />
                    系统信息
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex justify-between text-white">
                    <span>主机名</span>
                    <span className="font-mono">{systemInfo?.hostname || '获取中...'}</span>
                  </div>
                  <div className="flex justify-between text-white">
                    <span>运行时间</span>
                    <span>{systemInfo?.uptime || '获取中...'}</span>
                  </div>
                  <div className="flex justify-between text-white">
                    <span>活跃连接</span>
                    <span>{systemInfo?.active_connections || 0}</span>
                  </div>
                  <div className="flex justify-between text-white">
                    <span>监听端口</span>
                    <span>{systemInfo?.listening_ports?.length || 0} 个</span>
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-white/10 backdrop-blur border-white/20">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Globe className="mr-2 h-5 w-5" />
                    网络接口
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {systemInfo?.network_interfaces?.map((iface, index) => (
                      <div key={index} className="flex items-center justify-between p-2 bg-white/5 rounded">
                        <span className="text-white font-mono text-sm">{iface}</span>
                        <CheckCircle className="h-4 w-4 text-green-400" />
                      </div>
                    )) || (
                      <div className="text-blue-200 text-center py-4">获取网络接口信息中...</div>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Logs Tab */}
          <TabsContent value="logs" className="space-y-6">
            <Card className="bg-white/10 backdrop-blur border-white/20">
              <CardHeader>
                <CardTitle className="text-white flex items-center">
                  <Clock className="mr-2 h-5 w-5" />
                  实时系统日志
                </CardTitle>
                <CardDescription className="text-blue-200">
                  系统运行和安全事件的实时日志
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 max-h-96 overflow-y-auto font-mono text-sm">
                  {logs.length === 0 ? (
                    <div className="text-center py-8 text-blue-200">
                      <Activity className="mx-auto h-12 w-12 mb-4 opacity-50" />
                      <p>等待日志数据...</p>
                    </div>
                  ) : (
                    logs.map((log, index) => (
                      <div key={index} className="flex items-start space-x-3 p-2 bg-white/5 rounded">
                        <span className="text-blue-300 text-xs whitespace-nowrap">
                          {new Date(log.timestamp).toLocaleTimeString()}
                        </span>
                        <Badge 
                          variant={log.level === 'ERROR' ? 'destructive' : log.level === 'WARN' ? 'default' : 'secondary'}
                          className="text-xs"
                        >
                          {log.level}
                        </Badge>
                        <span className="text-white text-xs flex-1">{log.message}</span>
                      </div>
                    ))
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}
