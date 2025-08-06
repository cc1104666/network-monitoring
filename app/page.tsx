'use client'

import React, { useState, useEffect, useRef } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Alert, AlertDescription } from '@/components/ui/alert'

// TypeScript Interfaces
interface SystemMetrics {
  server_id: string
  server_name: string
  server_ip: string
  timestamp: string
  cpu: number
  memory: number
  disk: number
  network: {
    bytes_sent: number
    bytes_recv: number
    packets_sent: number
    packets_recv: number
  }
  status: string
}

interface NetworkConnection {
  protocol: string
  local_addr: string
  remote_addr: string
  state: string
  port: number
  process_name: string
  timestamp: string
}

interface ProcessInfo {
  pid: number
  name: string
  cpu_usage: number
  memory: number
  status: string
  timestamp: string
}

interface Threat {
  id: string
  type: string
  severity: string
  source: string
  target: string
  description: string
  timestamp: string
  status: string
}

interface AlertInfo {
  id: string
  type: string
  message: string
  severity: string
  timestamp: string
  acknowledged: boolean
}

interface SystemInfo {
  hostname: string
  os: string
  platform: string
  uptime: number
  cpu_model: string
  cpu_cores: number
  total_memory: number
  real_data_enabled: boolean
}

export default function NetworkMonitoringDashboard() {
  // State declarations
  const [systemMetrics, setSystemMetrics] = useState<SystemMetrics | null>(null)
  const [networkConnections, setNetworkConnections] = useState<NetworkConnection[]>([])
  const [processes, setProcesses] = useState<ProcessInfo[]>([])
  const [threats, setThreats] = useState<Threat[]>([])
  const [alerts, setAlerts] = useState<AlertInfo[]>([])
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null)
  const [wsStatus, setWsStatus] = useState<'connecting' | 'connected' | 'disconnected' | 'error'>('connecting')
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null)
  const [connectionAttempts, setConnectionAttempts] = useState(0)
  const [apiError, setApiError] = useState<string | null>(null)
  const ws = useRef<WebSocket | null>(null)
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null)

  // Fetch initial static data on component mount
  useEffect(() => {
    const fetchInitialData = async () => {
      console.log('🔄 Fetching initial data...')
      setApiError(null)
      
      try {
        // Test if the server is responding at all
        const testResponse = await fetch('/api/system/info', {
          method: 'GET',
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
          },
        })
        
        console.log('📡 API test response status:', testResponse.status)
        console.log('📡 API test response headers:', Object.fromEntries(testResponse.headers.entries()))
        
        if (!testResponse.ok) {
          throw new Error(`API responded with status ${testResponse.status}`)
        }
        
        const contentType = testResponse.headers.get('content-type')
        if (!contentType || !contentType.includes('application/json')) {
          const text = await testResponse.text()
          console.error('❌ Expected JSON but got:', contentType, text.substring(0, 200))
          throw new Error(`Expected JSON response but got ${contentType}`)
        }
        
        const systemInfoData = await testResponse.json()
        setSystemInfo(systemInfoData)
        console.log('✅ System info loaded:', systemInfoData)
        
        // Fetch other data
        const [threatsRes, alertsRes] = await Promise.all([
          fetch('/api/threats', { headers: { 'Accept': 'application/json' } }),
          fetch('/api/alerts', { headers: { 'Accept': 'application/json' } }),
        ])
        
        if (threatsRes.ok) {
          const threatsData = await threatsRes.json()
          setThreats(Array.isArray(threatsData) ? threatsData : [])
          console.log('✅ Threats loaded:', threatsData?.length || 0)
        } else {
          console.warn('⚠️ Failed to fetch threats:', threatsRes.status)
        }
        
        if (alertsRes.ok) {
          const alertsData = await alertsRes.json()
          setAlerts(Array.isArray(alertsData) ? alertsData : [])
          console.log('✅ Alerts loaded:', alertsData?.length || 0)
        } else {
          console.warn('⚠️ Failed to fetch alerts:', alertsRes.status)
        }
        
      } catch (error) {
        console.error("❌ Failed to fetch initial data:", error)
        setApiError(error instanceof Error ? error.message : 'Unknown error occurred')
        setWsStatus('error')
      }
    }
    
    fetchInitialData()
  }, [])

  // WebSocket connection management
  useEffect(() => {
    const connect = () => {
      // Clear any existing reconnect timeout
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
        reconnectTimeoutRef.current = null
      }

      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const wsUrl = `${protocol}//${window.location.host}/ws`
      
      console.log(`🔌 Attempting WebSocket connection to: ${wsUrl} (attempt ${connectionAttempts + 1})`)
      
      try {
        ws.current = new WebSocket(wsUrl)
        setWsStatus('connecting')

        ws.current.onopen = () => {
          console.log('✅ WebSocket connected successfully')
          setWsStatus('connected')
          setConnectionAttempts(0)
        }

        ws.current.onmessage = (event) => {
          try {
            const message = JSON.parse(event.data)
            console.log('📨 WebSocket message received:', message.type)
            
            switch (message.type) {
              case 'SYSTEM_METRICS_UPDATE':
                setSystemMetrics(message.payload)
                break
              case 'NETWORK_CONNECTIONS_UPDATE':
                setNetworkConnections(Array.isArray(message.payload) ? message.payload : [])
                break
              case 'PROCESSES_UPDATE':
                setProcesses(Array.isArray(message.payload) ? message.payload : [])
                break
              case 'NEW_THREAT':
                if (message.payload) {
                  setThreats(prev => [message.payload, ...prev].slice(0, 50))
                  setAlerts(prev => [{
                    id: `alert-${Date.now()}`,
                    type: 'security',
                    message: `New threat from ${message.payload.source}: ${message.payload.description}`,
                    severity: message.payload.severity,
                    timestamp: new Date().toISOString(),
                    acknowledged: false
                  }, ...prev].slice(0, 20))
                }
                break
              default:
                console.warn('⚠️ Unknown WebSocket message type:', message.type)
            }
            setLastUpdate(new Date())
          } catch (error) {
            console.error('❌ Error processing WebSocket message:', error)
          }
        }

        ws.current.onclose = (event) => {
          console.log(`🔌 WebSocket disconnected (code: ${event.code}, reason: ${event.reason})`)
          setWsStatus('disconnected')
          
          // Attempt to reconnect with exponential backoff
          const attempts = connectionAttempts + 1
          setConnectionAttempts(attempts)
          
          if (attempts < 10) {
            const delay = Math.min(1000 * Math.pow(2, attempts), 30000) // Max 30 seconds
            console.log(`🔄 Reconnecting in ${delay}ms...`)
            reconnectTimeoutRef.current = setTimeout(connect, delay)
          } else {
            console.error('❌ Max reconnection attempts reached')
            setWsStatus('error')
          }
        }

        ws.current.onerror = (error) => {
          console.error('❌ WebSocket error:', error)
          setWsStatus('error')
        }

      } catch (error) {
        console.error('❌ Failed to create WebSocket connection:', error)
        setWsStatus('error')
      }
    }

    // Only attempt WebSocket connection if API is working
    if (!apiError && systemInfo) {
      connect()
    }

    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
      }
      if (ws.current) {
        ws.current.onclose = null // prevent reconnect on unmount
        ws.current.close()
      }
    }
  }, [connectionAttempts, apiError, systemInfo])

  // UI Helper functions
  const getStatusColor = (status: string) => {
    const colors = {
      healthy: 'bg-green-500',
      warning: 'bg-yellow-500',
      critical: 'bg-red-500'
    }
    return colors[status as keyof typeof colors] || 'bg-gray-500'
  }

  const getSeverityColor = (severity: string) => {
    const colors = {
      critical: 'destructive' as const,
      high: 'destructive' as const,
      medium: 'default' as const,
      low: 'secondary' as const
    }
    return colors[severity as keyof typeof colors] || 'outline' as const
  }

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`
  }

  const ConnectionStatus = () => {
    if (apiError) {
      return (
        <div className="flex items-center space-x-2">
          <div className="w-3 h-3 rounded-full bg-red-500"></div>
          <span className="text-sm text-red-600">API错误: {apiError}</span>
        </div>
      )
    }

    const statusMap = {
      connecting: { text: '正在连接...', color: 'bg-yellow-500 animate-pulse' },
      connected: { text: '实时连接中', color: 'bg-green-500' },
      disconnected: { text: '连接已断开', color: 'bg-gray-500' },
      error: { text: '连接错误', color: 'bg-red-500' },
    }
    const { text, color } = statusMap[wsStatus]
    return (
      <div className="flex items-center space-x-2">
        <div className={`w-3 h-3 rounded-full ${color}`}></div>
        <span className="text-sm text-gray-600">{text}</span>
        {connectionAttempts > 0 && wsStatus !== 'connected' && (
          <span className="text-xs text-gray-500">({connectionAttempts} attempts)</span>
        )}
      </div>
    )
  }

  // Show error state if API is not working
  if (apiError) {
    return (
      <div className="min-h-screen bg-gray-50 p-4">
        <div className="max-w-4xl mx-auto">
          <div className="text-center">
            <h1 className="text-3xl font-bold text-gray-900 mb-4">🔍 天眼网络监控系统</h1>
            <Alert className="border-l-4 border-red-500 mb-6">
              <AlertDescription>
                <div className="text-left">
                  <strong>❌ 服务器连接失败</strong><br/>
                  <p className="mt-2">无法连接到后端服务器。请检查：</p>
                  <ul className="list-disc list-inside mt-2 space-y-1">
                    <li>Go服务器是否正在运行 (端口8080)</li>
                    <li>运行 <code className="bg-gray-100 px-1 rounded">go run *.go</code> 启动服务器</li>
                    <li>检查控制台错误信息</li>
                  </ul>
                  <p className="mt-2 text-sm text-gray-600">错误详情: {apiError}</p>
                </div>
              </AlertDescription>
            </Alert>
            <div className="bg-white p-6 rounded-lg shadow">
              <h3 className="text-lg font-semibold mb-4">🔧 故障排除步骤</h3>
              <div className="text-left space-y-2">
                <p><strong>1. 检查Go服务器状态:</strong></p>
                <code className="block bg-gray-100 p-2 rounded">sudo systemctl status network-monitor</code>
                
                <p><strong>2. 查看服务器日志:</strong></p>
                <code className="block bg-gray-100 p-2 rounded">sudo journalctl -u network-monitor -f</code>
                
                <p><strong>3. 手动启动服务器:</strong></p>
                <code className="block bg-gray-100 p-2 rounded">go run *.go</code>
              </div>
            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50 p-4">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-6 flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">🔍 天眼网络监控系统</h1>
            <p className="text-gray-600 mt-1">实时网络安全监控与威胁检测平台</p>
          </div>
          <div className="flex items-center space-x-4">
            <ConnectionStatus />
            <div className="text-sm text-gray-500">
              {lastUpdate ? `最后更新: ${lastUpdate.toLocaleTimeString()}` : '等待数据...'}
            </div>
            {systemInfo?.real_data_enabled && (
              <Badge className="bg-green-100 text-green-800">真实数据模式</Badge>
            )}
          </div>
        </div>

        {/* System Metrics Overview */}
        {systemMetrics ? (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">CPU</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{systemMetrics.cpu.toFixed(1)}%</div>
                <Progress value={systemMetrics.cpu} className="mt-2" />
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">内存</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{systemMetrics.memory.toFixed(1)}%</div>
                <Progress value={systemMetrics.memory} className="mt-2" />
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">磁盘</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{systemMetrics.disk.toFixed(1)}%</div>
                <Progress value={systemMetrics.disk} className="mt-2" />
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">状态</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center space-x-2">
                  <div className={`w-3 h-3 rounded-full ${getStatusColor(systemMetrics.status)}`}></div>
                  <span className="text-lg font-semibold capitalize">{systemMetrics.status}</span>
                </div>
              </CardContent>
            </Card>
          </div>
        ) : (
          <div className="text-center p-8 text-gray-500">
            {wsStatus === 'connected' ? '正在获取系统指标...' : '正在连接服务器...'}
          </div>
        )}

        {/* Alerts */}
        {alerts.length > 0 && (
          <div className="mb-6 space-y-2">
            {alerts.slice(0, 3).map((alert) => (
              <Alert key={alert.id} className="border-l-4 border-red-500">
                <AlertDescription className="flex items-center justify-between">
                  <span>{alert.message}</span>
                  <Badge variant={getSeverityColor(alert.severity)}>{alert.severity}</Badge>
                </AlertDescription>
              </Alert>
            ))}
          </div>
        )}

        {/* Main Content Tabs */}
        <Tabs defaultValue="overview" className="space-y-4">
          <TabsList className="grid w-full grid-cols-5">
            <TabsTrigger value="overview">概览</TabsTrigger>
            <TabsTrigger value="network">网络连接</TabsTrigger>
            <TabsTrigger value="processes">进程监控</TabsTrigger>
            <TabsTrigger value="threats">威胁检测</TabsTrigger>
            <TabsTrigger value="system">系统信息</TabsTrigger>
          </TabsList>

          {/* Overview Tab */}
          <TabsContent value="overview" className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <Card>
                <CardHeader>
                  <CardTitle>网络流量</CardTitle>
                </CardHeader>
                <CardContent>
                  {systemMetrics ? (
                    <div className="space-y-4">
                      <div className="flex justify-between">
                        <span>接收:</span>
                        <span className="font-mono">{formatBytes(systemMetrics.network.bytes_recv)}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>发送:</span>
                        <span className="font-mono">{formatBytes(systemMetrics.network.bytes_sent)}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>接收包:</span>
                        <span className="font-mono">{systemMetrics.network.packets_recv.toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>发送包:</span>
                        <span className="font-mono">{systemMetrics.network.packets_sent.toLocaleString()}</span>
                      </div>
                    </div>
                  ) : (
                    <p>加载中...</p>
                  )}
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle>安全与状态</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex justify-between">
                      <span>总威胁数:</span>
                      <span className="font-bold text-red-600">{threats.length}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>高危威胁:</span>
                      <span className="font-bold text-red-600">
                        {threats.filter(t => t.severity === 'critical' || t.severity === 'high').length}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span>活跃连接:</span>
                      <span className="font-bold text-blue-600">{networkConnections.length}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>运行进程:</span>
                      <span className="font-bold text-green-600">{processes.length}</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Network Tab */}
          <TabsContent value="network">
            <Card>
              <CardHeader>
                <CardTitle>网络连接 ({networkConnections.length})</CardTitle>
              </CardHeader>
              <CardContent className="overflow-auto max-h-96">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b">
                      <th className="text-left p-2">协议</th>
                      <th className="text-left p-2">本地地址</th>
                      <th className="text-left p-2">远程地址</th>
                      <th className="text-left p-2">状态</th>
                      <th className="text-left p-2">进程</th>
                    </tr>
                  </thead>
                  <tbody>
                    {networkConnections.length > 0 ? networkConnections.map((c, i) => (
                      <tr key={i} className="border-b hover:bg-gray-50">
                        <td className="p-2">
                          <Badge variant="outline">{c.protocol}</Badge>
                        </td>
                        <td className="p-2 font-mono text-xs">{c.local_addr}</td>
                        <td className="p-2 font-mono text-xs">{c.remote_addr || '-'}</td>
                        <td className="p-2">
                          <Badge variant={c.state === 'LISTEN' ? 'default' : 'secondary'}>
                            {c.state}
                          </Badge>
                        </td>
                        <td className="p-2">{c.process_name}</td>
                      </tr>
                    )) : (
                      <tr>
                        <td colSpan={5} className="text-center p-8 text-gray-500">
                          {wsStatus === 'connected' ? '无网络连接数据' : '等待连接...'}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Processes Tab */}
          <TabsContent value="processes">
            <Card>
              <CardHeader>
                <CardTitle>进程监控 ({processes.length})</CardTitle>
              </CardHeader>
              <CardContent className="overflow-auto max-h-96">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b">
                      <th className="text-left p-2">PID</th>
                      <th className="text-left p-2">进程名</th>
                      <th className="text-left p-2">CPU%</th>
                      <th className="text-left p-2">Mem%</th>
                      <th className="text-left p-2">状态</th>
                    </tr>
                  </thead>
                  <tbody>
                    {processes.length > 0 ? processes.map(p => (
                      <tr key={p.pid} className="border-b hover:bg-gray-50">
                        <td className="p-2 font-mono">{p.pid}</td>
                        <td className="p-2 font-medium">{p.name}</td>
                        <td className="p-2">{p.cpu_usage.toFixed(1)}</td>
                        <td className="p-2">{p.memory.toFixed(1)}</td>
                        <td className="p-2">
                          <Badge variant="secondary">{p.status}</Badge>
                        </td>
                      </tr>
                    )) : (
                      <tr>
                        <td colSpan={5} className="text-center p-8 text-gray-500">
                          {wsStatus === 'connected' ? '无进程数据' : '等待连接...'}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Threats Tab */}
          <TabsContent value="threats">
            <Card>
              <CardHeader>
                <CardTitle>威胁检测 ({threats.length})</CardTitle>
              </CardHeader>
              <CardContent className="overflow-auto max-h-96 space-y-4">
                {threats.length === 0 ? (
                  <div className="text-center py-8 text-green-600">✅ 暂无威胁</div>
                ) : (
                  threats.map(t => (
                    <Alert key={t.id} className="border-l-4 border-red-500">
                      <AlertDescription>
                        <div className="flex items-start justify-between">
                          <div>
                            <div className="flex items-center space-x-2 mb-2">
                              <Badge variant={getSeverityColor(t.severity)}>
                                {t.severity.toUpperCase()}
                              </Badge>
                              <Badge variant="outline">{t.type}</Badge>
                              <span className="text-xs text-gray-500">
                                {new Date(t.timestamp).toLocaleString()}
                              </span>
                            </div>
                            <div className="font-medium mb-1">{t.description}</div>
                            <div className="text-sm text-gray-600">
                              来源: <span className="font-mono">{t.source}</span>
                            </div>
                          </div>
                          <Badge variant="destructive">{t.status}</Badge>
                        </div>
                      </AlertDescription>
                    </Alert>
                  ))
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* System Tab */}
          <TabsContent value="system">
            <Card>
              <CardHeader>
                <CardTitle>系统信息</CardTitle>
              </CardHeader>
              <CardContent>
                {systemInfo ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="space-y-2">
                      <h3 className="font-semibold text-lg mb-2">基本信息</h3>
                      <div className="flex justify-between">
                        <span>主机名:</span>
                        <span className="font-mono">{systemInfo.hostname}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>操作系统:</span>
                        <span className="font-mono">{systemInfo.os}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>平台:</span>
                        <span className="font-mono">{systemInfo.platform}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>运行时间:</span>
                        <span className="font-mono">{Math.floor(systemInfo.uptime / 3600)}h</span>
                      </div>
                    </div>
                    <div className="space-y-2">
                      <h3 className="font-semibold text-lg mb-2">硬件信息</h3>
                      <div className="flex justify-between">
                        <span>CPU:</span>
                        <span className="font-mono text-xs">{systemInfo.cpu_model}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>核心数:</span>
                        <span className="font-mono">{systemInfo.cpu_cores}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>总内存:</span>
                        <span className="font-mono">{formatBytes(systemInfo.total_memory)}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>数据模式:</span>
                        <Badge variant={systemInfo.real_data_enabled ? 'default' : 'secondary'}>
                          {systemInfo.real_data_enabled ? '真实数据' : '模拟数据'}
                        </Badge>
                      </div>
                    </div>
                  </div>
                ) : (
                  <p>加载中...</p>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}
