'use client'

import React, { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Activity, Shield, Server, Network, AlertTriangle, CheckCircle, XCircle, Cpu, HardDrive, MemoryStick, Wifi, Users, Eye } from 'lucide-react'

// 类型定义
interface SystemData {
  timestamp: string
  cpu: {
    usage: number
    cores: number
    load_avg: number
    frequency: number
  }
  memory: {
    total: number
    used: number
    available: number
    usage_percent: number
    swap_total: number
    swap_used: number
  }
  disk: {
    total: number
    used: number
    free: number
    usage_percent: number
  }
  network: {
    bytes_sent: number
    bytes_recv: number
    packets_sent: number
    packets_recv: number
    connections: number
    listen_ports: number[]
    interfaces: Array<{
      name: string
      bytes_sent: number
      bytes_recv: number
      is_up: boolean
    }>
  }
  processes: Array<{
    pid: number
    name: string
    cpu_percent: number
    memory_mb: number
    status: string
    create_time: number
    connections: number
  }>
  connections: Array<{
    local_addr: string
    remote_addr: string
    status: string
    pid: number
    process: string
  }>
  threats: Array<{
    id: string
    type: string
    level: string
    source: string
    target: string
    description: string
    timestamp: string
    count: number
    status: string
  }>
  system_info: {
    hostname: string
    os: string
    platform: string
    platform_version: string
    architecture: string
    uptime: number
    boot_time: number
  }
}

interface Agent {
  id: string
  name: string
  host: string
  port: number
  status: string
  last_seen: string
  version?: string
  os?: string
}

export default function NetworkMonitoringDashboard() {
  const [systemData, setSystemData] = useState<SystemData | null>(null)
  const [agents, setAgents] = useState<Agent[]>([])
  const [threats, setThreats] = useState<any[]>([])
  const [connectionStatus, setConnectionStatus] = useState<'connecting' | 'connected' | 'disconnected'>('connecting')
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date())

  // WebSocket连接
  useEffect(() => {
    let ws: WebSocket | null = null
    let reconnectTimer: NodeJS.Timeout | null = null

    const connectWebSocket = () => {
      try {
        // 根据当前页面协议选择WebSocket协议
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
        const wsUrl = `${protocol}//${window.location.host}/api/ws`
        
        console.log('连接WebSocket:', wsUrl)
        ws = new WebSocket(wsUrl)

        ws.onopen = () => {
          console.log('WebSocket连接已建立')
          setConnectionStatus('connected')
          if (reconnectTimer) {
            clearTimeout(reconnectTimer)
            reconnectTimer = null
          }
        }

        ws.onmessage = (event) => {
          try {
            const data: SystemData = JSON.parse(event.data)
            setSystemData(data)
            setLastUpdate(new Date())
          } catch (error) {
            console.error('解析WebSocket数据失败:', error)
          }
        }

        ws.onclose = () => {
          console.log('WebSocket连接已关闭')
          setConnectionStatus('disconnected')
          
          // 5秒后重连
          if (!reconnectTimer) {
            reconnectTimer = setTimeout(() => {
              console.log('尝试重新连接WebSocket...')
              connectWebSocket()
            }, 5000)
          }
        }

        ws.onerror = (error) => {
          console.error('WebSocket错误:', error)
          setConnectionStatus('disconnected')
        }

      } catch (error) {
        console.error('创建WebSocket连接失败:', error)
        setConnectionStatus('disconnected')
        
        // 5秒后重试
        if (!reconnectTimer) {
          reconnectTimer = setTimeout(connectWebSocket, 5000)
        }
      }
    }

    // 初始连接
    connectWebSocket()

    // 清理函数
    return () => {
      if (reconnectTimer) {
        clearTimeout(reconnectTimer)
      }
      if (ws) {
        ws.close()
      }
    }
  }, [])

  // 获取代理数据
  useEffect(() => {
    const fetchAgents = async () => {
      try {
        const response = await fetch('/api/agents')
        if (response.ok) {
          const data = await response.json()
          setAgents(data)
        }
      } catch (error) {
        console.error('获取代理数据失败:', error)
      }
    }

    fetchAgents()
    const interval = setInterval(fetchAgents, 30000) // 每30秒更新一次

    return () => clearInterval(interval)
  }, [])

  // 获取威胁数据
  useEffect(() => {
    const fetchThreats = async () => {
      try {
        const response = await fetch('/api/threats')
        if (response.ok) {
          const data = await response.json()
          setThreats(data)
        }
      } catch (error) {
        console.error('获取威胁数据失败:', error)
      }
    }

    fetchThreats()
    const interval = setInterval(fetchThreats, 15000) // 每15秒更新一次

    return () => clearInterval(interval)
  }, [])

  // 格式化字节数
  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  // 格式化时间
  const formatUptime = (seconds: number): string => {
    const days = Math.floor(seconds / 86400)
    const hours = Math.floor((seconds % 86400) / 3600)
    const minutes = Math.floor((seconds % 3600) / 60)
    return `${days}天 ${hours}小时 ${minutes}分钟`
  }

  // 获取威胁级别颜色
  const getThreatLevelColor = (level: string): string => {
    switch (level.toLowerCase()) {
      case 'critical': return 'bg-red-500'
      case 'high': return 'bg-orange-500'
      case 'medium': return 'bg-yellow-500'
      case 'low': return 'bg-blue-500'
      default: return 'bg-gray-500'
    }
  }

  // 获取威胁级别文本
  const getThreatLevelText = (level: string): string => {
    switch (level.toLowerCase()) {
      case 'critical': return '严重'
      case 'high': return '高危'
      case 'medium': return '中危'
      case 'low': return '低危'
      default: return '未知'
    }
  }

  if (!systemData) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <h2 className="text-xl font-semibold text-gray-700">连接监控系统中...</h2>
          <p className="text-gray-500 mt-2">
            状态: {connectionStatus === 'connecting' ? '连接中' : 
                   connectionStatus === 'connected' ? '已连接' : '连接断开'}
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* 头部 */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center space-x-3">
              <Eye className="h-8 w-8 text-blue-600" />
              <div>
                <h1 className="text-2xl font-bold text-gray-900">天眼网络监控系统</h1>
                <p className="text-sm text-gray-500">实时网络安全监控与威胁检测</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                {connectionStatus === 'connected' ? (
                  <CheckCircle className="h-5 w-5 text-green-500" />
                ) : (
                  <XCircle className="h-5 w-5 text-red-500" />
                )}
                <span className="text-sm text-gray-600">
                  {connectionStatus === 'connected' ? '已连接' : '连接断开'}
                </span>
              </div>
              <div className="text-sm text-gray-500">
                最后更新: {lastUpdate.toLocaleTimeString()}
              </div>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* 系统概览卡片 */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">CPU使用率</CardTitle>
              <Cpu className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{systemData.cpu.usage.toFixed(1)}%</div>
              <Progress value={systemData.cpu.usage} className="mt-2" />
              <p className="text-xs text-muted-foreground mt-2">
                {systemData.cpu.cores} 核心 | 负载: {systemData.cpu.load_avg.toFixed(2)}
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">内存使用</CardTitle>
              <MemoryStick className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{systemData.memory.usage_percent.toFixed(1)}%</div>
              <Progress value={systemData.memory.usage_percent} className="mt-2" />
              <p className="text-xs text-muted-foreground mt-2">
                {formatBytes(systemData.memory.used)} / {formatBytes(systemData.memory.total)}
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">磁盘使用</CardTitle>
              <HardDrive className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{systemData.disk.usage_percent.toFixed(1)}%</div>
              <Progress value={systemData.disk.usage_percent} className="mt-2" />
              <p className="text-xs text-muted-foreground mt-2">
                {formatBytes(systemData.disk.used)} / {formatBytes(systemData.disk.total)}
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">网络连接</CardTitle>
              <Network className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{systemData.network.connections}</div>
              <p className="text-xs text-muted-foreground mt-2">
                活跃连接数
              </p>
              <p className="text-xs text-muted-foreground">
                监听端口: {systemData.network.listen_ports.length}
              </p>
            </CardContent>
          </Card>
        </div>

        {/* 威胁警报 */}
        {threats.length > 0 && (
          <Alert className="mb-6 border-red-200 bg-red-50">
            <AlertTriangle className="h-4 w-4 text-red-600" />
            <AlertDescription className="text-red-800">
              检测到 {threats.length} 个安全威胁，请及时处理！
            </AlertDescription>
          </Alert>
        )}

        {/* 主要内容区域 */}
        <Tabs defaultValue="overview" className="space-y-6">
          <TabsList className="grid w-full grid-cols-5">
            <TabsTrigger value="overview">系统概览</TabsTrigger>
            <TabsTrigger value="agents">监控代理</TabsTrigger>
            <TabsTrigger value="threats">威胁检测</TabsTrigger>
            <TabsTrigger value="network">网络监控</TabsTrigger>
            <TabsTrigger value="processes">进程监控</TabsTrigger>
          </TabsList>

          {/* 系统概览 */}
          <TabsContent value="overview" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>系统信息</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="font-medium">主机名:</span>
                      <p className="text-muted-foreground">{systemData.system_info.hostname}</p>
                    </div>
                    <div>
                      <span className="font-medium">操作系统:</span>
                      <p className="text-muted-foreground">{systemData.system_info.os}</p>
                    </div>
                    <div>
                      <span className="font-medium">平台:</span>
                      <p className="text-muted-foreground">{systemData.system_info.platform}</p>
                    </div>
                    <div>
                      <span className="font-medium">架构:</span>
                      <p className="text-muted-foreground">{systemData.system_info.architecture}</p>
                    </div>
                    <div className="col-span-2">
                      <span className="font-medium">运行时间:</span>
                      <p className="text-muted-foreground">{formatUptime(systemData.system_info.uptime)}</p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>网络接口</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {systemData.network.interfaces.slice(0, 5).map((iface, index) => (
                      <div key={index} className="flex justify-between items-center p-3 bg-gray-50 rounded-lg">
                        <div>
                          <div className="font-medium">{iface.name}</div>
                          <div className="text-sm text-muted-foreground">
                            {iface.is_up ? '活跃' : '非活跃'}
                          </div>
                        </div>
                        <div className="text-right text-sm">
                          <div>↑ {formatBytes(iface.bytes_sent)}</div>
                          <div>↓ {formatBytes(iface.bytes_recv)}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* 监控代理 */}
          <TabsContent value="agents" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Server className="h-5 w-5" />
                  <span>监控代理状态</span>
                </CardTitle>
                <CardDescription>
                  管理和监控所有网络代理的状态
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {agents.map((agent) => (
                    <div key={agent.id} className="p-4 border rounded-lg">
                      <div className="flex justify-between items-start mb-2">
                        <h3 className="font-medium">{agent.name}</h3>
                        <Badge variant={agent.status === 'online' ? 'default' : 'destructive'}>
                          {agent.status === 'online' ? '在线' : '离线'}
                        </Badge>
                      </div>
                      <div className="text-sm text-muted-foreground space-y-1">
                        <p>地址: {agent.host}:{agent.port}</p>
                        <p>最后连接: {new Date(agent.last_seen).toLocaleString()}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* 威胁检测 */}
          <TabsContent value="threats" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Shield className="h-5 w-5" />
                  <span>威胁检测</span>
                </CardTitle>
                <CardDescription>
                  实时监控和分析网络安全威胁
                </CardDescription>
              </CardHeader>
              <CardContent>
                {threats.length === 0 ? (
                  <div className="text-center py-8">
                    <CheckCircle className="h-12 w-12 text-green-500 mx-auto mb-4" />
                    <h3 className="text-lg font-medium text-gray-900 mb-2">暂无威胁</h3>
                    <p className="text-gray-500">系统运行正常，未检测到安全威胁</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {threats.map((threat) => (
                      <div key={threat.id} className="p-4 border rounded-lg">
                        <div className="flex justify-between items-start mb-2">
                          <div className="flex items-center space-x-2">
                            <Badge className={getThreatLevelColor(threat.level)}>
                              {getThreatLevelText(threat.level)}
                            </Badge>
                            <span className="font-medium">{threat.description}</span>
                          </div>
                          <span className="text-sm text-muted-foreground">
                            {new Date(threat.timestamp).toLocaleString()}
                          </span>
                        </div>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                          <div>
                            <span className="font-medium">类型:</span>
                            <p className="text-muted-foreground">{threat.type}</p>
                          </div>
                          <div>
                            <span className="font-medium">来源:</span>
                            <p className="text-muted-foreground">{threat.source}</p>
                          </div>
                          <div>
                            <span className="font-medium">目标:</span>
                            <p className="text-muted-foreground">{threat.target}</p>
                          </div>
                          <div>
                            <span className="font-medium">次数:</span>
                            <p className="text-muted-foreground">{threat.count}</p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* 网络监控 */}
          <TabsContent value="network" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>网络流量</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex justify-between items-center">
                      <span>发送数据:</span>
                      <span className="font-medium">{formatBytes(systemData.network.bytes_sent)}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span>接收数据:</span>
                      <span className="font-medium">{formatBytes(systemData.network.bytes_recv)}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span>发送包数:</span>
                      <span className="font-medium">{systemData.network.packets_sent.toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span>接收包数:</span>
                      <span className="font-medium">{systemData.network.packets_recv.toLocaleString()}</span>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>监听端口</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-4 gap-2">
                    {systemData.network.listen_ports.slice(0, 20).map((port, index) => (
                      <Badge key={index} variant="outline" className="justify-center">
                        {port}
                      </Badge>
                    ))}
                  </div>
                  {systemData.network.listen_ports.length > 20 && (
                    <p className="text-sm text-muted-foreground mt-2">
                      还有 {systemData.network.listen_ports.length - 20} 个端口...
                    </p>
                  )}
                </CardContent>
              </Card>
            </div>

            <Card>
              <CardHeader>
                <CardTitle>网络连接</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b">
                        <th className="text-left p-2">本地地址</th>
                        <th className="text-left p-2">远程地址</th>
                        <th className="text-left p-2">状态</th>
                        <th className="text-left p-2">进程</th>
                      </tr>
                    </thead>
                    <tbody>
                      {systemData.connections.slice(0, 10).map((conn, index) => (
                        <tr key={index} className="border-b">
                          <td className="p-2 font-mono text-xs">{conn.local_addr}</td>
                          <td className="p-2 font-mono text-xs">{conn.remote_addr}</td>
                          <td className="p-2">
                            <Badge variant={conn.status === 'ESTABLISHED' ? 'default' : 'secondary'}>
                              {conn.status}
                            </Badge>
                          </td>
                          <td className="p-2">{conn.process || 'N/A'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* 进程监控 */}
          <TabsContent value="processes" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Activity className="h-5 w-5" />
                  <span>系统进程</span>
                </CardTitle>
                <CardDescription>
                  监控系统中运行的进程资源使用情况
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b">
                        <th className="text-left p-2">PID</th>
                        <th className="text-left p-2">进程名</th>
                        <th className="text-left p-2">CPU%</th>
                        <th className="text-left p-2">内存(MB)</th>
                        <th className="text-left p-2">状态</th>
                        <th className="text-left p-2">连接数</th>
                      </tr>
                    </thead>
                    <tbody>
                      {systemData.processes.map((process) => (
                        <tr key={process.pid} className="border-b">
                          <td className="p-2 font-mono">{process.pid}</td>
                          <td className="p-2">{process.name}</td>
                          <td className="p-2">{process.cpu_percent.toFixed(1)}%</td>
                          <td className="p-2">{process.memory_mb.toFixed(1)}</td>
                          <td className="p-2">
                            <Badge variant="outline">{process.status}</Badge>
                          </td>
                          <td className="p-2">{process.connections}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  )
}
