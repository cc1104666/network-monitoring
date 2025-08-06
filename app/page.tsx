'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Shield, Activity, Network, Server, AlertTriangle, CheckCircle, XCircle, Cpu, HardDrive, Wifi, Users, Globe, Lock, Eye, Zap } from 'lucide-react'

interface SystemMetrics {
  CPUUsage: number
  MemoryUsage: number
  DiskUsage: number
  NetworkIn: number
  NetworkOut: number
  Timestamp: string
}

interface NetworkConnection {
  Protocol: string
  LocalAddr: string
  RemoteAddr: string
  State: string
  Port: number
  ProcessName: string
  Timestamp: string
}

interface HTTPRequest {
  Method: string
  Path: string
  IP: string
  UserAgent: string
  StatusCode: number
  Size: number
  ThreatScore: number
  Timestamp: string
}

interface ProcessInfo {
  PID: number
  Name: string
  CPUUsage: number
  Memory: number
  Status: string
  Timestamp: string
}

interface Threat {
  ID: string
  Type: string
  Severity: string
  Source: string
  Target: string
  Description: string
  Timestamp: string
  Status: string
}

interface Alert {
  ID: string
  Type: string
  Message: string
  Severity: string
  Timestamp: string
  Acknowledged: boolean
}

export default function NetworkMonitoringDashboard() {
  const [systemMetrics, setSystemMetrics] = useState<SystemMetrics | null>(null)
  const [networkConnections, setNetworkConnections] = useState<NetworkConnection[]>([])
  const [httpRequests, setHttpRequests] = useState<HTTPRequest[]>([])
  const [processes, setProcesses] = useState<ProcessInfo[]>([])
  const [threats, setThreats] = useState<Threat[]>([])
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [systemInfo, setSystemInfo] = useState<any>(null)
  const [isConnected, setIsConnected] = useState(false)
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date())

  // 获取系统指标
  const fetchSystemMetrics = async () => {
    try {
      const response = await fetch('http://localhost:8080/api/system')
      if (response.ok) {
        const data = await response.json()
        setSystemMetrics(data)
        setIsConnected(true)
        setLastUpdate(new Date())
      }
    } catch (error) {
      console.error('获取系统指标失败:', error)
      setIsConnected(false)
    }
  }

  // 获取网络连接
  const fetchNetworkConnections = async () => {
    try {
      const response = await fetch('http://localhost:8080/api/network')
      if (response.ok) {
        const data = await response.json()
        setNetworkConnections(data || [])
      }
    } catch (error) {
      console.error('获取网络连接失败:', error)
    }
  }

  // 获取HTTP请求
  const fetchHttpRequests = async () => {
    try {
      const response = await fetch('http://localhost:8080/api/requests')
      if (response.ok) {
        const data = await response.json()
        setHttpRequests(data || [])
      }
    } catch (error) {
      console.error('获取HTTP请求失败:', error)
    }
  }

  // 获取进程信息
  const fetchProcesses = async () => {
    try {
      const response = await fetch('http://localhost:8080/api/processes')
      if (response.ok) {
        const data = await response.json()
        setProcesses(data || [])
      }
    } catch (error) {
      console.error('获取进程信息失败:', error)
    }
  }

  // 获取威胁信息
  const fetchThreats = async () => {
    try {
      const response = await fetch('http://localhost:8080/api/threats')
      if (response.ok) {
        const data = await response.json()
        setThreats(data || [])
      }
    } catch (error) {
      console.error('获取威胁信息失败:', error)
    }
  }

  // 获取告警信息
  const fetchAlerts = async () => {
    try {
      const response = await fetch('http://localhost:8080/api/alerts')
      if (response.ok) {
        const data = await response.json()
        setAlerts(data || [])
      }
    } catch (error) {
      console.error('获取告警信息失败:', error)
    }
  }

  // 获取系统信息
  const fetchSystemInfo = async () => {
    try {
      const response = await fetch('http://localhost:8080/api/info')
      if (response.ok) {
        const data = await response.json()
        setSystemInfo(data)
      }
    } catch (error) {
      console.error('获取系统信息失败:', error)
    }
  }

  // WebSocket连接
  useEffect(() => {
    const connectWebSocket = () => {
      try {
        const ws = new WebSocket('ws://localhost:8080/api/ws')
        
        ws.onopen = () => {
          console.log('WebSocket连接已建立')
          setIsConnected(true)
        }
        
        ws.onmessage = (event) => {
          try {
            const message = JSON.parse(event.data)
            if (message.type === 'metrics') {
              setSystemMetrics(message.data)
              setLastUpdate(new Date())
            }
          } catch (error) {
            console.error('解析WebSocket消息失败:', error)
          }
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
        
        return ws
      } catch (error) {
        console.error('WebSocket连接失败:', error)
        setIsConnected(false)
        return null
      }
    }

    const ws = connectWebSocket()
    
    return () => {
      if (ws) {
        ws.close()
      }
    }
  }, [])

  // 定期获取数据
  useEffect(() => {
    // 立即获取一次数据
    fetchSystemMetrics()
    fetchNetworkConnections()
    fetchHttpRequests()
    fetchProcesses()
    fetchThreats()
    fetchAlerts()
    fetchSystemInfo()

    // 设置定时器
    const interval = setInterval(() => {
      fetchSystemMetrics()
      fetchNetworkConnections()
      fetchHttpRequests()
      fetchProcesses()
      fetchThreats()
      fetchAlerts()
    }, 5000)

    return () => clearInterval(interval)
  }, [])

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'bg-red-500'
      case 'high': return 'bg-orange-500'
      case 'medium': return 'bg-yellow-500'
      case 'low': return 'bg-blue-500'
      default: return 'bg-gray-500'
    }
  }

  const getThreatScoreColor = (score: number) => {
    if (score >= 70) return 'text-red-600'
    if (score >= 50) return 'text-orange-600'
    if (score >= 30) return 'text-yellow-600'
    return 'text-green-600'
  }

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* 头部 */}
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Shield className="h-8 w-8 text-blue-600" />
            <div>
              <h1 className="text-3xl font-bold text-gray-900">网络监控系统</h1>
              <p className="text-gray-600">实时网络安全监控与威胁检测</p>
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2">
              {isConnected ? (
                <CheckCircle className="h-5 w-5 text-green-500" />
              ) : (
                <XCircle className="h-5 w-5 text-red-500" />
              )}
              <span className={`text-sm ${isConnected ? 'text-green-600' : 'text-red-600'}`}>
                {isConnected ? '已连接' : '连接断开'}
              </span>
            </div>
            <Badge variant="outline">
              最后更新: {lastUpdate.toLocaleTimeString()}
            </Badge>
            {systemInfo?.real_data_enabled && (
              <Badge className="bg-green-100 text-green-800">
                真实数据模式
              </Badge>
            )}
          </div>
        </div>

        {/* 系统状态卡片 */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">CPU使用率</CardTitle>
              <Cpu className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {systemMetrics ? `${systemMetrics.CPUUsage.toFixed(1)}%` : '--'}
              </div>
              <Progress 
                value={systemMetrics?.CPUUsage || 0} 
                className="mt-2"
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">内存使用率</CardTitle>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {systemMetrics ? `${systemMetrics.MemoryUsage.toFixed(1)}%` : '--'}
              </div>
              <Progress 
                value={systemMetrics?.MemoryUsage || 0} 
                className="mt-2"
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">磁盘使用率</CardTitle>
              <HardDrive className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {systemMetrics ? `${systemMetrics.DiskUsage.toFixed(1)}%` : '--'}
              </div>
              <Progress 
                value={systemMetrics?.DiskUsage || 0} 
                className="mt-2"
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">网络流量</CardTitle>
              <Wifi className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-sm">
                <div>入: {systemMetrics ? formatBytes(systemMetrics.NetworkIn) : '--'}</div>
                <div>出: {systemMetrics ? formatBytes(systemMetrics.NetworkOut) : '--'}</div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* 告警信息 */}
        {alerts.length > 0 && (
          <div className="space-y-2">
            {alerts.slice(0, 3).map((alert) => (
              <Alert key={alert.ID} className={`border-l-4 ${
                alert.Severity === 'high' ? 'border-red-500' : 
                alert.Severity === 'medium' ? 'border-yellow-500' : 'border-blue-500'
              }`}>
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>
                  <div className="flex items-center justify-between">
                    <span>{alert.Message}</span>
                    <Badge className={getSeverityColor(alert.Severity)}>
                      {alert.Severity}
                    </Badge>
                  </div>
                </AlertDescription>
              </Alert>
            ))}
          </div>
        )}

        {/* 主要内容标签页 */}
        <Tabs defaultValue="overview" className="space-y-4">
          <TabsList className="grid w-full grid-cols-6">
            <TabsTrigger value="overview">概览</TabsTrigger>
            <TabsTrigger value="network">网络连接</TabsTrigger>
            <TabsTrigger value="requests">HTTP请求</TabsTrigger>
            <TabsTrigger value="processes">进程监控</TabsTrigger>
            <TabsTrigger value="threats">威胁检测</TabsTrigger>
            <TabsTrigger value="system">系统信息</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <Network className="h-5 w-5" />
                    <span>网络连接统计</span>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <span>总连接数:</span>
                      <span className="font-bold">{networkConnections.length}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>监听端口:</span>
                      <span className="font-bold">
                        {networkConnections.filter(c => c.State === 'LISTEN').length}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span>已建立连接:</span>
                      <span className="font-bold">
                        {networkConnections.filter(c => c.State === 'ESTABLISHED').length}
                      </span>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <Globe className="h-5 w-5" />
                    <span>HTTP请求统计</span>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <span>总请求数:</span>
                      <span className="font-bold">{httpRequests.length}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>高威胁请求:</span>
                      <span className="font-bold text-red-600">
                        {httpRequests.filter(r => r.ThreatScore > 50).length}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span>成功请求:</span>
                      <span className="font-bold text-green-600">
                        {httpRequests.filter(r => r.StatusCode === 200).length}
                      </span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="network" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Network className="h-5 w-5" />
                  <span>网络连接详情</span>
                </CardTitle>
                <CardDescription>
                  当前系统的所有网络连接状态
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b">
                        <th className="text-left p-2">协议</th>
                        <th className="text-left p-2">本地地址</th>
                        <th className="text-left p-2">远程地址</th>
                        <th className="text-left p-2">状态</th>
                        <th className="text-left p-2">端口</th>
                      </tr>
                    </thead>
                    <tbody>
                      {networkConnections.slice(0, 10).map((conn, index) => (
                        <tr key={index} className="border-b hover:bg-gray-50">
                          <td className="p-2">
                            <Badge variant="outline">{conn.Protocol}</Badge>
                          </td>
                          <td className="p-2 font-mono text-xs">{conn.LocalAddr}</td>
                          <td className="p-2 font-mono text-xs">{conn.RemoteAddr || '--'}</td>
                          <td className="p-2">
                            <Badge className={
                              conn.State === 'LISTEN' ? 'bg-blue-100 text-blue-800' :
                              conn.State === 'ESTABLISHED' ? 'bg-green-100 text-green-800' :
                              'bg-gray-100 text-gray-800'
                            }>
                              {conn.State}
                            </Badge>
                          </td>
                          <td className="p-2">{conn.Port}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="requests" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Globe className="h-5 w-5" />
                  <span>HTTP请求监控</span>
                </CardTitle>
                <CardDescription>
                  实时HTTP请求分析与威胁评分
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b">
                        <th className="text-left p-2">方法</th>
                        <th className="text-left p-2">路径</th>
                        <th className="text-left p-2">IP地址</th>
                        <th className="text-left p-2">状态码</th>
                        <th className="text-left p-2">威胁分数</th>
                        <th className="text-left p-2">时间</th>
                      </tr>
                    </thead>
                    <tbody>
                      {httpRequests.slice(0, 10).map((req, index) => (
                        <tr key={index} className="border-b hover:bg-gray-50">
                          <td className="p-2">
                            <Badge variant="outline">{req.Method}</Badge>
                          </td>
                          <td className="p-2 font-mono text-xs">{req.Path}</td>
                          <td className="p-2">{req.IP}</td>
                          <td className="p-2">
                            <Badge className={
                              req.StatusCode === 200 ? 'bg-green-100 text-green-800' :
                              req.StatusCode === 404 ? 'bg-yellow-100 text-yellow-800' :
                              'bg-red-100 text-red-800'
                            }>
                              {req.StatusCode}
                            </Badge>
                          </td>
                          <td className="p-2">
                            <span className={getThreatScoreColor(req.ThreatScore)}>
                              {req.ThreatScore}
                            </span>
                          </td>
                          <td className="p-2 text-xs">
                            {new Date(req.Timestamp).toLocaleTimeString()}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="processes" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Server className="h-5 w-5" />
                  <span>进程监控</span>
                </CardTitle>
                <CardDescription>
                  系统进程资源使用情况
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b">
                        <th className="text-left p-2">PID</th>
                        <th className="text-left p-2">进程名</th>
                        <th className="text-left p-2">CPU使用率</th>
                        <th className="text-left p-2">内存使用率</th>
                        <th className="text-left p-2">状态</th>
                      </tr>
                    </thead>
                    <tbody>
                      {processes.slice(0, 10).map((proc, index) => (
                        <tr key={index} className="border-b hover:bg-gray-50">
                          <td className="p-2">{proc.PID}</td>
                          <td className="p-2 font-mono">{proc.Name}</td>
                          <td className="p-2">{proc.CPUUsage.toFixed(1)}%</td>
                          <td className="p-2">{proc.Memory.toFixed(1)}%</td>
                          <td className="p-2">
                            <Badge className="bg-green-100 text-green-800">
                              {proc.Status}
                            </Badge>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="threats" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Lock className="h-5 w-5" />
                  <span>威胁检测</span>
                </CardTitle>
                <CardDescription>
                  实时安全威胁分析与检测
                </CardDescription>
              </CardHeader>
              <CardContent>
                {threats.length > 0 ? (
                  <div className="space-y-4">
                    {threats.map((threat) => (
                      <div key={threat.ID} className="border rounded-lg p-4">
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center space-x-2">
                            <AlertTriangle className="h-5 w-5 text-red-500" />
                            <span className="font-semibold">{threat.Description}</span>
                          </div>
                          <Badge className={getSeverityColor(threat.Severity)}>
                            {threat.Severity}
                          </Badge>
                        </div>
                        <div className="grid grid-cols-2 gap-4 text-sm text-gray-600">
                          <div>来源: {threat.Source}</div>
                          <div>目标: {threat.Target}</div>
                          <div>类型: {threat.Type}</div>
                          <div>时间: {new Date(threat.Timestamp).toLocaleString()}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8 text-gray-500">
                    <Shield className="h-12 w-12 mx-auto mb-4 text-gray-300" />
                    <p>暂无检测到威胁</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="system" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Eye className="h-5 w-5" />
                  <span>系统信息</span>
                </CardTitle>
                <CardDescription>
                  系统配置与运行状态
                </CardDescription>
              </CardHeader>
              <CardContent>
                {systemInfo ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-2">
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
                        <span className="font-mono">
                          {Math.floor((systemInfo.uptime || 0) / 3600)}小时
                        </span>
                      </div>
                    </div>
                    <div className="space-y-2">
                      <div className="flex justify-between">
                        <span>CPU型号:</span>
                        <span className="font-mono text-xs">{systemInfo.cpu_model}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>CPU核心数:</span>
                        <span className="font-mono">{systemInfo.cpu_cores}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>总内存:</span>
                        <span className="font-mono">
                          {formatBytes(systemInfo.total_memory || 0)}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span>可用内存:</span>
                        <span className="font-mono">
                          {formatBytes(systemInfo.available_memory || 0)}
                        </span>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8 text-gray-500">
                    <Zap className="h-12 w-12 mx-auto mb-4 text-gray-300" />
                    <p>正在加载系统信息...</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}
