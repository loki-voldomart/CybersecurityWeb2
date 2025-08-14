"use client"

import { useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Progress } from "@/components/ui/progress"
import {
  Shield,
  AlertTriangle,
  Activity,
  Eye,
  Ban,
  Zap,
  Network,
  Lock,
  Skull,
  ChevronLeft,
  ChevronRight,
  Wifi,
  WifiOff,
  Brain,
  Bot,
} from "lucide-react"
import { useRealtimeThreats, useRealtimeStats, useRealtimeSystemStatus, useWebSocket } from "@/lib/websocket-client"
import MLDashboard from "@/components/ml-dashboard"

interface ThreatEvent {
  id: string
  threat_type: "dos" | "port_scan" | "malware" | "phishing"
  severity: "low" | "medium" | "high" | "critical"
  source_ip: string
  target_ip?: string
  port?: number
  description: string
  status: "active" | "blocked" | "investigating" | "resolved"
  detected_at: string
}

export default function CyberSecurityDashboard() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [activeTab, setActiveTab] = useState("overview")
  const [defenseMode, setDefenseMode] = useState({
    lockdown: false,
    autoBlock: false,
    scanning: false,
  })

  const { threats, loading: threatsLoading } = useRealtimeThreats()
  const stats = useRealtimeStats()
  const systems = useRealtimeSystemStatus()
  const { isConnected, connectionError } = useWebSocket()

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "border-red-500 bg-red-500/10 text-red-400"
      case "high":
        return "border-orange-500 bg-orange-500/10 text-orange-400"
      case "medium":
        return "border-yellow-500 bg-yellow-500/10 text-yellow-400"
      case "low":
        return "border-green-500 bg-green-500/10 text-green-400"
      default:
        return "border-gray-500 bg-gray-500/10 text-gray-400"
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case "active":
        return "bg-red-500 text-white"
      case "blocked":
        return "bg-green-500 text-white"
      case "investigating":
        return "bg-yellow-500 text-black"
      case "resolved":
        return "bg-blue-500 text-white"
      default:
        return "bg-gray-500 text-white"
    }
  }

  const handleThreatAction = async (threatId: string, action: string) => {
    try {
      const response = await fetch(`/api/threats/${threatId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          status: action === "block" ? "blocked" : "investigating",
        }),
      })

      if (response.ok) {
        // Also trigger defense action
        await fetch("/api/defense-actions", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            threat_event_id: threatId,
            action_type: action === "block" ? "block_ip" : "investigate",
            executed_by: "dashboard_user",
          }),
        })
      }
    } catch (error) {
      console.error("Error handling threat action:", error)
    }
  }

  const handleDefenseAction = async (action: string) => {
    try {
      const newMode = { ...defenseMode }

      switch (action) {
        case "lockdown":
          newMode.lockdown = !defenseMode.lockdown
          break
        case "autoblock":
          newMode.autoBlock = !defenseMode.autoBlock
          break
        case "scan":
          newMode.scanning = true
          // Reset scanning after 5 seconds
          setTimeout(() => {
            setDefenseMode((prev) => ({ ...prev, scanning: false }))
          }, 5000)
          break
      }

      setDefenseMode(newMode)

      // Send to API
      await fetch("/api/defense-actions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action_type: action,
          executed_by: "dashboard_user",
          status: "active",
        }),
      })
    } catch (error) {
      console.error("Defense action error:", error)
    }
  }

  const getSystemStatusBadge = (status: string) => {
    switch (status) {
      case "online":
        return <Badge className="bg-green-500 text-white">ACTIVE</Badge>
      case "warning":
        return <Badge className="bg-yellow-500 text-black">WARNING</Badge>
      case "error":
        return <Badge className="bg-red-500 text-white">ERROR</Badge>
      case "offline":
        return <Badge className="bg-gray-500 text-white">OFFLINE</Badge>
      default:
        return <Badge className="bg-gray-500 text-white">UNKNOWN</Badge>
    }
  }

  const renderTabContent = () => {
    switch (activeTab) {
      case "threats":
        return (
          <Card className="bg-gray-900/50 border-red-500/30 backdrop-blur-sm">
            <CardHeader>
              <CardTitle className="text-red-400 flex items-center">
                <AlertTriangle className="w-5 h-5 mr-2" />
                THREAT MANAGEMENT
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <Card className="bg-gray-800/50 border-red-400/30">
                    <CardContent className="p-4">
                      <h3 className="text-red-400 font-bold">Critical Threats</h3>
                      <p className="text-2xl text-red-400">{threats.filter((t) => t.severity === "critical").length}</p>
                    </CardContent>
                  </Card>
                  <Card className="bg-gray-800/50 border-yellow-400/30">
                    <CardContent className="p-4">
                      <h3 className="text-yellow-400 font-bold">Active Investigations</h3>
                      <p className="text-2xl text-yellow-400">
                        {threats.filter((t) => t.status === "investigating").length}
                      </p>
                    </CardContent>
                  </Card>
                </div>
                <div className="space-y-2">
                  {threats.map((threat) => (
                    <div key={threat.id} className="p-3 bg-gray-800/30 border border-gray-600 rounded">
                      <div className="flex justify-between items-center">
                        <span className="text-green-400">{threat.threat_type?.toUpperCase() || "UNKNOWN"}</span>
                        <Badge className={getStatusColor(threat.status || "unknown")}>
                          {(threat.status || "unknown").toUpperCase()}
                        </Badge>
                      </div>
                      <p className="text-gray-300 text-sm mt-1">{threat.description}</p>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        )

      case "network":
        return (
          <Card className="bg-gray-900/50 border-cyan-500/30 backdrop-blur-sm">
            <CardHeader>
              <CardTitle className="text-cyan-400 flex items-center">
                <Network className="w-5 h-5 mr-2" />
                NETWORK MONITORING
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="grid grid-cols-3 gap-4">
                  <Card className="bg-gray-800/50 border-green-400/30">
                    <CardContent className="p-4">
                      <h3 className="text-green-400 font-bold">Bandwidth</h3>
                      <p className="text-xl text-green-400">{stats.bandwidth || "1.2"} GB/s</p>
                    </CardContent>
                  </Card>
                  <Card className="bg-gray-800/50 border-blue-400/30">
                    <CardContent className="p-4">
                      <h3 className="text-blue-400 font-bold">Packets/sec</h3>
                      <p className="text-xl text-blue-400">{stats.packetsPerSecond || "45,231"}</p>
                    </CardContent>
                  </Card>
                  <Card className="bg-gray-800/50 border-purple-400/30">
                    <CardContent className="p-4">
                      <h3 className="text-purple-400 font-bold">Latency</h3>
                      <p className="text-xl text-purple-400">{stats.latency || "12"}ms</p>
                    </CardContent>
                  </Card>
                </div>
                <div className="p-4 bg-gray-800/30 border border-gray-600 rounded">
                  <h3 className="text-cyan-400 font-bold mb-2">Network Activity</h3>
                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <span className="text-gray-300">Inbound Traffic</span>
                      <span className="text-green-400">Normal</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-300">Outbound Traffic</span>
                      <span className="text-green-400">Normal</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-300">Port Scans Detected</span>
                      <span className="text-yellow-400">
                        {threats.filter((t) => t.threat_type === "port_scan").length}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        )

      case "defense":
        return (
          <Card className="bg-gray-900/50 border-green-500/30 backdrop-blur-sm">
            <CardHeader>
              <CardTitle className="text-green-400 flex items-center">
                <Shield className="w-5 h-5 mr-2" />
                DEFENSE SYSTEMS
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <Card className="bg-gray-800/50 border-green-400/30">
                    <CardContent className="p-4">
                      <h3 className="text-green-400 font-bold">Firewall Status</h3>
                      <p className="text-green-400">{defenseMode.lockdown ? "LOCKDOWN ACTIVE" : "ACTIVE"}</p>
                    </CardContent>
                  </Card>
                  <Card className="bg-gray-800/50 border-blue-400/30">
                    <CardContent className="p-4">
                      <h3 className="text-blue-400 font-bold">Auto-Block</h3>
                      <p className="text-blue-400">{defenseMode.autoBlock ? "ENABLED" : "DISABLED"}</p>
                    </CardContent>
                  </Card>
                </div>
                <div className="space-y-3">
                  <Button
                    className={`w-full ${defenseMode.lockdown ? "bg-red-800 hover:bg-red-900" : "bg-red-600 hover:bg-red-700"} text-white`}
                    onClick={() => handleDefenseAction("lockdown")}
                  >
                    <Lock className="w-4 h-4 mr-2" />
                    {defenseMode.lockdown ? "DISABLE LOCKDOWN" : "ENABLE LOCKDOWN"}
                  </Button>
                  <Button
                    className={`w-full ${defenseMode.autoBlock ? "bg-yellow-800 hover:bg-yellow-900" : "bg-yellow-600 hover:bg-yellow-700"} text-white`}
                    onClick={() => handleDefenseAction("autoblock")}
                  >
                    <Zap className="w-4 h-4 mr-2" />
                    {defenseMode.autoBlock ? "DISABLE AUTO-BLOCK" : "ENABLE AUTO-BLOCK"}
                  </Button>
                  <Button
                    className="w-full bg-green-600 hover:bg-green-700 text-white"
                    onClick={() => handleDefenseAction("scan")}
                    disabled={defenseMode.scanning}
                  >
                    <Activity className="w-4 h-4 mr-2" />
                    {defenseMode.scanning ? "SCANNING..." : "SCAN NETWORK"}
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        )

      case "analytics":
        return (
          <Card className="bg-gray-900/50 border-purple-500/30 backdrop-blur-sm">
            <CardHeader>
              <CardTitle className="text-purple-400 flex items-center">
                <Eye className="w-5 h-5 mr-2" />
                SECURITY ANALYTICS
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <Card className="bg-gray-800/50 border-purple-400/30">
                    <CardContent className="p-4">
                      <h3 className="text-purple-400 font-bold">Threat Score</h3>
                      <p className="text-2xl text-purple-400">{Math.floor(Math.random() * 100)}/100</p>
                    </CardContent>
                  </Card>
                  <Card className="bg-gray-800/50 border-orange-400/30">
                    <CardContent className="p-4">
                      <h3 className="text-orange-400 font-bold">Risk Level</h3>
                      <p className="text-orange-400">
                        {stats.activeThreats > 5 ? "HIGH" : stats.activeThreats > 2 ? "MEDIUM" : "LOW"}
                      </p>
                    </CardContent>
                  </Card>
                </div>
                <div className="p-4 bg-gray-800/30 border border-gray-600 rounded">
                  <h3 className="text-purple-400 font-bold mb-2">Attack Patterns</h3>
                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <span className="text-gray-300">DoS Attacks</span>
                      <span className="text-red-400">{threats.filter((t) => t.threat_type === "dos").length}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-300">Port Scans</span>
                      <span className="text-yellow-400">
                        {threats.filter((t) => t.threat_type === "port_scan").length}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-300">Malware</span>
                      <span className="text-orange-400">
                        {threats.filter((t) => t.threat_type === "malware").length}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-300">Phishing</span>
                      <span className="text-blue-400">
                        {threats.filter((t) => t.threat_type === "phishing").length}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        )

      default:
        return (
          <>
            {/* Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
              <Card className="bg-gray-900/50 border-green-500/30 backdrop-blur-sm">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-green-400/70 text-sm">CONNECTIONS</p>
                      <p className="text-2xl font-bold text-green-400">{stats.totalConnections}</p>
                    </div>
                    <Network className="w-8 h-8 text-green-400" />
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-gray-900/50 border-red-500/30 backdrop-blur-sm">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-red-400/70 text-sm">ACTIVE THREATS</p>
                      <p className="text-2xl font-bold text-red-400">{stats.activeThreats}</p>
                    </div>
                    <Skull className="w-8 h-8 text-red-400" />
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-gray-900/50 border-yellow-500/30 backdrop-blur-sm">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-yellow-400/70 text-sm">BLOCKED</p>
                      <p className="text-2xl font-bold text-yellow-400">{stats.blockedAttacks}</p>
                    </div>
                    <Ban className="w-8 h-8 text-yellow-400" />
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-gray-900/50 border-cyan-500/30 backdrop-blur-sm">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-cyan-400/70 text-sm">SYSTEM HEALTH</p>
                      <p className="text-2xl font-bold text-cyan-400">{stats.systemHealth}%</p>
                    </div>
                    <Activity className="w-8 h-8 text-cyan-400" />
                  </div>
                  <Progress value={stats.systemHealth} className="mt-2" />
                </CardContent>
              </Card>
            </div>

            {/* Main Content Area */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Threat Feed */}
              <div className="lg:col-span-2">
                <Card className="bg-gray-900/50 border-red-500/30 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="text-red-400 flex items-center">
                      <AlertTriangle className="w-5 h-5 mr-2" />
                      ACTIVE THREAT FEED
                      {isConnected && <div className="ml-2 w-2 h-2 bg-red-400 rounded-full animate-pulse" />}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {threatsLoading ? (
                      <div className="text-center text-gray-400 py-8">Loading threats...</div>
                    ) : threats.length === 0 ? (
                      <div className="text-center text-gray-400 py-8">No active threats detected</div>
                    ) : (
                      <div className="space-y-4">
                        {threats.map((threat) => (
                          <Alert key={threat.id} className={`${getSeverityColor(threat.severity)} border-2`}>
                            <div className="flex items-start justify-between">
                              <div className="flex-1">
                                <div className="flex items-center space-x-2 mb-2">
                                  <Badge className={getStatusColor(threat.status || "unknown")}>
                                    {(threat.status || "unknown").toUpperCase()}
                                  </Badge>
                                  <Badge variant="outline" className="text-cyan-400 border-cyan-400">
                                    {(threat.threat_type || "unknown").toUpperCase()}
                                  </Badge>
                                  <span className="text-xs text-gray-400">
                                    {new Date(threat.detected_at).toLocaleTimeString()}
                                  </span>
                                </div>
                                <AlertDescription className="text-white mb-2">{threat.description}</AlertDescription>
                                <div className="text-xs text-gray-400">
                                  <span>Source: {threat.source_ip}</span>
                                  {threat.target_ip && <span> → Target: {threat.target_ip}</span>}
                                  {threat.port && <span> Port: {threat.port}</span>}
                                </div>
                              </div>
                              <div className="flex space-x-2 ml-4">
                                <Button
                                  size="sm"
                                  variant="outline"
                                  className="text-cyan-400 border-cyan-400 hover:bg-cyan-500/20 bg-transparent"
                                  onClick={() => handleThreatAction(threat.id, "investigate")}
                                >
                                  <Eye className="w-3 h-3 mr-1" />
                                  Analyze
                                </Button>
                                <Button
                                  size="sm"
                                  variant="outline"
                                  className="text-red-400 border-red-400 hover:bg-red-500/20 bg-transparent"
                                  onClick={() => handleThreatAction(threat.id, "block")}
                                >
                                  <Ban className="w-3 h-3 mr-1" />
                                  Block
                                </Button>
                              </div>
                            </div>
                          </Alert>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              </div>

              {/* Control Panel */}
              <div className="space-y-6">
                {/* Defense Actions */}
                <Card className="bg-gray-900/50 border-green-500/30 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="text-green-400 flex items-center">
                      <Shield className="w-5 h-5 mr-2" />
                      DEFENSE CONTROLS
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <Button
                      className={`w-full ${defenseMode.lockdown ? "bg-red-800 hover:bg-red-900" : "bg-red-600 hover:bg-red-700"} text-white`}
                      onClick={() => handleDefenseAction("lockdown")}
                    >
                      <Lock className="w-4 h-4 mr-2" />
                      {defenseMode.lockdown ? "LOCKDOWN ACTIVE" : "LOCKDOWN MODE"}
                    </Button>
                    <Button
                      className={`w-full ${defenseMode.autoBlock ? "bg-yellow-800 hover:bg-yellow-900" : "bg-yellow-600 hover:bg-yellow-700"} text-white`}
                      onClick={() => handleDefenseAction("autoblock")}
                    >
                      <Zap className="w-4 h-4 mr-2" />
                      {defenseMode.autoBlock ? "AUTO-BLOCK ON" : "AUTO-BLOCK IPS"}
                    </Button>
                    <Button
                      className="w-full bg-green-600 hover:bg-green-700 text-white"
                      onClick={() => handleDefenseAction("scan")}
                      disabled={defenseMode.scanning}
                    >
                      <Activity className="w-4 h-4 mr-2" />
                      {defenseMode.scanning ? "SCANNING..." : "SCAN NETWORK"}
                    </Button>
                  </CardContent>
                </Card>

                {/* System Status */}
                <Card className="bg-gray-900/50 border-cyan-500/30 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="text-cyan-400">SYSTEM STATUS</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {systems.length === 0 ? (
                      <div className="text-gray-400 text-sm">Loading system status...</div>
                    ) : (
                      systems.map((system) => (
                        <div key={system.id} className="flex justify-between items-center">
                          <span className="text-green-400 capitalize">{system.component}</span>
                          {getSystemStatusBadge(system.status)}
                        </div>
                      ))
                    )}
                  </CardContent>
                </Card>
              </div>
            </div>
          </>
        )
    }
  }

  return (
    <div className="min-h-screen bg-black text-green-400 font-mono">
      {/* Cyberpunk Grid Background */}
      <div className="fixed inset-0 opacity-10">
        <div
          className="absolute inset-0"
          style={{
            backgroundImage: `
            linear-gradient(rgba(0,255,255,0.1) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0,255,255,0.1) 1px, transparent 1px)
          `,
            backgroundSize: "50px 50px",
          }}
        />
      </div>

      <div className="relative flex">
        {/* Sidebar */}
        <div
          className={`${sidebarCollapsed ? "w-16" : "w-64"} transition-all duration-300 bg-gray-900/50 border-r border-cyan-500/30 backdrop-blur-sm`}
        >
          <div className="p-4">
            <div className="flex items-center justify-between mb-8">
              {!sidebarCollapsed && (
                <div className="flex items-center space-x-2">
                  <Shield className="w-8 h-8 text-cyan-400" />
                  <span className="text-xl font-bold text-cyan-400">CYBERDEFENSE</span>
                </div>
              )}
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
                className="text-cyan-400 hover:bg-cyan-500/20"
              >
                {sidebarCollapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
              </Button>
            </div>

            <nav className="space-y-2">
              {[
                { id: "overview", label: "Overview", icon: Activity },
                { id: "threats", label: "Threats", icon: AlertTriangle },
                { id: "network", label: "Network", icon: Network },
                { id: "defense", label: "Defense", icon: Shield },
                { id: "analytics", label: "Analytics", icon: Eye },
              ].map(({ id, label, icon: Icon }) => (
                <Button
                  key={id} // ensuring unique key is present
                  variant="ghost"
                  className={`w-full justify-start ${activeTab === id ? "bg-cyan-500/20 text-cyan-400" : "text-green-400 hover:bg-green-500/20"}`}
                  onClick={() => setActiveTab(id)}
                >
                  <Icon className="w-4 h-4" />
                  {!sidebarCollapsed && <span className="ml-2">{label}</span>}
                </Button>
              ))}
            </nav>

            {!sidebarCollapsed && (
              <div className="mt-8 p-3 bg-gray-800/50 rounded border border-gray-700">
                <div className="flex items-center space-x-2">
                  {isConnected ? (
                    <>
                      <Wifi className="w-4 h-4 text-green-400" />
                      <span className="text-xs text-green-400">LIVE MONITORING</span>
                    </>
                  ) : (
                    <>
                      <WifiOff className="w-4 h-4 text-red-400" />
                      <span className="text-xs text-red-400">DISCONNECTED</span>
                    </>
                  )}
                </div>
                {connectionError && <p className="text-xs text-red-400 mt-1">{connectionError}</p>}
              </div>
            )}
          </div>
        </div>

        {/* Main Content */}
        <div className="flex-1 p-6">
          {/* Header */}
          <div className="mb-6">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-3xl font-bold text-cyan-400 mb-2">THREAT DEFENSE MATRIX</h1>
                <p className="text-green-400/70">Real-time cybersecurity monitoring and response system</p>
              </div>
              <div className="flex items-center space-x-2">
                <div className={`w-3 h-3 rounded-full ${isConnected ? "bg-green-400 animate-pulse" : "bg-red-400"}`} />
                <span className="text-sm text-gray-400">{isConnected ? "LIVE" : "OFFLINE"}</span>
              </div>
            </div>
          </div>

          {renderTabContent()}
        </div>
      </div>
    </div>
  )
}
