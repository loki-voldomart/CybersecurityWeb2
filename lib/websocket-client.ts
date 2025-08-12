"use client"

import { useEffect, useState } from "react"
import type { ThreatEvent, SystemStatus } from "@/lib/supabase/client"

export interface WebSocketMessage {
  type: "threat_event" | "network_log" | "system_status" | "stats_update"
  data: any
  timestamp: string
}

// Updated useWebSocket to use polling instead of WebSocket connection
export function useWebSocket(url = "ws://localhost:3001") {
  const [isConnected, setIsConnected] = useState(false)
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null)
  const [connectionError, setConnectionError] = useState<string | null>(null)

  useEffect(() => {
    // Simulate connection without actual WebSocket
    setIsConnected(true)
    setConnectionError(null)

    // Generate periodic fake messages to simulate real-time updates
    const interval = setInterval(() => {
      const messageTypes = ["threat_event", "stats_update", "system_status"] as const
      const randomType = messageTypes[Math.floor(Math.random() * messageTypes.length)]

      let data = {}
      switch (randomType) {
        case "threat_event":
          data = {
            id: Date.now().toString(),
            type: ["dos", "port_scan", "malware", "phishing"][Math.floor(Math.random() * 4)],
            severity: ["low", "medium", "high", "critical"][Math.floor(Math.random() * 4)],
            source_ip: `192.168.1.${Math.floor(Math.random() * 255)}`,
            description: "Simulated threat detected",
            created_at: new Date().toISOString(),
          }
          break
        case "stats_update":
          data = {
            totalConnections: Math.floor(Math.random() * 2000) + 1000,
            blockedAttacks: Math.floor(Math.random() * 50),
            activeThreats: Math.floor(Math.random() * 10),
            systemHealth: Math.floor(Math.random() * 20) + 80,
          }
          break
        case "system_status":
          data = {
            component: ["Firewall", "IDS/IPS", "VPN Gateway", "DNS Filter"][Math.floor(Math.random() * 4)],
            status: ["online", "warning", "offline"][Math.floor(Math.random() * 3)],
            last_check: new Date().toISOString(),
          }
          break
      }

      setLastMessage({
        type: randomType,
        data,
        timestamp: new Date().toISOString(),
      })
    }, 3000) // Update every 3 seconds

    return () => clearInterval(interval)
  }, [url])

  const sendMessage = (message: any) => {
    // Simulate sending message (no-op for polling implementation)
    console.log("Simulated message send:", message)
  }

  return {
    isConnected,
    lastMessage,
    connectionError,
    sendMessage,
  }
}

// Hook for real-time threat events
export function useRealtimeThreats() {
  const [threats, setThreats] = useState<ThreatEvent[]>([])
  const [loading, setLoading] = useState(true)
  const { lastMessage } = useWebSocket()

  // Fetch initial data
  useEffect(() => {
    const fetchInitialThreats = async () => {
      try {
        const response = await fetch("/api/threats?limit=20")
        if (response.ok) {
          const data = await response.json()
          setThreats(data.threats || [])
        }
      } catch (error) {
        console.error("Error fetching initial threats:", error)
      } finally {
        setLoading(false)
      }
    }

    fetchInitialThreats()
  }, [])

  // Handle real-time updates
  useEffect(() => {
    if (lastMessage && lastMessage.type === "threat_event") {
      const newThreat = lastMessage.data as ThreatEvent
      setThreats((prev) => {
        // Check if threat already exists
        const existingIndex = prev.findIndex((t) => t.id === newThreat.id)
        if (existingIndex >= 0) {
          // Update existing threat
          const updated = [...prev]
          updated[existingIndex] = newThreat
          return updated
        } else {
          // Add new threat to the beginning
          return [newThreat, ...prev.slice(0, 19)] // Keep only 20 most recent
        }
      })
    }
  }, [lastMessage])

  return { threats, loading, setThreats }
}

// Hook for real-time network statistics
export function useRealtimeStats() {
  const [stats, setStats] = useState({
    totalConnections: 1247,
    blockedAttacks: 23,
    activeThreats: 5,
    systemHealth: 98,
    networkThroughput: 45.2,
    cpuUsage: 34,
    memoryUsage: 67,
  })
  const { lastMessage } = useWebSocket()

  // Fetch initial stats
  useEffect(() => {
    const fetchInitialStats = async () => {
      try {
        const response = await fetch("/api/system-status")
        if (response.ok) {
          const data = await response.json()
          // Process system status data into stats
          const systems = data.systems || []
          const avgHealth =
            systems.length > 0
              ? systems.reduce((sum: number, sys: any) => sum + (sys.status === "online" ? 100 : 50), 0) /
                systems.length
              : 100

          setStats((prev) => ({
            ...prev,
            systemHealth: Math.round(avgHealth),
          }))
        }
      } catch (error) {
        console.error("Error fetching initial stats:", error)
      }
    }

    fetchInitialStats()
  }, [])

  // Handle real-time updates
  useEffect(() => {
    if (lastMessage && lastMessage.type === "stats_update") {
      setStats((prev) => ({
        ...prev,
        ...lastMessage.data,
      }))
    }
  }, [lastMessage])

  return stats
}

// Hook for real-time system status
export function useRealtimeSystemStatus() {
  const [systems, setSystems] = useState<SystemStatus[]>([])
  const { lastMessage } = useWebSocket()

  useEffect(() => {
    const fetchInitialStatus = async () => {
      try {
        const response = await fetch("/api/system-status")
        if (response.ok) {
          const data = await response.json()
          setSystems(data.systems || [])
        }
      } catch (error) {
        console.error("Error fetching system status:", error)
      }
    }

    fetchInitialStatus()
  }, [])

  useEffect(() => {
    if (lastMessage && lastMessage.type === "system_status") {
      const updatedSystem = lastMessage.data as SystemStatus
      setSystems((prev) => {
        const existingIndex = prev.findIndex((s) => s.component === updatedSystem.component)
        if (existingIndex >= 0) {
          const updated = [...prev]
          updated[existingIndex] = updatedSystem
          return updated
        } else {
          return [...prev, updatedSystem]
        }
      })
    }
  }, [lastMessage])

  return systems
}
