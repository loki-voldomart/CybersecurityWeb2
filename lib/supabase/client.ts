import { createClient } from "@supabase/supabase-js"

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!

export const supabase = createClient(supabaseUrl, supabaseAnonKey)

// Database types for TypeScript
export interface ThreatEvent {
  id: string
  threat_type: "dos" | "port_scan" | "malware" | "phishing"
  severity: "low" | "medium" | "high" | "critical"
  source_ip: string
  target_ip?: string
  port?: number
  description: string
  status: "active" | "blocked" | "investigating" | "resolved"
  detected_at: string
  resolved_at?: string
  metadata: Record<string, any>
  created_at: string
  updated_at: string
}

export interface NetworkLog {
  id: string
  source_ip: string
  destination_ip: string
  source_port?: number
  destination_port?: number
  protocol?: string
  packet_size?: number
  flags?: string
  payload_hash?: string
  timestamp: string
  threat_score: number
  is_suspicious: boolean
  metadata: Record<string, any>
}

export interface SystemStatus {
  id: string
  component: string
  status: "online" | "offline" | "warning" | "error"
  cpu_usage?: number
  memory_usage?: number
  disk_usage?: number
  network_throughput?: number
  last_updated: string
  metadata: Record<string, any>
}

export interface DefenseAction {
  id: string
  threat_event_id: string
  action_type: string
  action_status: "pending" | "executed" | "failed"
  executed_at?: string
  executed_by?: string
  details?: string
  metadata: Record<string, any>
  created_at: string
}
