import { type NextRequest, NextResponse } from "next/server"
import { supabase } from "@/lib/supabase/client"

// POST /api/ai-analysis - Trigger AI analysis on network logs
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { log_id, network_log } = body

    // For now, we'll implement a simple rule-based analysis
    // In production, this would call the Python ML models
    const analysis = await analyzeNetworkLog(network_log)

    // Update the network log with AI analysis results
    const { error } = await supabase
      .from("network_logs")
      .update({
        threat_score: analysis.threat_score,
        is_suspicious: analysis.is_suspicious,
        metadata: {
          ...network_log.metadata,
          ai_analysis: analysis,
        },
      })
      .eq("id", log_id)

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 500 })
    }

    // If high threat detected, create threat event
    if (analysis.threat_score > 0.7) {
      await createThreatEvent(network_log, analysis)
    }

    return NextResponse.json({ analysis })
  } catch (error) {
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}

// GET /api/ai-analysis/stats - Get AI analysis statistics
export async function GET() {
  try {
    // Get threat detection statistics
    const { data: logs, error } = await supabase
      .from("network_logs")
      .select("threat_score, is_suspicious, metadata")
      .not("threat_score", "is", null)
      .order("timestamp", { ascending: false })
      .limit(1000)

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 500 })
    }

    // Calculate statistics
    const totalAnalyzed = logs.length
    const suspiciousCount = logs.filter((log) => log.is_suspicious).length
    const avgThreatScore = logs.reduce((sum, log) => sum + (log.threat_score || 0), 0) / totalAnalyzed
    const highThreatCount = logs.filter((log) => (log.threat_score || 0) > 0.7).length

    const stats = {
      total_analyzed: totalAnalyzed,
      suspicious_count: suspiciousCount,
      suspicious_percentage: totalAnalyzed > 0 ? (suspiciousCount / totalAnalyzed) * 100 : 0,
      average_threat_score: avgThreatScore,
      high_threat_count: highThreatCount,
      detection_accuracy: calculateDetectionAccuracy(logs),
    }

    return NextResponse.json({ stats })
  } catch (error) {
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}

async function analyzeNetworkLog(log: any) {
  // Simple rule-based analysis (placeholder for ML models)
  let threatScore = 0.0
  const indicators = []

  // Check for DoS indicators
  if (log.packet_size > 1400 && log.protocol === "TCP") {
    threatScore += 0.3
    indicators.push("large_packet_size")
  }

  // Check for port scanning indicators
  if (log.destination_port && (log.destination_port < 1024 || log.packet_size < 100)) {
    threatScore += 0.25
    indicators.push("potential_port_scan")
  }

  // Check for suspicious IPs (external to internal)
  if (isExternalIP(log.source_ip) && isInternalIP(log.destination_ip)) {
    threatScore += 0.2
    indicators.push("external_to_internal")
  }

  // Check for unusual protocols or ports
  if (log.protocol === "ICMP" || (log.destination_port && [135, 139, 445, 1433, 3389].includes(log.destination_port))) {
    threatScore += 0.15
    indicators.push("suspicious_protocol_port")
  }

  // Time-based analysis (simplified)
  const hour = new Date().getHours()
  if (hour < 6 || hour > 22) {
    // Activity during off-hours
    threatScore += 0.1
    indicators.push("off_hours_activity")
  }

  return {
    threat_score: Math.min(1.0, threatScore),
    is_suspicious: threatScore > 0.5,
    threat_level: categorizeThreatLevel(threatScore),
    indicators,
    analysis_timestamp: new Date().toISOString(),
    model_version: "rule_based_v1.0",
  }
}

async function createThreatEvent(networkLog: any, analysis: any) {
  const threatEvent = {
    threat_type: determineThreatType(analysis.indicators),
    severity: analysis.threat_level === "critical" ? "critical" : analysis.threat_level === "high" ? "high" : "medium",
    source_ip: networkLog.source_ip,
    target_ip: networkLog.destination_ip,
    port: networkLog.destination_port,
    description: `AI-detected threat: ${analysis.indicators.join(", ")}`,
    status: "active",
    metadata: {
      ai_detected: true,
      threat_score: analysis.threat_score,
      indicators: analysis.indicators,
      source_log_id: networkLog.id,
    },
  }

  await supabase.from("threat_events").insert([threatEvent])
}

function determineThreatType(indicators: string[]): string {
  if (indicators.includes("large_packet_size") || indicators.includes("external_to_internal")) {
    return "dos"
  }
  if (indicators.includes("potential_port_scan")) {
    return "port_scan"
  }
  if (indicators.includes("suspicious_protocol_port")) {
    return "malware"
  }
  return "unknown"
}

function categorizeThreatLevel(score: number): string {
  if (score >= 0.8) return "critical"
  if (score >= 0.6) return "high"
  if (score >= 0.4) return "medium"
  if (score >= 0.2) return "low"
  return "minimal"
}

function isExternalIP(ip: string): boolean {
  return !isInternalIP(ip)
}

function isInternalIP(ip: string): boolean {
  const internalRanges = [
    "10.",
    "192.168.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
  ]
  return internalRanges.some((range) => ip.startsWith(range))
}

function calculateDetectionAccuracy(logs: any[]): number {
  // Simple accuracy calculation based on known suspicious patterns
  let correctDetections = 0
  let totalSuspicious = 0

  for (const log of logs) {
    const metadata = typeof log.metadata === "string" ? JSON.parse(log.metadata) : log.metadata
    const actuallyMalicious =
      metadata?.traffic_type && ["dos_attack", "port_scan", "malware", "phishing"].includes(metadata.traffic_type)

    if (actuallyMalicious) {
      totalSuspicious++
      if (log.is_suspicious) {
        correctDetections++
      }
    }
  }

  return totalSuspicious > 0 ? (correctDetections / totalSuspicious) * 100 : 0
}
