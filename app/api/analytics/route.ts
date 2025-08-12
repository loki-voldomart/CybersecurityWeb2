import { type NextRequest, NextResponse } from "next/server"
import { createClient } from "@/lib/supabase/server"

export async function GET(request: NextRequest) {
  try {
    const supabase = createClient()
    const { searchParams } = new URL(request.url)
    const timeframe = searchParams.get("timeframe") || "24"

    // Get threat analytics from database
    const { data: threats, error: threatsError } = await supabase
      .from("threat_events")
      .select("*")
      .gte("created_at", new Date(Date.now() - Number.parseInt(timeframe) * 60 * 60 * 1000).toISOString())
      .order("created_at", { ascending: false })

    if (threatsError) {
      throw threatsError
    }

    // Calculate analytics
    const analytics = {
      threat_summary: {
        total_threats: threats?.length || 0,
        critical_threats: threats?.filter((t) => t.severity === "critical").length || 0,
        blocked_threats: threats?.filter((t) => t.status === "blocked").length || 0,
        detection_accuracy: 0.96, // Would be calculated from actual data
      },
      attack_patterns: {
        dos_attacks: threats?.filter((t) => t.threat_type?.includes("dos")).length || 0,
        port_scans: threats?.filter((t) => t.threat_type?.includes("port")).length || 0,
        malware_attempts: threats?.filter((t) => t.threat_type?.includes("malware")).length || 0,
        phishing_attempts: threats?.filter((t) => t.threat_type?.includes("phishing")).length || 0,
      },
      geographic_distribution: {
        Internal: threats?.filter((t) => t.source_ip?.startsWith("192.168")).length || 0,
        External: threats?.filter((t) => !t.source_ip?.startsWith("192.168")).length || 0,
      },
      hourly_distribution: calculateHourlyDistribution(threats || []),
      system_performance: {
        uptime: 99.9,
        response_time: 1.2,
        false_positive_rate: 0.03,
      },
    }

    return NextResponse.json(analytics)
  } catch (error) {
    console.error("Analytics API error:", error)
    return NextResponse.json({ error: "Failed to fetch analytics" }, { status: 500 })
  }
}

function calculateHourlyDistribution(threats: any[]) {
  const hourly = Array(24).fill(0)

  threats.forEach((threat) => {
    if (threat.created_at) {
      const hour = new Date(threat.created_at).getHours()
      hourly[hour]++
    }
  })

  return hourly
}
