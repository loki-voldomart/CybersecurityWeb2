import { type NextRequest, NextResponse } from "next/server"
import { supabase } from "@/lib/supabase/client"

// GET /api/network-logs - Fetch network logs
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const suspicious = searchParams.get("suspicious")
    const limit = Number.parseInt(searchParams.get("limit") || "100")

    let query = supabase.from("network_logs").select("*").order("timestamp", { ascending: false }).limit(limit)

    if (suspicious === "true") {
      query = query.eq("is_suspicious", true)
    }

    const { data, error } = await query

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 500 })
    }

    return NextResponse.json({ logs: data })
  } catch (error) {
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}

// POST /api/network-logs - Create new network log entry
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()

    const { data, error } = await supabase.from("network_logs").insert([body]).select().single()

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 500 })
    }

    return NextResponse.json({ log: data }, { status: 201 })
  } catch (error) {
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}
