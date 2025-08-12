import { type NextRequest, NextResponse } from "next/server"
import { supabase } from "@/lib/supabase/client"

// GET /api/system-status - Fetch system status
export async function GET() {
  try {
    const { data, error } = await supabase.from("system_status").select("*").order("last_updated", { ascending: false })

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 500 })
    }

    return NextResponse.json({ systems: data })
  } catch (error) {
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}

// POST /api/system-status - Update system status
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()

    const { data, error } = await supabase
      .from("system_status")
      .upsert(
        [
          {
            ...body,
            last_updated: new Date().toISOString(),
          },
        ],
        {
          onConflict: "component",
        },
      )
      .select()

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 500 })
    }

    return NextResponse.json({ systems: data })
  } catch (error) {
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}
