import { type NextRequest, NextResponse } from "next/server"
import { supabase } from "@/lib/supabase/client"

// GET /api/threats/[id] - Fetch specific threat event
export async function GET(request: NextRequest, { params }: { params: { id: string } }) {
  try {
    const { data, error } = await supabase.from("threat_events").select("*").eq("id", params.id).single()

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 500 })
    }

    if (!data) {
      return NextResponse.json({ error: "Threat not found" }, { status: 404 })
    }

    return NextResponse.json({ threat: data })
  } catch (error) {
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}

// PATCH /api/threats/[id] - Update threat event status
export async function PATCH(request: NextRequest, { params }: { params: { id: string } }) {
  try {
    const body = await request.json()

    const { data, error } = await supabase
      .from("threat_events")
      .update({
        ...body,
        updated_at: new Date().toISOString(),
        ...(body.status === "resolved" && { resolved_at: new Date().toISOString() }),
      })
      .eq("id", params.id)
      .select()
      .single()

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 500 })
    }

    return NextResponse.json({ threat: data })
  } catch (error) {
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}
