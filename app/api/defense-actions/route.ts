import { type NextRequest, NextResponse } from "next/server"
import { supabase } from "@/lib/supabase/client"

// POST /api/defense-actions - Execute defense action
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { threat_event_id, action_type, executed_by = "system" } = body

    // Create defense action record
    const { data: actionData, error: actionError } = await supabase
      .from("defense_actions")
      .insert([
        {
          threat_event_id,
          action_type,
          action_status: "executed",
          executed_at: new Date().toISOString(),
          executed_by,
          details: `${action_type} action executed automatically`,
        },
      ])
      .select()
      .single()

    if (actionError) {
      return NextResponse.json({ error: actionError.message }, { status: 500 })
    }

    // Update threat status based on action
    let newStatus = "investigating"
    if (action_type === "block_ip") {
      newStatus = "blocked"
    }

    const { error: updateError } = await supabase
      .from("threat_events")
      .update({
        status: newStatus,
        updated_at: new Date().toISOString(),
      })
      .eq("id", threat_event_id)

    if (updateError) {
      return NextResponse.json({ error: updateError.message }, { status: 500 })
    }

    return NextResponse.json({
      action: actionData,
      message: `${action_type} executed successfully`,
    })
  } catch (error) {
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}
