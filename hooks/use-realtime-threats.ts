"use client"

import { useEffect, useState } from "react"
import { supabase, type ThreatEvent } from "@/lib/supabase/client"

export function useRealtimeThreats() {
  const [threats, setThreats] = useState<ThreatEvent[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // Fetch initial data
    const fetchThreats = async () => {
      const { data, error } = await supabase
        .from("threat_events")
        .select("*")
        .order("detected_at", { ascending: false })
        .limit(50)

      if (!error && data) {
        setThreats(data)
      }
      setLoading(false)
    }

    fetchThreats()

    // Set up real-time subscription
    const channel = supabase
      .channel("threat_events_changes")
      .on(
        "postgres_changes",
        {
          event: "*",
          schema: "public",
          table: "threat_events",
        },
        (payload) => {
          if (payload.eventType === "INSERT") {
            setThreats((prev) => [payload.new as ThreatEvent, ...prev.slice(0, 49)])
          } else if (payload.eventType === "UPDATE") {
            setThreats((prev) =>
              prev.map((threat) => (threat.id === payload.new.id ? (payload.new as ThreatEvent) : threat)),
            )
          } else if (payload.eventType === "DELETE") {
            setThreats((prev) => prev.filter((threat) => threat.id !== payload.old.id))
          }
        },
      )
      .subscribe()

    return () => {
      supabase.removeChannel(channel)
    }
  }, [])

  return { threats, loading }
}
