import type { NextRequest } from "next/server"

export async function GET(request: NextRequest) {
  // This endpoint provides WebSocket connection info
  return new Response(
    JSON.stringify({
      websocket_url: process.env.WEBSOCKET_URL || "ws://localhost:3001",
      status: "WebSocket server should be running on port 3001",
      instructions: "Run the WebSocket server using: node scripts/websocket_server.js",
    }),
    {
      headers: { "Content-Type": "application/json" },
    },
  )
}
