import { NextRequest, NextResponse } from 'next/server'
import { spawn } from 'child_process'

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { query, context } = body

    if (!query) {
      return NextResponse.json(
        { error: 'Query required' },
        { status: 400 }
      )
    }

    // Call Python AI consultation
    const pythonProcess = spawn('python3', ['-c', `
import sys
sys.path.append('/app')
from ml_engine.ai_advisor import ai_advisor
import json
import asyncio

# Parse input
input_data = json.loads('''${JSON.stringify(body).replace(/'/g, "\\'")}''')

async def run_consultation():
    try:
        result = await ai_advisor.security_consultation(
            query=input_data['query'],
            context=input_data.get('context')
        )
        return result
    except Exception as e:
        return {"error": str(e), "ai_enabled": False}

# Run async function
result = asyncio.run(run_consultation())
print(json.dumps(result))
`])

    let stdout = ''
    let stderr = ''

    pythonProcess.stdout.on('data', (data) => {
      stdout += data.toString()
    })

    pythonProcess.stderr.on('data', (data) => {
      stderr += data.toString()
    })

    const result = await new Promise((resolve, reject) => {
      pythonProcess.on('close', (code) => {
        if (code === 0) {
          try {
            const response = JSON.parse(stdout.trim())
            resolve(response)
          } catch (e) {
            reject(new Error('Failed to parse AI consultation response'))
          }
        } else {
          reject(new Error(stderr || 'AI consultation failed'))
        }
      })
    })

    return NextResponse.json(result)
  } catch (error) {
    console.error('AI consultation error:', error)
    return NextResponse.json(
      { 
        ai_enabled: false,
        error: error instanceof Error ? error.message : 'AI consultation failed',
        response: 'AI consultation temporarily unavailable. Please try again later.'
      },
      { status: 500 }
    )
  }
}