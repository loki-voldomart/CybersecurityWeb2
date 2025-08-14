import { NextRequest, NextResponse } from 'next/server'
import { spawn } from 'child_process'

export async function GET() {
  try {
    // Call Python RL status
    const pythonProcess = spawn('python3', ['-c', `
import sys
sys.path.append('/app')
from ml_engine.rl_engine import rl_engine
import json

status = rl_engine.get_status()
print(json.dumps(status))
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
            const status = JSON.parse(stdout.trim())
            resolve(status)
          } catch (e) {
            reject(new Error('Failed to parse RL status response'))
          }
        } else {
          reject(new Error(stderr || 'Python RL process failed'))
        }
      })
    })

    return NextResponse.json(result)
  } catch (error) {
    console.error('RL status error:', error)
    return NextResponse.json(
      { 
        installed: false, 
        error: error instanceof Error ? error.message : 'Unknown error',
        has_policies: false
      }, 
      { status: 500 }
    )
  }
}