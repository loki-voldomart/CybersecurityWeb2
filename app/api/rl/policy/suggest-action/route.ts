import { NextRequest, NextResponse } from 'next/server'
import { spawn } from 'child_process'

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { state, policy_id } = body

    if (!state) {
      return NextResponse.json(
        { error: 'State data required' },
        { status: 400 }
      )
    }

    // Call Python RL action suggestion
    const pythonProcess = spawn('python3', ['-c', `
import sys
sys.path.append('/app')
from ml_engine.rl_engine import rl_engine
import json

# Parse input
input_data = json.loads('''${JSON.stringify(body).replace(/'/g, "\\'")}''')

try:
    result = rl_engine.suggest_action(
        state=input_data['state'],
        policy_id=input_data.get('policy_id')
    )
    print(json.dumps(result))
except Exception as e:
    print(json.dumps({"error": str(e)}), file=sys.stderr)
    sys.exit(1)
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
            reject(new Error('Failed to parse RL action response'))
          }
        } else {
          reject(new Error(stderr || 'RL action suggestion failed'))
        }
      })
    })

    return NextResponse.json(result)
  } catch (error) {
    console.error('RL action suggestion error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Action suggestion failed' },
      { status: 500 }
    )
  }
}