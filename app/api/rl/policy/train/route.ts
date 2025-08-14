import { NextRequest, NextResponse } from 'next/server'
import { spawn } from 'child_process'

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { policy_name, training_episodes = [], episodes = 1000 } = body

    if (!policy_name) {
      return NextResponse.json(
        { error: 'Policy name required' },
        { status: 400 }
      )
    }

    // Call Python RL training
    const pythonProcess = spawn('python3', ['-c', `
import sys
sys.path.append('/app')
from ml_engine.rl_engine import rl_engine
import json

# Parse input
input_data = json.loads('''${JSON.stringify(body).replace(/'/g, "\\'")}''')

try:
    result = rl_engine.train_policy(
        policy_name=input_data['policy_name'],
        training_episodes=input_data.get('training_episodes', []),
        episodes=input_data.get('episodes', 1000)
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
            reject(new Error('Failed to parse RL training response'))
          }
        } else {
          reject(new Error(stderr || 'RL training failed'))
        }
      })
    })

    return NextResponse.json(result)
  } catch (error) {
    console.error('RL training error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'RL training failed' },
      { status: 500 }
    )
  }
}