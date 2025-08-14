import { NextRequest, NextResponse } from 'next/server'
import { spawn } from 'child_process'

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { algorithm = 'isolation_forest', samples = [], ...params } = body

    if (!samples || samples.length === 0) {
      return NextResponse.json(
        { error: 'Training samples required' },
        { status: 400 }
      )
    }

    // Call Python anomaly training
    const pythonProcess = spawn('python3', ['-c', `
import sys
sys.path.append('/app')
from ml_engine.anomaly_detector import anomaly_engine
import json

# Parse input
import sys
input_data = json.loads('''${JSON.stringify(body).replace(/'/g, "\\'")}''')

try:
    result = anomaly_engine.train_model(
        algorithm=input_data['algorithm'],
        normal_samples=input_data['samples'],
        **{k: v for k, v in input_data.items() if k not in ['algorithm', 'samples']}
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
            reject(new Error('Failed to parse training response'))
          }
        } else {
          reject(new Error(stderr || 'Training failed'))
        }
      })
    })

    return NextResponse.json(result)
  } catch (error) {
    console.error('Anomaly training error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Training failed' },
      { status: 500 }
    )
  }
}