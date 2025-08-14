import { NextRequest, NextResponse } from 'next/server'
import { spawn } from 'child_process'

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { telemetry, model_id } = body

    if (!telemetry) {
      return NextResponse.json(
        { error: 'Telemetry data required' },
        { status: 400 }
      )
    }

    // Call Python anomaly prediction
    const pythonProcess = spawn('python3', ['-c', `
import sys
sys.path.append('/app')
from ml_engine.anomaly_detector import anomaly_engine
import json

# Parse input
input_data = json.loads('''${JSON.stringify(body).replace(/'/g, "\\'")}''')

try:
    result = anomaly_engine.predict(
        telemetry=input_data['telemetry'],
        model_id=input_data.get('model_id')
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
            reject(new Error('Failed to parse prediction response'))
          }
        } else {
          reject(new Error(stderr || 'Prediction failed'))
        }
      })
    })

    return NextResponse.json(result)
  } catch (error) {
    console.error('Anomaly prediction error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Prediction failed' },
      { status: 500 }
    )
  }
}