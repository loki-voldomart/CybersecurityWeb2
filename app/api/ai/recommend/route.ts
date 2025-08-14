import { NextRequest, NextResponse } from 'next/server'
import { spawn } from 'child_process'

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { threat_data, analysis_style = 'concise', analysis_type = 'threat_analysis' } = body

    if (!threat_data) {
      return NextResponse.json(
        { error: 'Threat data required' },
        { status: 400 }
      )
    }

    // Call Python AI analysis
    const pythonProcess = spawn('python3', ['-c', `
import sys
sys.path.append('/app')
from ml_engine.ai_advisor import ai_advisor
import json
import asyncio

# Parse input
input_data = json.loads('''${JSON.stringify(body).replace(/'/g, "\\'")}''')

async def run_analysis():
    try:
        if input_data.get('analysis_type') == 'remediation':
            result = await ai_advisor.recommend_remediation(input_data['threat_data'])
        else:
            result = await ai_advisor.analyze_threat(
                threat_data=input_data['threat_data'],
                analysis_style=input_data.get('analysis_style', 'concise')
            )
        return result
    except Exception as e:
        return {"error": str(e), "ai_enabled": False}

# Run async function
result = asyncio.run(run_analysis())
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
            reject(new Error('Failed to parse AI analysis response'))
          }
        } else {
          reject(new Error(stderr || 'AI analysis failed'))
        }
      })
    })

    return NextResponse.json(result)
  } catch (error) {
    console.error('AI analysis error:', error)
    return NextResponse.json(
      { 
        ai_enabled: false,
        error: error instanceof Error ? error.message : 'AI analysis failed',
        fallback_analysis: 'AI analysis temporarily unavailable. Please try again later.'
      },
      { status: 500 }
    )
  }
}