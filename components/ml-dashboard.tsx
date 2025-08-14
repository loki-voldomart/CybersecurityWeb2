"use client"

import { useState, useEffect } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Textarea } from '@/components/ui/textarea'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { 
  Brain, 
  Shield, 
  Zap, 
  Activity, 
  CheckCircle, 
  XCircle, 
  AlertTriangle,
  Loader2,
  Bot,
  Target,
  TrendingUp,
  Settings
} from 'lucide-react'

interface MLStatus {
  installed: boolean
  has_model?: boolean
  has_policies?: boolean
  models?: any[]
  policies?: any[]
  error?: string
}

interface PredictionResult {
  is_anomaly: boolean
  score: number
  model_id: string
  algorithm: string
  feature_vector: number[]
  feature_names: string[]
}

interface RLSuggestion {
  suggested_action: string
  confidence: number
  action_probabilities: Record<string, number>
  policy_id: string
}

interface AIAnalysis {
  ai_enabled: boolean
  analysis?: string
  recommendations?: string
  error?: string
  fallback_analysis?: string
}

export default function MLDashboard() {
  const [activeTab, setActiveTab] = useState('anomaly')
  
  // Anomaly Detection State
  const [anomalyStatus, setAnomalyStatus] = useState<MLStatus>({ installed: false })
  const [anomalyPrediction, setAnomalyPrediction] = useState<PredictionResult | null>(null)
  const [anomalyLoading, setAnomalyLoading] = useState(false)
  const [telemetryData, setTelemetryData] = useState('')
  
  // RL State
  const [rlStatus, setRlStatus] = useState<MLStatus>({ installed: false })
  const [rlSuggestion, setRlSuggestion] = useState<RLSuggestion | null>(null)
  const [rlLoading, setRlLoading] = useState(false)
  const [stateData, setStateData] = useState('')
  const [policyName, setPolicyName] = useState('')
  
  // AI State
  const [aiAnalysis, setAiAnalysis] = useState<AIAnalysis | null>(null)
  const [aiLoading, setAiLoading] = useState(false)
  const [threatData, setThreatData] = useState('')
  const [analysisStyle, setAnalysisStyle] = useState('concise')
  const [aiQuery, setAiQuery] = useState('')
  const [aiConsultation, setAiConsultation] = useState<any>(null)
  
  // Load statuses on component mount
  useEffect(() => {
    loadAnomalyStatus()
    loadRLStatus()
  }, [])

  const loadAnomalyStatus = async () => {
    try {
      const response = await fetch('/api/ml/anomaly/status')
      const data = await response.json()
      setAnomalyStatus(data)
    } catch (error) {
      console.error('Failed to load anomaly status:', error)
    }
  }

  const loadRLStatus = async () => {
    try {
      const response = await fetch('/api/rl/policy/status')
      const data = await response.json()
      setRlStatus(data)
    } catch (error) {
      console.error('Failed to load RL status:', error)
    }
  }

  const trainAnomalyModel = async () => {
    if (!telemetryData.trim()) return
    
    setAnomalyLoading(true)
    try {
      // Parse telemetry data - expecting JSON array of normal samples
      const samples = JSON.parse(telemetryData)
      
      const response = await fetch('/api/ml/anomaly/train', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          algorithm: 'isolation_forest',
          samples: samples,
          contamination: 0.1
        })
      })
      
      const result = await response.json()
      if (result.error) {
        throw new Error(result.error)
      }
      
      await loadAnomalyStatus()
      alert('Model trained successfully!')
      
    } catch (error) {
      console.error('Training failed:', error)
      alert(`Training failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
    } finally {
      setAnomalyLoading(false)
    }
  }

  const predictAnomaly = async () => {
    if (!telemetryData.trim()) return
    
    setAnomalyLoading(true)
    try {
      // Parse single telemetry record
      const telemetry = JSON.parse(telemetryData)
      
      const response = await fetch('/api/ml/anomaly/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ telemetry })
      })
      
      const result = await response.json()
      if (result.error) {
        throw new Error(result.error)
      }
      
      setAnomalyPrediction(result)
      
    } catch (error) {
      console.error('Prediction failed:', error)
      alert(`Prediction failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
    } finally {
      setAnomalyLoading(false)
    }
  }

  const trainRLPolicy = async () => {
    if (!policyName.trim()) return
    
    setRlLoading(true)
    try {
      const response = await fetch('/api/rl/policy/train', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          policy_name: policyName,
          episodes: 1000
        })
      })
      
      const result = await response.json()
      if (result.error) {
        throw new Error(result.error)
      }
      
      await loadRLStatus()
      alert('RL Policy trained successfully!')
      
    } catch (error) {
      console.error('RL Training failed:', error)
      alert(`RL Training failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
    } finally {
      setRlLoading(false)
    }
  }

  const suggestAction = async () => {
    if (!stateData.trim()) return
    
    setRlLoading(true)
    try {
      const state = JSON.parse(stateData)
      
      const response = await fetch('/api/rl/policy/suggest-action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ state })
      })
      
      const result = await response.json()
      if (result.error) {
        throw new Error(result.error)
      }
      
      setRlSuggestion(result)
      
    } catch (error) {
      console.error('Action suggestion failed:', error)
      alert(`Action suggestion failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
    } finally {
      setRlLoading(false)
    }
  }

  const analyzeWithAI = async () => {
    if (!threatData.trim()) return
    
    setAiLoading(true)
    try {
      const threat = JSON.parse(threatData)
      
      const response = await fetch('/api/ai/recommend', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          threat_data: threat,
          analysis_style: analysisStyle
        })
      })
      
      const result = await response.json()
      setAiAnalysis(result)
      
    } catch (error) {
      console.error('AI Analysis failed:', error)
      setAiAnalysis({
        ai_enabled: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    } finally {
      setAiLoading(false)
    }
  }

  const consultAI = async () => {
    if (!aiQuery.trim()) return
    
    setAiLoading(true)
    try {
      const response = await fetch('/api/ai/consult', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: aiQuery })
      })
      
      const result = await response.json()
      setAiConsultation(result)
      
    } catch (error) {
      console.error('AI Consultation failed:', error)
      setAiConsultation({
        ai_enabled: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    } finally {
      setAiLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-black text-green-400 font-mono p-6">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-cyan-400 mb-2 flex items-center">
            <Brain className="w-8 h-8 mr-3" />
            AI/ML CYBERSECURITY SUITE
          </h1>
          <p className="text-green-400/70">
            Advanced Machine Learning, Reinforcement Learning & AI-Powered Threat Analysis
          </p>
        </div>

        {/* Main Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="bg-gray-900/50 border border-cyan-500/30">
            <TabsTrigger value="anomaly" className="flex items-center space-x-2">
              <Target className="w-4 h-4" />
              <span>Anomaly Detection</span>
            </TabsTrigger>
            <TabsTrigger value="rl" className="flex items-center space-x-2">
              <TrendingUp className="w-4 h-4" />
              <span>Reinforcement Learning</span>
            </TabsTrigger>
            <TabsTrigger value="ai" className="flex items-center space-x-2">
              <Bot className="w-4 h-4" />
              <span>AI Analysis</span>
            </TabsTrigger>
          </TabsList>

          {/* Phase 1: Anomaly Detection */}
          <TabsContent value="anomaly" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Status Card */}
              <Card className="bg-gray-900/50 border-cyan-500/30">
                <CardHeader>
                  <CardTitle className="text-cyan-400 flex items-center">
                    <Target className="w-5 h-5 mr-2" />
                    Anomaly Detection Status
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex items-center space-x-2">
                    {anomalyStatus.installed ? (
                      <CheckCircle className="w-5 h-5 text-green-400" />
                    ) : (
                      <XCircle className="w-5 h-5 text-red-400" />
                    )}
                    <span className={anomalyStatus.installed ? 'text-green-400' : 'text-red-400'}>
                      {anomalyStatus.installed ? 'System Active' : 'System Offline'}
                    </span>
                  </div>
                  
                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <span>Trained Models:</span>
                      <Badge variant={anomalyStatus.has_model ? 'default' : 'secondary'}>
                        {anomalyStatus.models?.length || 0}
                      </Badge>
                    </div>
                    
                    {anomalyStatus.models?.map((model, idx) => (
                      <div key={idx} className="text-sm text-gray-400 ml-4">
                        {model.algorithm} - {model.n_samples} samples
                      </div>
                    ))}
                  </div>
                  
                  {anomalyStatus.error && (
                    <Alert className="border-red-500/30 bg-red-500/10">
                      <AlertTriangle className="h-4 w-4 text-red-400" />
                      <AlertDescription className="text-red-400">
                        {anomalyStatus.error}
                      </AlertDescription>
                    </Alert>
                  )}
                </CardContent>
              </Card>

              {/* Controls */}
              <Card className="bg-gray-900/50 border-green-500/30">
                <CardHeader>
                  <CardTitle className="text-green-400">Training & Prediction</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <Label className="text-green-400">Telemetry Data (JSON)</Label>
                    <Textarea
                      value={telemetryData}
                      onChange={(e) => setTelemetryData(e.target.value)}
                      placeholder='Training: [{"packet_size": 1024, "protocol": "TCP", ...}]
Prediction: {"packet_size": 1024, "protocol": "TCP", ...}'
                      className="bg-black border-gray-600 text-green-400 font-mono"
                      rows={6}
                    />
                  </div>
                  
                  <div className="flex space-x-2">
                    <Button
                      onClick={trainAnomalyModel}
                      disabled={anomalyLoading || !telemetryData.trim()}
                      className="bg-blue-600 hover:bg-blue-700 text-white flex-1"
                    >
                      {anomalyLoading ? (
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      ) : (
                        <Settings className="w-4 h-4 mr-2" />
                      )}
                      Train Model
                    </Button>
                    
                    <Button
                      onClick={predictAnomaly}
                      disabled={anomalyLoading || !anomalyStatus.has_model || !telemetryData.trim()}
                      className="bg-green-600 hover:bg-green-700 text-white flex-1"
                    >
                      {anomalyLoading ? (
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      ) : (
                        <Activity className="w-4 h-4 mr-2" />
                      )}
                      Predict
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Prediction Results */}
              {anomalyPrediction && (
                <Card className="bg-gray-900/50 border-yellow-500/30 lg:col-span-2">
                  <CardHeader>
                    <CardTitle className="text-yellow-400">Anomaly Detection Results</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <div className="text-center">
                        <div className={`text-2xl font-bold ${anomalyPrediction.is_anomaly ? 'text-red-400' : 'text-green-400'}`}>
                          {anomalyPrediction.is_anomaly ? 'ANOMALY' : 'NORMAL'}
                        </div>
                        <div className="text-sm text-gray-400">Classification</div>
                      </div>
                      
                      <div className="text-center">
                        <div className="text-2xl font-bold text-orange-400">
                          {(anomalyPrediction.score * 100).toFixed(1)}%
                        </div>
                        <div className="text-sm text-gray-400">Anomaly Score</div>
                      </div>
                      
                      <div className="text-center">
                        <div className="text-lg text-cyan-400">
                          {anomalyPrediction.algorithm.toUpperCase()}
                        </div>
                        <div className="text-sm text-gray-400">Algorithm Used</div>
                      </div>
                    </div>
                    
                    <div className="text-xs text-gray-500 font-mono">
                      Model: {anomalyPrediction.model_id} | Features: {anomalyPrediction.feature_names.length}
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          </TabsContent>

          {/* Phase 2: Reinforcement Learning */}
          <TabsContent value="rl" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* RL Status */}
              <Card className="bg-gray-900/50 border-purple-500/30">
                <CardHeader>
                  <CardTitle className="text-purple-400 flex items-center">
                    <TrendingUp className="w-5 h-5 mr-2" />
                    RL Engine Status
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex items-center space-x-2">
                    {rlStatus.installed ? (
                      <CheckCircle className="w-5 h-5 text-green-400" />
                    ) : (
                      <XCircle className="w-5 h-5 text-red-400" />
                    )}
                    <span className={rlStatus.installed ? 'text-green-400' : 'text-red-400'}>
                      {rlStatus.installed ? 'RL Engine Active' : 'RL Engine Offline'}
                    </span>
                  </div>
                  
                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <span>Trained Policies:</span>
                      <Badge variant={rlStatus.has_policies ? 'default' : 'secondary'}>
                        {rlStatus.policies?.length || 0}
                      </Badge>
                    </div>
                    
                    {rlStatus.policies?.map((policy, idx) => (
                      <div key={idx} className="text-sm text-gray-400 ml-4">
                        {policy.name} - Reward: {policy.average_reward?.toFixed(2)}
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* RL Controls */}
              <Card className="bg-gray-900/50 border-purple-500/30">
                <CardHeader>
                  <CardTitle className="text-purple-400">Policy Training & Action</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <Label className="text-purple-400">Policy Name</Label>
                    <Input
                      value={policyName}
                      onChange={(e) => setPolicyName(e.target.value)}
                      placeholder="e.g., threat_response_policy_v1"
                      className="bg-black border-gray-600 text-purple-400"
                    />
                  </div>
                  
                  <Button
                    onClick={trainRLPolicy}
                    disabled={rlLoading || !policyName.trim()}
                    className="w-full bg-purple-600 hover:bg-purple-700 text-white"
                  >
                    {rlLoading ? (
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    ) : (
                      <Brain className="w-4 h-4 mr-2" />
                    )}
                    Train RL Policy
                  </Button>
                  
                  <div className="space-y-2">
                    <Label className="text-purple-400">State Data (JSON)</Label>
                    <Textarea
                      value={stateData}
                      onChange={(e) => setStateData(e.target.value)}
                      placeholder='{"threat_score": 0.8, "severity": "high", "source_trust": 0.2}'
                      className="bg-black border-gray-600 text-purple-400 font-mono"
                      rows={3}
                    />
                  </div>
                  
                  <Button
                    onClick={suggestAction}
                    disabled={rlLoading || !stateData.trim()}
                    className="w-full bg-green-600 hover:bg-green-700 text-white"
                  >
                    {rlLoading ? (
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    ) : (
                      <Zap className="w-4 h-4 mr-2" />
                    )}
                    Suggest Action
                  </Button>
                </CardContent>
              </Card>

              {/* RL Results */}
              {rlSuggestion && (
                <Card className="bg-gray-900/50 border-green-500/30 lg:col-span-2">
                  <CardHeader>
                    <CardTitle className="text-green-400">RL Action Recommendation</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="text-center">
                        <div className="text-3xl font-bold text-green-400 uppercase">
                          {rlSuggestion.suggested_action}
                        </div>
                        <div className="text-sm text-gray-400">Recommended Action</div>
                      </div>
                      
                      <div className="text-center">
                        <div className="text-2xl font-bold text-yellow-400">
                          {(rlSuggestion.confidence * 100).toFixed(1)}%
                        </div>
                        <div className="text-sm text-gray-400">Confidence</div>
                      </div>
                    </div>
                    
                    <div className="space-y-2">
                      <div className="text-sm text-gray-400">Action Probabilities:</div>
                      <div className="grid grid-cols-2 gap-2">
                        {Object.entries(rlSuggestion.action_probabilities).map(([action, prob]) => (
                          <div key={action} className="flex justify-between text-sm">
                            <span className="capitalize">{action}:</span>
                            <span>{(prob * 100).toFixed(1)}%</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          </TabsContent>

          {/* Phase 3: AI Analysis */}
          <TabsContent value="ai" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* AI Threat Analysis */}
              <Card className="bg-gray-900/50 border-blue-500/30">
                <CardHeader>
                  <CardTitle className="text-blue-400 flex items-center">
                    <Bot className="w-5 h-5 mr-2" />
                    AI Threat Analysis
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <Label className="text-blue-400">Threat Data (JSON)</Label>
                    <Textarea
                      value={threatData}
                      onChange={(e) => setThreatData(e.target.value)}
                      placeholder='{"threat_type": "dos", "severity": "high", "source_ip": "192.168.1.100", "description": "Potential DoS attack detected"}'
                      className="bg-black border-gray-600 text-blue-400 font-mono"
                      rows={4}
                    />
                  </div>
                  
                  <div className="space-y-2">
                    <Label className="text-blue-400">Analysis Style</Label>
                    <Select value={analysisStyle} onValueChange={setAnalysisStyle}>
                      <SelectTrigger className="bg-black border-gray-600 text-blue-400">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="concise">Concise</SelectItem>
                        <SelectItem value="detailed">Detailed</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  
                  <Button
                    onClick={analyzeWithAI}
                    disabled={aiLoading || !threatData.trim()}
                    className="w-full bg-blue-600 hover:bg-blue-700 text-white"
                  >
                    {aiLoading ? (
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    ) : (
                      <Brain className="w-4 h-4 mr-2" />
                    )}
                    Analyze Threat
                  </Button>
                </CardContent>
              </Card>

              {/* AI Consultation */}
              <Card className="bg-gray-900/50 border-green-500/30">
                <CardHeader>
                  <CardTitle className="text-green-400 flex items-center">
                    <Bot className="w-5 h-5 mr-2" />
                    AI Security Consultation
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <Label className="text-green-400">Security Question</Label>
                    <Textarea
                      value={aiQuery}
                      onChange={(e) => setAiQuery(e.target.value)}
                      placeholder="Ask about security best practices, threat analysis, or incident response..."
                      className="bg-black border-gray-600 text-green-400 font-mono"
                      rows={4}
                    />
                  </div>
                  
                  <Button
                    onClick={consultAI}
                    disabled={aiLoading || !aiQuery.trim()}
                    className="w-full bg-green-600 hover:bg-green-700 text-white"
                  >
                    {aiLoading ? (
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    ) : (
                      <Bot className="w-4 h-4 mr-2" />
                    )}
                    Get AI Advice
                  </Button>
                </CardContent>
              </Card>

              {/* AI Analysis Results */}
              {aiAnalysis && (
                <Card className="bg-gray-900/50 border-yellow-500/30 lg:col-span-2">
                  <CardHeader>
                    <CardTitle className="text-yellow-400 flex items-center">
                      <Brain className="w-5 h-5 mr-2" />
                      AI Analysis Results
                      {aiAnalysis.ai_enabled && (
                        <Badge className="ml-2 bg-green-600">AI Powered</Badge>
                      )}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {aiAnalysis.ai_enabled ? (
                      <div className="space-y-4">
                        <div className="bg-black/50 p-4 rounded border border-gray-600 prose prose-invert max-w-none">
                          <div className="whitespace-pre-wrap text-green-400 font-mono text-sm">
                            {aiAnalysis.analysis || aiAnalysis.recommendations}
                          </div>
                        </div>
                        {aiAnalysis.model && (
                          <div className="text-xs text-gray-500">
                            Model: {aiAnalysis.model}
                          </div>
                        )}
                      </div>
                    ) : (
                      <Alert className="border-red-500/30 bg-red-500/10">
                        <AlertTriangle className="h-4 w-4 text-red-400" />
                        <AlertDescription className="text-red-400">
                          {aiAnalysis.error || 'AI analysis not available'}
                          {aiAnalysis.fallback_analysis && (
                            <div className="mt-2 text-gray-300 whitespace-pre-wrap">
                              {aiAnalysis.fallback_analysis}
                            </div>
                          )}
                        </AlertDescription>
                      </Alert>
                    )}
                  </CardContent>
                </Card>
              )}

              {/* AI Consultation Results */}
              {aiConsultation && (
                <Card className="bg-gray-900/50 border-cyan-500/30 lg:col-span-2">
                  <CardHeader>
                    <CardTitle className="text-cyan-400 flex items-center">
                      <Bot className="w-5 h-5 mr-2" />
                      AI Security Consultation
                      {aiConsultation.ai_enabled && (
                        <Badge className="ml-2 bg-green-600">AI Powered</Badge>
                      )}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {aiConsultation.ai_enabled ? (
                      <div className="space-y-4">
                        <div className="bg-black/50 p-4 rounded border border-gray-600">
                          <div className="whitespace-pre-wrap text-cyan-400 font-mono text-sm">
                            {aiConsultation.response}
                          </div>
                        </div>
                        {aiConsultation.model && (
                          <div className="text-xs text-gray-500">
                            Model: {aiConsultation.model}
                          </div>
                        )}
                      </div>
                    ) : (
                      <Alert className="border-red-500/30 bg-red-500/10">
                        <AlertTriangle className="h-4 w-4 text-red-400" />
                        <AlertDescription className="text-red-400">
                          {aiConsultation.error || 'AI consultation not available'}
                        </AlertDescription>
                      </Alert>
                    )}
                  </CardContent>
                </Card>
              )}
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}