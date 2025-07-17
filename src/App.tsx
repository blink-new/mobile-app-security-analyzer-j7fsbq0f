import React, { useState } from 'react'
import { Upload, Link, Shield, AlertTriangle, CheckCircle, XCircle, Download, History, Eye, FileText, BarChart3, Clock, TrendingUp, Loader2 } from 'lucide-react'
import { Button } from './components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './components/ui/card'
import { Input } from './components/ui/input'
import { Badge } from './components/ui/badge'
import { Progress } from './components/ui/progress'
import { Tabs, TabsContent, TabsList, TabsTrigger } from './components/ui/tabs'
import { Alert, AlertDescription } from './components/ui/alert'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from './components/ui/dialog'
import { Separator } from './components/ui/separator'
import { ScrollArea } from './components/ui/scroll-area'
import { analyzeAPKFile, analyzePlayStoreURL, validateAPKFile, validatePlayStoreURL, type AnalysisResult, type SecurityIssue } from './lib/apk-analyzer'
import toast, { Toaster } from 'react-hot-toast'

// Types are now imported from lib/apk-analyzer.ts

const OWASP_CATEGORIES = [
  'M1: Improper Platform Usage',
  'M2: Insecure Data Storage', 
  'M3: Insecure Communication',
  'M4: Insecure Authentication',
  'M5: Insufficient Cryptography',
  'M6: Insecure Authorization',
  'M7: Client Code Quality',
  'M8: Code Tampering',
  'M9: Reverse Engineering',
  'M10: Extraneous Functionality'
]

function App() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [playStoreUrl, setPlayStoreUrl] = useState('')
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [analysisProgress, setAnalysisProgress] = useState(0)
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null)
  const [analysisHistory, setAnalysisHistory] = useState<AnalysisResult[]>([])
  const [dragActive, setDragActive] = useState(false)
  const [selectedIssue, setSelectedIssue] = useState<SecurityIssue | null>(null)
  const [showHistory, setShowHistory] = useState(false)
  const [analysisError, setAnalysisError] = useState<string | null>(null)
  const [currentAnalysisType, setCurrentAnalysisType] = useState<'apk' | 'playstore' | null>(null)

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true)
    } else if (e.type === 'dragleave') {
      setDragActive(false)
    }
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0]
      if (file.name.endsWith('.apk')) {
        const validation = validateAPKFile(file)
        
        if (!validation.valid) {
          toast.error(validation.error || 'Invalid APK file')
          return
        }
        
        setSelectedFile(file)
        setAnalysisError(null)
      }
    }
  }

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0]
      const validation = validateAPKFile(file)
      
      if (!validation.valid) {
        toast.error(validation.error || 'Invalid APK file')
        return
      }
      
      setSelectedFile(file)
      setAnalysisError(null)
    }
  }

  const performRealAnalysis = async () => {
    setIsAnalyzing(true)
    setAnalysisProgress(0)
    setAnalysisError(null)
    
    let progressInterval: NodeJS.Timeout | null = null
    
    try {
      let result: AnalysisResult
      
      if (selectedFile) {
        setCurrentAnalysisType('apk')
        toast.loading('Analyzing APK file...', { id: 'analysis' })
        
        // Simulate progress for better UX
        progressInterval = setInterval(() => {
          setAnalysisProgress(prev => Math.min(prev + 8, 85))
        }, 400)
        
        result = await analyzeAPKFile(selectedFile)
        
      } else if (playStoreUrl) {
        setCurrentAnalysisType('playstore')
        
        // Validate URL first
        const validation = validatePlayStoreURL(playStoreUrl)
        if (!validation.valid) {
          throw new Error(validation.error || 'Invalid Play Store URL')
        }
        
        toast.loading('Analyzing Play Store app...', { id: 'analysis' })
        
        // Simulate progress for better UX
        progressInterval = setInterval(() => {
          setAnalysisProgress(prev => Math.min(prev + 12, 85))
        }, 300)
        
        result = await analyzePlayStoreURL(playStoreUrl)
        
      } else {
        throw new Error('No file or URL provided for analysis')
      }
      
      if (progressInterval) {
        clearInterval(progressInterval)
        progressInterval = null
      }
      
      setAnalysisProgress(100)
      setAnalysisResult(result)
      setAnalysisHistory(prev => [result, ...prev.slice(0, 9)]) // Keep last 10 analyses
      
      toast.success('Analysis completed successfully!', { id: 'analysis' })
      
    } catch (error) {
      console.error('Analysis failed:', error)
      
      // Clear progress interval on error
      if (progressInterval) {
        clearInterval(progressInterval)
      }
      
      let errorMessage = 'Analysis failed'
      
      if (error instanceof Error) {
        errorMessage = error.message
      } else if (typeof error === 'string') {
        errorMessage = error
      }
      
      // Provide more helpful error messages
      if (errorMessage.includes('fetch')) {
        errorMessage = 'Network error: Unable to connect to analysis service. Please check your internet connection and try again.'
      } else if (errorMessage.includes('Invalid Play Store URL')) {
        errorMessage = 'Please provide a valid Google Play Store app URL (e.g., https://play.google.com/store/apps/details?id=com.example.app)'
      } else if (errorMessage.includes('base64')) {
        errorMessage = 'Invalid APK file format. Please ensure you\'re uploading a valid .apk file.'
      }
      
      setAnalysisError(errorMessage)
      toast.error(errorMessage, { id: 'analysis' })
    } finally {
      setIsAnalyzing(false)
      setCurrentAnalysisType(null)
      setAnalysisProgress(0)
    }
  }

  const startAnalysis = () => {
    if (selectedFile || playStoreUrl) {
      performRealAnalysis()
    }
  }

  const downloadReport = (format: 'pdf' | 'json') => {
    if (!analysisResult) return
    
    if (format === 'json') {
      const dataStr = JSON.stringify(analysisResult, null, 2)
      const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr)
      const exportFileDefaultName = `security-report-${analysisResult.appName}-${new Date().toISOString().split('T')[0]}.json`
      
      const linkElement = document.createElement('a')
      linkElement.setAttribute('href', dataUri)
      linkElement.setAttribute('download', exportFileDefaultName)
      linkElement.click()
    } else {
      // Simulate PDF download
      alert('PDF report generation would be implemented with a PDF library like jsPDF or server-side generation.')
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-200'
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-200'
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200'
      case 'low': return 'bg-green-100 text-green-800 border-green-200'
      default: return 'bg-gray-100 text-gray-800 border-gray-200'
    }
  }

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical': return <XCircle className="w-4 h-4" />
      case 'high': return <AlertTriangle className="w-4 h-4" />
      case 'medium': return <AlertTriangle className="w-4 h-4" />
      case 'low': return <CheckCircle className="w-4 h-4" />
      default: return <AlertTriangle className="w-4 h-4" />
    }
  }

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-green-600'
    if (score >= 60) return 'text-yellow-600'
    return 'text-red-600'
  }

  const CircularProgress = ({ value, size = 120 }: { value: number; size?: number }) => {
    const radius = (size - 8) / 2
    const circumference = radius * 2 * Math.PI
    const strokeDasharray = `${(value / 100) * circumference} ${circumference}`
    
    return (
      <div className="relative" style={{ width: size, height: size }}>
        <svg className="transform -rotate-90" width={size} height={size}>
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="currentColor"
            strokeWidth="8"
            fill="transparent"
            className="text-slate-200"
          />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="currentColor"
            strokeWidth="8"
            fill="transparent"
            strokeDasharray={strokeDasharray}
            className={getScoreColor(value)}
            strokeLinecap="round"
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="text-center">
            <div className={`text-2xl font-bold ${getScoreColor(value)}`}>{value}</div>
            <div className="text-xs text-slate-500">/ 100</div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100">
      <Toaster 
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: {
            background: '#363636',
            color: '#fff',
          },
          success: {
            duration: 3000,
            iconTheme: {
              primary: '#10b981',
              secondary: '#fff',
            },
          },
          error: {
            duration: 5000,
            iconTheme: {
              primary: '#ef4444',
              secondary: '#fff',
            },
          },
        }}
      />
      {/* Header */}
      <header className="bg-white border-b border-slate-200 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-3">
              <Shield className="w-8 h-8 text-blue-600" />
              <h1 className="text-xl font-semibold text-slate-900">Mobile App Security Analyzer</h1>
            </div>
            <div className="flex items-center space-x-4">
              <Button 
                variant="outline" 
                size="sm"
                onClick={() => setShowHistory(!showHistory)}
              >
                <History className="w-4 h-4 mr-2" />
                History ({analysisHistory.length})
              </Button>
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="flex gap-6">
          {/* Main Content */}
          <div className={`flex-1 transition-all duration-300 ${showHistory ? 'mr-80' : ''}`}>
            {!analysisResult ? (
              <div className="space-y-8">
                {/* Hero Section */}
                <div className="text-center space-y-4">
                  <h2 className="text-3xl font-bold text-slate-900">
                    Comprehensive OWASP Security Analysis
                  </h2>
                  <p className="text-lg text-slate-600 max-w-2xl mx-auto">
                    Upload your APK file or provide a Play Store URL to get detailed security insights 
                    and actionable recommendations based on OWASP Mobile Top 10.
                  </p>
                </div>

                {/* Upload Interface */}
                <Card className="max-w-2xl mx-auto">
                  <CardHeader>
                    <CardTitle>Start Security Analysis</CardTitle>
                    <CardDescription>
                      Choose your preferred method to analyze your mobile application
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <Tabs defaultValue="upload" className="w-full">
                      <TabsList className="grid w-full grid-cols-2">
                        <TabsTrigger value="upload">Upload APK</TabsTrigger>
                        <TabsTrigger value="url">Play Store URL</TabsTrigger>
                      </TabsList>
                      
                      <TabsContent value="upload" className="space-y-4">
                        <div
                          className={`border-2 border-dashed rounded-lg p-8 text-center transition-all duration-200 ${
                            dragActive 
                              ? 'border-blue-400 bg-blue-50 scale-105' 
                              : 'border-slate-300 hover:border-slate-400 hover:bg-slate-50'
                          }`}
                          onDragEnter={handleDrag}
                          onDragLeave={handleDrag}
                          onDragOver={handleDrag}
                          onDrop={handleDrop}
                        >
                          <Upload className={`w-12 h-12 mx-auto mb-4 transition-colors ${
                            dragActive ? 'text-blue-500' : 'text-slate-400'
                          }`} />
                          <div className="space-y-2">
                            <p className="text-lg font-medium text-slate-900">
                              Drop your APK file here
                            </p>
                            <p className="text-sm text-slate-500">
                              or click to browse files
                            </p>
                          </div>
                          <input
                            type="file"
                            accept=".apk"
                            onChange={handleFileSelect}
                            className="hidden"
                            id="apk-upload"
                          />
                          <label htmlFor="apk-upload">
                            <Button variant="outline" className="mt-4" asChild>
                              <span>Browse Files</span>
                            </Button>
                          </label>
                        </div>
                        
                        {selectedFile && (
                          <Alert className="animate-slide-up">
                            <CheckCircle className="w-4 h-4" />
                            <AlertDescription>
                              Selected file: <strong>{selectedFile.name}</strong> ({(selectedFile.size / 1024 / 1024).toFixed(2)} MB)
                            </AlertDescription>
                          </Alert>
                        )}
                      </TabsContent>
                      
                      <TabsContent value="url" className="space-y-4">
                        <div className="space-y-2">
                          <label className="text-sm font-medium text-slate-700">
                            Play Store URL
                          </label>
                          <div className="flex space-x-2">
                            <div className="relative flex-1">
                              <Link className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400" />
                              <Input
                                placeholder="https://play.google.com/store/apps/details?id=..."
                                value={playStoreUrl}
                                onChange={(e) => {
                                  setPlayStoreUrl(e.target.value)
                                  setAnalysisError(null)
                                }}
                                className="pl-10"
                              />
                            </div>
                          </div>
                        </div>
                      </TabsContent>
                    </Tabs>

                    {/* Error Display */}
                    {analysisError && (
                      <Alert className="mt-4 border-red-200 bg-red-50">
                        <AlertTriangle className="w-4 h-4 text-red-600" />
                        <AlertDescription className="text-red-800">
                          {analysisError}
                        </AlertDescription>
                      </Alert>
                    )}

                    {isAnalyzing ? (
                      <div className="space-y-4 mt-6">
                        <div className="text-center">
                          <div className="flex items-center justify-center mb-2">
                            <Loader2 className="w-5 h-5 animate-spin mr-2 text-blue-600" />
                            <p className="text-sm font-medium text-slate-700">
                              {currentAnalysisType === 'apk' ? 'Analyzing APK file...' : 'Analyzing Play Store app...'}
                            </p>
                          </div>
                          <Progress value={analysisProgress} className="w-full" />
                          <p className="text-xs text-slate-500 mt-1">
                            {analysisProgress}% complete
                          </p>
                        </div>
                      </div>
                    ) : (
                      <Button 
                        onClick={startAnalysis}
                        disabled={!selectedFile && !playStoreUrl}
                        className="w-full mt-6"
                        size="lg"
                      >
                        <Shield className="w-4 h-4 mr-2" />
                        Start Security Analysis
                      </Button>
                    )}
                  </CardContent>
                </Card>
              </div>
            ) : (
              /* Analysis Results */
              <div className="space-y-6 animate-fade-in">
                {/* Results Header */}
                <Card className="border-l-4 border-l-blue-500">
                  <CardContent className="p-6">
                    <div className="flex items-center justify-between">
                      <div className="flex-1">
                        <h2 className="text-2xl font-bold text-slate-900">{analysisResult.appName}</h2>
                        <p className="text-slate-600">{analysisResult.packageName} • v{analysisResult.version}</p>
                        <div className="flex items-center space-x-4 mt-2 text-sm text-slate-500">
                          <span className="flex items-center">
                            <Clock className="w-4 h-4 mr-1" />
                            {new Date(analysisResult.analysisDate).toLocaleDateString()}
                          </span>
                          {analysisResult.fileSize && (
                            <span>
                              {(analysisResult.fileSize / 1024 / 1024).toFixed(2)} MB
                            </span>
                          )}
                          <span>
                            Analysis time: {analysisResult.analysisTime}s
                          </span>
                        </div>
                      </div>
                      <div className="flex items-center space-x-6">
                        <div className="text-center">
                          <CircularProgress value={analysisResult.securityScore} />
                          <p className="text-sm text-slate-600 mt-2">Security Score</p>
                        </div>
                        <div className="space-y-2">
                          <Button onClick={() => downloadReport('json')} size="sm" variant="outline">
                            <FileText className="w-4 h-4 mr-2" />
                            JSON Report
                          </Button>
                          <Button onClick={() => downloadReport('pdf')} size="sm">
                            <Download className="w-4 h-4 mr-2" />
                            PDF Report
                          </Button>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* OWASP Coverage Overview */}
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center">
                      <BarChart3 className="w-5 h-5 mr-2" />
                      OWASP Mobile Top 10 Coverage
                    </CardTitle>
                    <CardDescription>
                      Security analysis coverage across OWASP Mobile Top 10 categories
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {analysisResult.owaspCoverage.map((category, index) => (
                        <div key={index} className="flex items-center justify-between p-3 rounded-lg border">
                          <div className="flex-1">
                            <p className="text-sm font-medium text-slate-900">{category.category}</p>
                          </div>
                          <div className="flex items-center space-x-2">
                            {category.issues > 0 ? (
                              <>
                                <Badge className={getSeverityColor(category.severity)} variant="outline">
                                  {category.issues} issue{category.issues > 1 ? 's' : ''}
                                </Badge>
                                {getSeverityIcon(category.severity)}
                              </>
                            ) : (
                              <Badge className="bg-green-100 text-green-800 border-green-200" variant="outline">
                                <CheckCircle className="w-3 h-3 mr-1" />
                                Clean
                              </Badge>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>

                {/* Security Issues */}
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center justify-between">
                      <span className="flex items-center">
                        <AlertTriangle className="w-5 h-5 mr-2" />
                        Security Issues Found ({analysisResult.issues.length})
                      </span>
                      <div className="flex space-x-2">
                        {['critical', 'high', 'medium', 'low'].map(severity => {
                          const count = analysisResult.issues.filter(issue => issue.severity === severity).length
                          return count > 0 ? (
                            <Badge key={severity} className={getSeverityColor(severity)} variant="outline">
                              {count} {severity}
                            </Badge>
                          ) : null
                        })}
                      </div>
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {analysisResult.issues.map((issue) => (
                      <Card key={issue.id} className={`border-l-4 ${
                        issue.severity === 'critical' ? 'border-l-red-500' :
                        issue.severity === 'high' ? 'border-l-orange-500' :
                        issue.severity === 'medium' ? 'border-l-yellow-500' :
                        'border-l-green-500'
                      }`}>
                        <CardHeader className="pb-3">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center space-x-3">
                              {getSeverityIcon(issue.severity)}
                              <div>
                                <CardTitle className="text-lg">{issue.title}</CardTitle>
                                <CardDescription>{issue.owaspCategory}</CardDescription>
                              </div>
                            </div>
                            <div className="flex items-center space-x-2">
                              <Badge className={getSeverityColor(issue.severity)}>
                                {issue.severity.toUpperCase()}
                              </Badge>
                              <Dialog>
                                <DialogTrigger asChild>
                                  <Button variant="outline" size="sm">
                                    <Eye className="w-4 h-4 mr-1" />
                                    Details
                                  </Button>
                                </DialogTrigger>
                                <DialogContent className="max-w-4xl max-h-[80vh]">
                                  <DialogHeader>
                                    <DialogTitle className="flex items-center space-x-2">
                                      {getSeverityIcon(issue.severity)}
                                      <span>{issue.title}</span>
                                      <Badge className={getSeverityColor(issue.severity)}>
                                        {issue.severity.toUpperCase()}
                                      </Badge>
                                    </DialogTitle>
                                    <DialogDescription>
                                      {issue.owaspCategory} • {issue.category}
                                    </DialogDescription>
                                  </DialogHeader>
                                  <ScrollArea className="max-h-[60vh]">
                                    <div className="space-y-6 pr-4">
                                      <div>
                                        <h4 className="font-semibold text-slate-900 mb-2">Description</h4>
                                        <p className="text-slate-600">{issue.description}</p>
                                      </div>
                                      
                                      <Separator />
                                      
                                      <div>
                                        <h4 className="font-semibold text-slate-900 mb-2">Technical Details</h4>
                                        <p className="text-slate-600">{issue.technicalDetails}</p>
                                      </div>
                                      
                                      <Separator />
                                      
                                      <div>
                                        <h4 className="font-semibold text-slate-900 mb-2">Recommendation</h4>
                                        <p className="text-slate-600">{issue.recommendation}</p>
                                      </div>
                                      
                                      {issue.codeExample && (
                                        <>
                                          <Separator />
                                          <div>
                                            <h4 className="font-semibold text-slate-900 mb-2">Code Example</h4>
                                            <pre className="bg-slate-100 p-4 rounded-lg text-sm overflow-x-auto">
                                              <code>{issue.codeExample}</code>
                                            </pre>
                                          </div>
                                        </>
                                      )}
                                      
                                      <Separator />
                                      
                                      <div>
                                        <h4 className="font-semibold text-slate-900 mb-2">References</h4>
                                        <ul className="space-y-1">
                                          {issue.references.map((ref, index) => (
                                            <li key={index}>
                                              <a 
                                                href={ref} 
                                                target="_blank" 
                                                rel="noopener noreferrer"
                                                className="text-blue-600 hover:text-blue-800 text-sm underline"
                                              >
                                                {ref}
                                              </a>
                                            </li>
                                          ))}
                                        </ul>
                                      </div>
                                    </div>
                                  </ScrollArea>
                                </DialogContent>
                              </Dialog>
                            </div>
                          </div>
                        </CardHeader>
                        <CardContent className="space-y-3">
                          <div>
                            <p className="text-slate-600 text-sm">{issue.description}</p>
                          </div>
                          <div className="bg-blue-50 p-3 rounded-lg">
                            <h5 className="font-medium text-blue-900 text-sm mb-1">💡 Recommendation</h5>
                            <p className="text-blue-800 text-sm">{issue.recommendation}</p>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </CardContent>
                </Card>

                {/* New Analysis Button */}
                <div className="text-center pt-6">
                  <Button 
                    onClick={() => {
                      setAnalysisResult(null)
                      setSelectedFile(null)
                      setPlayStoreUrl('')
                      setAnalysisProgress(0)
                      setAnalysisError(null)
                    }}
                    variant="outline"
                    size="lg"
                  >
                    Analyze Another App
                  </Button>
                </div>
              </div>
            )}
          </div>

          {/* History Sidebar */}
          {showHistory && (
            <div className="fixed right-0 top-16 h-[calc(100vh-4rem)] w-80 bg-white border-l border-slate-200 shadow-lg z-10 animate-slide-up">
              <div className="p-4 border-b border-slate-200">
                <h3 className="font-semibold text-slate-900">Analysis History</h3>
                <p className="text-sm text-slate-500">Recent security analyses</p>
              </div>
              <ScrollArea className="h-[calc(100%-5rem)]">
                <div className="p-4 space-y-3">
                  {analysisHistory.length === 0 ? (
                    <div className="text-center py-8">
                      <History className="w-12 h-12 text-slate-300 mx-auto mb-3" />
                      <p className="text-slate-500 text-sm">No analyses yet</p>
                    </div>
                  ) : (
                    analysisHistory.map((analysis) => (
                      <Card 
                        key={analysis.id} 
                        className="cursor-pointer hover:shadow-md transition-shadow"
                        onClick={() => setAnalysisResult(analysis)}
                      >
                        <CardContent className="p-4">
                          <div className="flex items-center justify-between mb-2">
                            <h4 className="font-medium text-slate-900 text-sm truncate">
                              {analysis.appName}
                            </h4>
                            <div className={`text-xs font-bold ${getScoreColor(analysis.securityScore)}`}>
                              {analysis.securityScore}/100
                            </div>
                          </div>
                          <p className="text-xs text-slate-500 mb-2">
                            {new Date(analysis.analysisDate).toLocaleDateString()}
                          </p>
                          <div className="flex items-center justify-between">
                            <div className="flex space-x-1">
                              {['critical', 'high', 'medium', 'low'].map(severity => {
                                const count = analysis.issues.filter(issue => issue.severity === severity).length
                                return count > 0 ? (
                                  <Badge key={severity} className={`${getSeverityColor(severity)} text-xs`} variant="outline">
                                    {count}
                                  </Badge>
                                ) : null
                              })}
                            </div>
                            <TrendingUp className="w-4 h-4 text-slate-400" />
                          </div>
                        </CardContent>
                      </Card>
                    ))
                  )}
                </div>
              </ScrollArea>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default App