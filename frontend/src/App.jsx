import { useState, useEffect } from 'react'

const API_BASE_URL = 'https://permit-pro-ai-production.up.railway.app'

export default function App() {
  const [currentUser, setCurrentUser] = useState(null)
  const [authToken, setAuthToken] = useState(null)
  const [showLogin, setShowLogin] = useState(false)
  const [showRegister, setShowRegister] = useState(false)
  const [page, setPage] = useState('home')
  const [city, setCity] = useState('')
  const [permitType, setPermitType] = useState('')
  const [files, setFiles] = useState([])
  const [validFiles, setValidFiles] = useState([])
  const [loading, setLoading] = useState(false)
  const [loadingStatus, setLoadingStatus] = useState('')
  const [progress, setProgress] = useState(0)
  const [results, setResults] = useState(null)
  const [history, setHistory] = useState([])
  const [historyLoading, setHistoryLoading] = useState(false)
  const [error, setError] = useState('')
  const [isDragging, setIsDragging] = useState(false)

  useEffect(() => {
    const token = localStorage.getItem('authToken')
    const user = localStorage.getItem('currentUser')
    if (token && user) {
      setAuthToken(token)
      setCurrentUser(JSON.parse(user))
    }
  }, [])

  const handleLogin = async (e) => {
    e.preventDefault()
    setError('')
    const email = e.target.email.value
    const password = e.target.password.value
    try {
      const res = await fetch(`${API_BASE_URL}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      })
      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.detail || 'Login failed')
      }
      const data = await res.json()
      setAuthToken(data.access_token)
      setCurrentUser(data.user)
      localStorage.setItem('authToken', data.access_token)
      localStorage.setItem('currentUser', JSON.stringify(data.user))
      setShowLogin(false)
    } catch (err) {
      setError(err.message)
    }
  }

  const handleRegister = async (e) => {
    e.preventDefault()
    setError('')
    const email = e.target.email.value
    const password = e.target.password.value
    const full_name = e.target.fullName.value || null
    const company_name = e.target.company.value || null
    try {
      const res = await fetch(`${API_BASE_URL}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, full_name, company_name })
      })
      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.detail || 'Registration failed')
      }
      const data = await res.json()
      setAuthToken(data.access_token)
      setCurrentUser(data.user)
      localStorage.setItem('authToken', data.access_token)
      localStorage.setItem('currentUser', JSON.stringify(data.user))
      setShowRegister(false)
    } catch (err) {
      setError(err.message)
    }
  }

  const logout = () => {
    setAuthToken(null)
    setCurrentUser(null)
    localStorage.removeItem('authToken')
    localStorage.removeItem('currentUser')
    setPage('home')
  }

  const handleFiles = (e) => {
    const fileList = Array.from(e.target.files)
    setFiles(fileList)
    const valid = fileList.filter(f => {
      const ext = f.name.split('.').pop().toLowerCase()
      return ['pdf', 'png', 'jpg', 'jpeg'].includes(ext) && f.size <= 25 * 1024 * 1024
    }).slice(0, 50)
    setValidFiles(valid)
  }

  const clearFiles = () => {
    setFiles([])
    setValidFiles([])
  }

  const formatSize = (bytes) => {
    if (bytes < 1024) return bytes + ' B'
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
  }

  const totalSize = validFiles.reduce((sum, f) => sum + f.size, 0)

  const analyze = async () => {
    if (!city || !permitType || validFiles.length === 0) return
    setLoading(true)
    setProgress(0)
    setLoadingStatus('Preparing files...')
    try {
      const formData = new FormData()
      formData.append('city', city)
      formData.append('permit_type', permitType)
      validFiles.forEach((f, i) => {
        formData.append('files', f)
        setProgress(((i + 1) / validFiles.length) * 50)
      })
      setLoadingStatus('Uploading...')
      setProgress(50)
      const headers = {}
      if (authToken) headers['Authorization'] = `Bearer ${authToken}`
      const res = await fetch(`${API_BASE_URL}/api/analyze-permit-folder`, {
        method: 'POST',
        headers,
        body: formData
      })
      setProgress(80)
      setLoadingStatus('Analyzing with AI...')
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        throw new Error(err.detail || 'Analysis failed')
      }
      const data = await res.json()
      setProgress(100)
      setResults(data)
      setPage('results')
    } catch (err) {
      alert('Error: ' + err.message)
    } finally {
      setLoading(false)
    }
  }

  const loadHistory = async () => {
    setHistoryLoading(true)
    try {
      const res = await fetch(`${API_BASE_URL}/api/history`, {
        headers: { 'Authorization': `Bearer ${authToken}` }
      })
      if (res.ok) {
        const data = await res.json()
        setHistory(data.analyses || [])
      }
    } catch (err) {
      console.error(err)
    } finally {
      setHistoryLoading(false)
    }
  }

  const viewAnalysis = async (uuid) => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/history/${uuid}`, {
        headers: { 'Authorization': `Bearer ${authToken}` }
      })
      if (res.ok) {
        const data = await res.json()
        setResults({
          city: data.city,
          permit_type: data.permit_type,
          files_analyzed: data.files_analyzed,
          file_tree: data.file_list,
          analysis: data.analysis
        })
        setPage('results')
      }
    } catch (err) {
      alert('Error loading analysis')
    }
  }

  useEffect(() => {
    if (page === 'history' && authToken) loadHistory()
  }, [page])

  const canAnalyze = city && permitType && validFiles.length > 0 && totalSize <= 200 * 1024 * 1024

  const getPermitTypes = () => {
    const basePermits = [
      { value: 'building', label: 'Building' },
      { value: 'electrical', label: 'Electrical' },
      { value: 'plumbing', label: 'Plumbing' },
      { value: 'mechanical', label: 'Mechanical/HVAC' },
      { value: 'roofing', label: 'Roofing' },
    ]
    
    const waterfrontCities = [
      'Fort Lauderdale',
      'Pompano Beach',
      'Hollywood',
      'Lauderdale-by-the-Sea',
      'Boca Raton',
      'Deerfield Beach',
    ]
    
    if (waterfrontCities.includes(city)) {
      return [
        ...basePermits,
        { value: 'dock', label: 'Dock/Marine Structure' },
        { value: 'seawall', label: 'Seawall' },
        { value: 'boat_lift', label: 'Boat Lift' },
      ]
    }
    
    return basePermits
  }

  return (
    <div className="min-h-screen bg-black text-white overflow-hidden">
      {/* Animated Background */}
      <div className="fixed inset-0 z-0">
        <div className="absolute inset-0 bg-gradient-to-br from-black via-gray-900 to-black"></div>
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-cyan-500/20 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-purple-500/20 rounded-full blur-3xl animate-pulse" style={{animationDelay: '1s'}}></div>
        <div className="absolute top-1/2 left-1/2 w-64 h-64 bg-emerald-500/10 rounded-full blur-3xl animate-pulse" style={{animationDelay: '2s'}}></div>
        {/* Grid overlay */}
        <div className="absolute inset-0 opacity-20" style={{
          backgroundImage: 'linear-gradient(rgba(6, 182, 212, 0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(6, 182, 212, 0.1) 1px, transparent 1px)',
          backgroundSize: '50px 50px'
        }}></div>
      </div>

      {/* Nav */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-black/80 backdrop-blur-xl border-b border-cyan-500/20">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3 cursor-pointer group" onClick={() => { setPage('home'); setResults(null) }}>
            <div className="relative">
              <div className="absolute inset-0 bg-cyan-500 rounded-xl blur-lg opacity-50 group-hover:opacity-100 transition-opacity"></div>
              <div className="relative w-11 h-11 bg-gradient-to-br from-cyan-400 to-emerald-400 rounded-xl flex items-center justify-center transform group-hover:scale-110 transition-transform">
                <svg className="w-6 h-6 text-black" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
                </svg>
              </div>
            </div>
            <div>
              <h1 className="text-xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent">PermitPro AI</h1>
              <p className="text-xs text-cyan-500 font-semibold tracking-wider">SOUTH FLORIDA</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            {currentUser ? (
              <>
                <button onClick={() => setPage('history')} className="text-sm font-semibold text-gray-400 hover:text-cyan-400 transition-colors">History</button>
                <span className="text-sm text-gray-500">{currentUser.email}</span>
                <button onClick={logout} className="text-sm text-red-400 hover:text-red-300 transition-colors">Logout</button>
              </>
            ) : (
              <>
                <button onClick={() => setShowLogin(true)} className="text-sm font-semibold text-gray-400 hover:text-cyan-400 transition-colors">Log In</button>
                <button onClick={() => setShowRegister(true)} className="relative group">
                  <div className="absolute -inset-0.5 bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-xl blur opacity-60 group-hover:opacity-100 transition-opacity"></div>
                  <div className="relative px-5 py-2.5 bg-black text-white text-sm font-bold rounded-xl">Sign Up</div>
                </button>
              </>
            )}
          </div>
        </div>
      </nav>

      {/* Login Modal */}
      {showLogin && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="relative">
            <div className="absolute -inset-1 bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-3xl blur-lg opacity-50"></div>
            <div className="relative bg-gray-900 rounded-2xl p-8 max-w-md w-full border border-cyan-500/20">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-2xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent">Log In</h2>
                <button onClick={() => { setShowLogin(false); setError('') }} className="text-2xl text-gray-500 hover:text-white transition-colors">&times;</button>
              </div>
              <form onSubmit={handleLogin}>
                <input name="email" type="email" required placeholder="Email" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl mb-4 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none transition-colors" />
                <input name="password" type="password" required placeholder="Password" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl mb-4 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none transition-colors" />
                {error && <p className="text-red-400 text-sm mb-4">{error}</p>}
                <button type="submit" className="relative w-full group">
                  <div className="absolute -inset-0.5 bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-xl blur opacity-60 group-hover:opacity-100 transition-opacity"></div>
                  <div className="relative w-full py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl">Log In</div>
                </button>
              </form>
              <p className="text-center mt-4 text-sm text-gray-500">No account? <button onClick={() => { setShowLogin(false); setShowRegister(true); setError('') }} className="text-cyan-400 hover:text-cyan-300">Sign up</button></p>
            </div>
          </div>
        </div>
      )}

      {/* Register Modal */}
      {showRegister && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="relative">
            <div className="absolute -inset-1 bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-3xl blur-lg opacity-50"></div>
            <div className="relative bg-gray-900 rounded-2xl p-8 max-w-md w-full border border-cyan-500/20">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-2xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent">Create Account</h2>
                <button onClick={() => { setShowRegister(false); setError('') }} className="text-2xl text-gray-500 hover:text-white transition-colors">&times;</button>
              </div>
              <form onSubmit={handleRegister}>
                <input name="email" type="email" required placeholder="Email" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl mb-4 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none transition-colors" />
                <input name="password" type="password" required minLength="8" placeholder="Password (min 8)" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl mb-4 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none transition-colors" />
                <input name="fullName" type="text" placeholder="Full Name (optional)" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl mb-4 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none transition-colors" />
                <input name="company" type="text" placeholder="Company (optional)" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl mb-4 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none transition-colors" />
                {error && <p className="text-red-400 text-sm mb-4">{error}</p>}
                <button type="submit" className="relative w-full group">
                  <div className="absolute -inset-0.5 bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-xl blur opacity-60 group-hover:opacity-100 transition-opacity"></div>
                  <div className="relative w-full py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl">Create Account</div>
                </button>
              </form>
              <p className="text-center mt-4 text-sm text-gray-500">Have an account? <button onClick={() => { setShowRegister(false); setShowLogin(true); setError('') }} className="text-cyan-400 hover:text-cyan-300">Log in</button></p>
            </div>
          </div>
        </div>
      )}

      {/* Loading Overlay */}
      {loading && (
        <div className="fixed inset-0 z-50 bg-black/95 flex items-center justify-center">
          <div className="text-center">
            <div className="relative w-24 h-24 mx-auto mb-6">
              <div className="absolute inset-0 border-4 border-cyan-500/20 rounded-full"></div>
              <div className="absolute inset-0 border-4 border-transparent border-t-cyan-500 rounded-full animate-spin"></div>
              <div className="absolute inset-2 border-4 border-transparent border-t-emerald-500 rounded-full animate-spin" style={{animationDirection: 'reverse', animationDuration: '1.5s'}}></div>
              <div className="absolute inset-4 border-4 border-transparent border-t-purple-500 rounded-full animate-spin" style={{animationDuration: '2s'}}></div>
            </div>
            <h3 className="text-2xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent mb-2">{loadingStatus}</h3>
            <p className="text-gray-500 mb-6">Please wait while we process your documents</p>
            <div className="w-64 h-2 bg-gray-800 rounded-full mx-auto overflow-hidden">
              <div className="h-full bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-full transition-all duration-300 relative" style={{ width: `${progress}%` }}>
                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent animate-shimmer"></div>
              </div>
            </div>
            <p className="text-cyan-400 mt-2 font-mono">{progress}%</p>
          </div>
        </div>
      )}

      {/* Main Content */}
      <div className="relative z-10 pt-24 px-6 pb-12">
        {page === 'home' && (
          <div className="max-w-4xl mx-auto">
            <div className="text-center mb-12">
              <div className="inline-block mb-4">
                <span className="px-4 py-1.5 bg-cyan-500/10 border border-cyan-500/20 rounded-full text-cyan-400 text-sm font-semibold tracking-wide">
                  AI-POWERED PERMIT ANALYSIS
                </span>
              </div>
              <h1 className="text-5xl md:text-7xl font-black mb-6">
                <span className="bg-gradient-to-r from-white via-gray-200 to-gray-400 bg-clip-text text-transparent">South Florida</span>
                <br />
                <span className="bg-gradient-to-r from-cyan-400 via-emerald-400 to-cyan-400 bg-clip-text text-transparent animate-gradient">Permit Checker</span>
              </h1>
              <p className="text-xl text-gray-400 max-w-2xl mx-auto">Upload your permit package and get instant AI-powered analysis with compliance scoring</p>
            </div>

            <div className="relative">
              <div className="absolute -inset-1 bg-gradient-to-r from-cyan-500/50 via-emerald-500/50 to-purple-500/50 rounded-3xl blur-xl opacity-30"></div>
              <div className="relative bg-gray-900/80 backdrop-blur-xl rounded-3xl p-8 border border-gray-800">
                {/* City & Permit */}
                <div className="grid md:grid-cols-2 gap-4 mb-8">
                  <div>
                    <label className="block text-sm font-semibold text-gray-400 mb-2 tracking-wide">CITY</label>
                    <select 
                      value={city} 
                      onChange={e => { 
                        setCity(e.target.value)
                        setPermitType('')
                      }} 
                      className="w-full px-4 py-3.5 bg-black/50 border border-gray-700 rounded-xl text-white focus:border-cyan-500 focus:outline-none transition-all cursor-pointer hover:border-gray-600"
                    >
                      <option value="">Select city...</option>
                      <option value="Fort Lauderdale">Fort Lauderdale</option>
                      <option value="Pompano Beach">Pompano Beach</option>
                      <option value="Hollywood">Hollywood</option>
                      <option value="Coral Springs">Coral Springs</option>
                      <option value="Boca Raton">Boca Raton</option>
                      <option value="Lauderdale-by-the-Sea">Lauderdale-by-the-Sea</option>
                      <option value="Deerfield Beach">Deerfield Beach</option>
                      <option value="Pembroke Pines">Pembroke Pines</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-semibold text-gray-400 mb-2 tracking-wide">PERMIT TYPE</label>
                    <select 
                      value={permitType} 
                      onChange={e => setPermitType(e.target.value)} 
                      className="w-full px-4 py-3.5 bg-black/50 border border-gray-700 rounded-xl text-white focus:border-cyan-500 focus:outline-none transition-all cursor-pointer hover:border-gray-600 disabled:opacity-50 disabled:cursor-not-allowed"
                      disabled={!city}
                    >
                      <option value="">Select type...</option>
                      {getPermitTypes().map(pt => (
                        <option key={pt.value} value={pt.value}>{pt.label}</option>
                      ))}
                    </select>
                    {!city && <p className="text-xs text-gray-600 mt-1">Select a city first</p>}
                  </div>
                </div>

                {/* Upload */}
                <div className="mb-8">
                  <label className="block text-sm font-semibold text-gray-400 mb-2 tracking-wide">UPLOAD FILES</label>
                  <div 
                    className={`relative group cursor-pointer transition-all duration-300 ${isDragging ? 'scale-105' : ''}`}
                    onDragOver={(e) => { e.preventDefault(); setIsDragging(true) }}
                    onDragLeave={() => setIsDragging(false)}
                    onDrop={(e) => { e.preventDefault(); setIsDragging(false); handleFiles({ target: { files: e.dataTransfer.files } }) }}
                  >
                    <div className={`absolute -inset-0.5 bg-gradient-to-r from-cyan-500 via-emerald-500 to-purple-500 rounded-2xl blur opacity-0 group-hover:opacity-50 transition-opacity duration-500 ${isDragging ? 'opacity-75' : ''}`}></div>
                    <div className={`relative border-2 border-dashed rounded-2xl p-10 text-center transition-all duration-300 ${isDragging ? 'border-cyan-400 bg-cyan-500/10' : 'border-gray-700 hover:border-gray-600 bg-black/30'}`}>
                      <input type="file" multiple webkitdirectory="" directory="" onChange={handleFiles} className="hidden" id="fileInput" />
                      <label htmlFor="fileInput" className="cursor-pointer block">
                        <div className={`relative w-20 h-20 mx-auto mb-4 transition-transform duration-300 ${isDragging ? 'scale-110 rotate-3' : 'group-hover:scale-110'}`}>
                          <div className="absolute inset-0 bg-gradient-to-br from-cyan-500 to-emerald-500 rounded-2xl blur-lg opacity-50"></div>
                          <div className="relative w-full h-full bg-gradient-to-br from-cyan-500/20 to-emerald-500/20 rounded-2xl flex items-center justify-center border border-cyan-500/30">
                            <svg className={`w-10 h-10 text-cyan-400 transition-transform duration-300 ${isDragging ? 'translate-y-2' : 'group-hover:-translate-y-1'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                            </svg>
                          </div>
                        </div>
                        <p className="font-bold text-white text-lg mb-1">Drop your permit folder here</p>
                        <p className="text-sm text-gray-500">PDF, PNG, JPG • Max 50 files • 200MB total</p>
                        <div className="mt-4 inline-flex items-center gap-2 px-4 py-2 bg-gray-800 rounded-lg text-sm text-gray-400">
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                          </svg>
                          Click to browse folders
                        </div>
                      </label>
                    </div>
                  </div>

                  {validFiles.length > 0 && (
                    <div className="mt-4 p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-xl">
                      <div className="flex justify-between items-center mb-2">
                        <span className="font-semibold text-emerald-400">
                          <svg className="w-5 h-5 inline mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
                          </svg>
                          {validFiles.length} files selected ({formatSize(totalSize)})
                        </span>
                        <button onClick={clearFiles} className="text-sm text-red-400 hover:text-red-300 transition-colors">Clear all</button>
                      </div>
                      <div className="max-h-32 overflow-y-auto text-sm text-gray-400 space-y-1">
                        {validFiles.map((f, i) => (
                          <div key={i} className="flex items-center gap-2">
                            <svg className="w-4 h-4 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                            </svg>
                            {f.name}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Analyze Button */}
                <button 
                  onClick={analyze} 
                  disabled={!canAnalyze} 
                  className={`relative w-full group ${!canAnalyze ? 'cursor-not-allowed' : ''}`}
                >
                  {canAnalyze && (
                    <div className="absolute -inset-1 bg-gradient-to-r from-cyan-500 via-emerald-500 to-cyan-500 rounded-xl blur-lg opacity-70 group-hover:opacity-100 transition-opacity animate-pulse"></div>
                  )}
                  <div className={`relative w-full py-4 rounded-xl font-bold text-lg transition-all ${
                    canAnalyze 
                      ? 'bg-gradient-to-r from-cyan-500 to-emerald-500 text-black hover:shadow-2xl hover:shadow-cyan-500/25' 
                      : 'bg-gray-800 text-gray-500'
                  }`}>
                    {canAnalyze ? (
                      <span className="flex items-center justify-center gap-2">
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
                        </svg>
                        Analyze {validFiles.length} Files
                      </span>
                    ) : (
                      'Select city, permit type & files'
                    )}
                  </div>
                </button>
                {!currentUser && (
                  <p className="text-center text-sm text-gray-600 mt-4">
                    <span className="text-cyan-500">Sign up</span> to save your analysis history
                  </p>
                )}
              </div>
            </div>

            {/* Features */}
            <div className="grid md:grid-cols-3 gap-6 mt-12">
              {[
                { icon: '⚡', title: 'Instant Analysis', desc: 'Get results in seconds' },
                { icon: '🎯', title: 'Compliance Score', desc: 'Know exactly where you stand' },
                { icon: '📋', title: 'Missing Items', desc: 'Never miss a requirement' },
              ].map((f, i) => (
                <div key={i} className="text-center p-6 bg-gray-900/50 rounded-2xl border border-gray-800 hover:border-gray-700 transition-colors">
                  <div className="text-3xl mb-3">{f.icon}</div>
                  <h3 className="font-bold text-white mb-1">{f.title}</h3>
                  <p className="text-sm text-gray-500">{f.desc}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {page === 'history' && (
          <div className="max-w-4xl mx-auto">
            <div className="flex justify-between items-center mb-8">
              <h1 className="text-3xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent">Analysis History</h1>
              <button onClick={() => setPage('home')} className="relative group">
                <div className="absolute -inset-0.5 bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-xl blur opacity-60 group-hover:opacity-100 transition-opacity"></div>
                <div className="relative px-6 py-3 bg-black text-white font-bold rounded-xl">New Analysis</div>
              </button>
            </div>
            {historyLoading ? (
              <div className="text-center py-12">
                <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto"></div>
              </div>
            ) : history.length === 0 ? (
              <div className="text-center py-12 bg-gray-900/50 rounded-2xl border border-gray-800">
                <p className="text-gray-500">No analyses yet</p>
              </div>
            ) : (
              <div className="bg-gray-900/50 rounded-2xl border border-gray-800 overflow-hidden">
                <table className="w-full">
                  <thead className="bg-black/50">
                    <tr>
                      <th className="text-left px-6 py-4 text-sm font-semibold text-gray-400">Date</th>
                      <th className="text-left px-6 py-4 text-sm font-semibold text-gray-400">City</th>
                      <th className="text-left px-6 py-4 text-sm font-semibold text-gray-400">Type</th>
                      <th className="text-left px-6 py-4 text-sm font-semibold text-gray-400">Score</th>
                      <th className="px-6 py-4"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.map(h => (
                      <tr key={h.analysis_uuid} className="border-t border-gray-800 hover:bg-gray-800/50 transition-colors">
                        <td className="px-6 py-4 text-sm text-gray-400">{new Date(h.created_at).toLocaleDateString()}</td>
                        <td className="px-6 py-4 text-sm font-semibold text-white">{h.city}</td>
                        <td className="px-6 py-4 text-sm text-gray-400">{h.permit_type}</td>
                        <td className="px-6 py-4 text-sm font-bold text-cyan-400">{h.compliance_score || '-'}%</td>
                        <td className="px-6 py-4">
                          <button onClick={() => viewAnalysis(h.analysis_uuid)} className="text-cyan-400 hover:text-cyan-300 text-sm transition-colors">View →</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {page === 'results' && results && (
          <div className="max-w-4xl mx-auto">
            <div className="relative">
              <div className="absolute -inset-1 bg-gradient-to-r from-cyan-500/30 to-emerald-500/30 rounded-3xl blur-xl"></div>
              <div className="relative bg-gray-900/90 backdrop-blur-xl rounded-3xl overflow-hidden border border-gray-800">
                <div className="p-8 border-b border-gray-800 bg-gradient-to-r from-cyan-500/10 to-emerald-500/10">
                  <div className="flex justify-between items-center">
                    <div>
                      <h2 className="text-2xl font-black text-white mb-1">Analysis Complete</h2>
                      <p className="text-gray-400">{results.city} • {results.permit_type}</p>
                    </div>
                    <div className="text-center">
                      <div className={`text-5xl font-black ${(results.analysis?.compliance_score || 0) >= 70 ? 'text-emerald-400' : (results.analysis?.compliance_score || 0) >= 40 ? 'text-amber-400' : 'text-red-400'}`}>
                        {results.analysis?.compliance_score || 0}%
                      </div>
                      <div className="text-sm text-gray-500">Compliance Score</div>
                    </div>
                  </div>
                </div>
                <div className="p-8 space-y-6">
                  {results.analysis?.summary && (
                    <div>
                      <h3 className="font-bold text-white mb-2 flex items-center gap-2">
                        <span className="w-2 h-2 bg-cyan-500 rounded-full"></span>
                        Summary
                      </h3>
                      <p className="text-gray-400 pl-4">{results.analysis.summary}</p>
                    </div>
                  )}
                  {results.analysis?.critical_issues?.length > 0 && (
                    <div>
                      <h3 className="font-bold text-red-400 mb-2 flex items-center gap-2">
                        <span className="w-2 h-2 bg-red-500 rounded-full"></span>
                        Critical Issues
                      </h3>
                      <ul className="space-y-2 pl-4">
                        {results.analysis.critical_issues.map((issue, i) => (
                          <li key={i} className="text-red-300 flex items-start gap-2">
                            <span className="text-red-500 mt-1">•</span>
                            {issue}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {results.analysis?.missing_documents?.length > 0 && (
                    <div>
                      <h3 className="font-bold text-amber-400 mb-2 flex items-center gap-2">
                        <span className="w-2 h-2 bg-amber-500 rounded-full"></span>
                        Missing Documents
                      </h3>
                      <ul className="space-y-2 pl-4">
                        {results.analysis.missing_documents.map((doc, i) => (
                          <li key={i} className="text-amber-300 flex items-start gap-2">
                            <span className="text-amber-500 mt-1">•</span>
                            {doc}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {results.analysis?.recommendations?.length > 0 && (
                    <div>
                      <h3 className="font-bold text-emerald-400 mb-2 flex items-center gap-2">
                        <span className="w-2 h-2 bg-emerald-500 rounded-full"></span>
                        Recommendations
                      </h3>
                      <ul className="space-y-2 pl-4">
                        {results.analysis.recommendations.map((rec, i) => (
                          <li key={i} className="text-gray-400 flex items-start gap-2">
                            <span className="text-emerald-500 mt-1">•</span>
                            {rec}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
                <div className="p-6 bg-black/50 border-t border-gray-800 flex justify-center">
                  <button onClick={() => { setPage('home'); setResults(null); clearFiles() }} className="relative group">
                    <div className="absolute -inset-0.5 bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-xl blur opacity-60 group-hover:opacity-100 transition-opacity"></div>
                    <div className="relative px-8 py-3 bg-black text-white font-bold rounded-xl">New Analysis</div>
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Custom Styles */}
      <style>{`
        @keyframes shimmer {
          0% { transform: translateX(-100%); }
          100% { transform: translateX(100%); }
        }
        .animate-shimmer {
          animation: shimmer 2s infinite;
        }
        @keyframes gradient {
          0%, 100% { background-position: 0% 50%; }
          50% { background-position: 100% 50%; }
        }
        .animate-gradient {
          background-size: 200% 200%;
          animation: gradient 3s ease infinite;
        }
        select option {
          background: #111;
          color: white;
        }
      `}</style>
    </div>
  )
}