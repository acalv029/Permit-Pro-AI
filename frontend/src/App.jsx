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
      setLoadingStatus('Analyzing...')
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

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-100 via-teal-100 to-cyan-100">
      {/* Nav */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-blue-100/80 backdrop-blur-xl border-b border-teal-300/50">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3 cursor-pointer" onClick={() => { setPage('home'); setResults(null) }}>
            <div className="w-11 h-11 bg-gradient-to-br from-blue-600 to-teal-500 rounded-xl flex items-center justify-center">
              <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
              </svg>
            </div>
            <div>
              <h1 className="text-xl font-bold text-slate-900">PermitPro AI</h1>
              <p className="text-xs text-teal-600 font-semibold">South Florida</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            {currentUser ? (
              <>
                <button onClick={() => setPage('history')} className="text-sm font-semibold text-slate-700 hover:text-teal-600">History</button>
                <span className="text-sm text-slate-600">{currentUser.email}</span>
                <button onClick={logout} className="text-sm text-red-600 hover:text-red-700">Logout</button>
              </>
            ) : (
              <>
                <button onClick={() => setShowLogin(true)} className="text-sm font-semibold text-slate-700 hover:text-teal-600">Log In</button>
                <button onClick={() => setShowRegister(true)} className="px-5 py-2.5 bg-gradient-to-r from-slate-900 to-slate-800 text-white text-sm font-bold rounded-xl hover:scale-105 transition-transform">Sign Up</button>
              </>
            )}
          </div>
        </div>
      </nav>

      {/* Login Modal */}
      {showLogin && (
        <div className="fixed inset-0 z-50 bg-black/50 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl p-8 max-w-md w-full">
            <div className="flex justify-between items-center mb-6">
              <h2 className="text-2xl font-bold">Log In</h2>
              <button onClick={() => { setShowLogin(false); setError('') }} className="text-2xl text-gray-500">&times;</button>
            </div>
            <form onSubmit={handleLogin}>
              <input name="email" type="email" required placeholder="Email" className="w-full px-4 py-3 border rounded-xl mb-4" />
              <input name="password" type="password" required placeholder="Password" className="w-full px-4 py-3 border rounded-xl mb-4" />
              {error && <p className="text-red-500 text-sm mb-4">{error}</p>}
              <button type="submit" className="w-full py-3 bg-gradient-to-r from-blue-600 to-teal-600 text-white font-bold rounded-xl">Log In</button>
            </form>
            <p className="text-center mt-4 text-sm text-gray-600">No account? <button onClick={() => { setShowLogin(false); setShowRegister(true); setError('') }} className="text-teal-600">Sign up</button></p>
          </div>
        </div>
      )}

      {/* Register Modal */}
      {showRegister && (
        <div className="fixed inset-0 z-50 bg-black/50 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl p-8 max-w-md w-full">
            <div className="flex justify-between items-center mb-6">
              <h2 className="text-2xl font-bold">Create Account</h2>
              <button onClick={() => { setShowRegister(false); setError('') }} className="text-2xl text-gray-500">&times;</button>
            </div>
            <form onSubmit={handleRegister}>
              <input name="email" type="email" required placeholder="Email" className="w-full px-4 py-3 border rounded-xl mb-4" />
              <input name="password" type="password" required minLength="8" placeholder="Password (min 8)" className="w-full px-4 py-3 border rounded-xl mb-4" />
              <input name="fullName" type="text" placeholder="Full Name (optional)" className="w-full px-4 py-3 border rounded-xl mb-4" />
              <input name="company" type="text" placeholder="Company (optional)" className="w-full px-4 py-3 border rounded-xl mb-4" />
              {error && <p className="text-red-500 text-sm mb-4">{error}</p>}
              <button type="submit" className="w-full py-3 bg-gradient-to-r from-blue-600 to-teal-600 text-white font-bold rounded-xl">Create Account</button>
            </form>
            <p className="text-center mt-4 text-sm text-gray-600">Have an account? <button onClick={() => { setShowRegister(false); setShowLogin(true); setError('') }} className="text-teal-600">Log in</button></p>
          </div>
        </div>
      )}

      {/* Loading Overlay */}
      {loading && (
        <div className="fixed inset-0 z-50 bg-slate-900/90 flex items-center justify-center">
          <div className="text-center text-white">
            <div className="w-16 h-16 border-4 border-teal-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
            <h3 className="text-xl font-bold mb-2">Analyzing...</h3>
            <p className="text-teal-300 mb-4">{loadingStatus}</p>
            <div className="w-64 h-2 bg-slate-700 rounded-full mx-auto">
              <div className="h-2 bg-teal-500 rounded-full transition-all" style={{ width: `${progress}%` }}></div>
            </div>
          </div>
        </div>
      )}

      {/* Main Content */}
      <div className="pt-24 px-6 pb-12">
        {page === 'home' && (
          <div className="max-w-4xl mx-auto">
            <div className="text-center mb-12">
              <h1 className="text-4xl md:text-5xl font-black text-slate-900 mb-4">South Florida Permit Checker</h1>
              <p className="text-xl text-slate-600">Upload your permit package for instant AI analysis</p>
            </div>

            <div className="bg-white rounded-3xl shadow-xl p-8 border-2 border-teal-200">
              {/* City & Permit */}
              <div className="grid md:grid-cols-2 gap-4 mb-8">
                <div>
                  <label className="block text-sm font-semibold text-slate-700 mb-2">City</label>
                  <select value={city} onChange={e => setCity(e.target.value)} className="w-full px-4 py-3 border-2 border-teal-200 rounded-xl focus:border-teal-500 outline-none">
                    <option value="">Select city...</option>
                    <option value="Fort Lauderdale">Fort Lauderdale</option>
                    <option value="Pompano Beach">Pompano Beach</option>
                    <option value="Hollywood">Hollywood</option>
                    <option value="Coral Springs">Coral Springs</option>
                    <option value="Boca Raton">Boca Raton</option>
                    <option value="Lauderdale-by-the-Sea">Lauderdale-by-the-Sea</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-semibold text-slate-700 mb-2">Permit Type</label>
                  <select value={permitType} onChange={e => setPermitType(e.target.value)} className="w-full px-4 py-3 border-2 border-teal-200 rounded-xl focus:border-teal-500 outline-none">
                    <option value="">Select type...</option>
                    <option value="building">Building</option>
                    <option value="electrical">Electrical</option>
                    <option value="plumbing">Plumbing</option>
                    <option value="mechanical">Mechanical/HVAC</option>
                    <option value="roofing">Roofing</option>
                  </select>
                </div>
              </div>

              {/* Upload */}
              <div className="mb-8">
                <label className="block text-sm font-semibold text-slate-700 mb-2">Upload Files</label>
                <div className="border-2 border-dashed border-teal-300 rounded-2xl p-8 text-center hover:border-teal-500 transition-colors">
                  <input type="file" multiple webkitdirectory="" directory="" onChange={handleFiles} className="hidden" id="fileInput" />
                  <label htmlFor="fileInput" className="cursor-pointer">
                    <div className="w-16 h-16 bg-teal-100 rounded-2xl flex items-center justify-center mx-auto mb-4">
                      <svg className="w-8 h-8 text-teal-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                      </svg>
                    </div>
                    <p className="font-bold text-slate-900">Drop your permit folder here</p>
                    <p className="text-sm text-slate-500 mt-1">PDF, PNG, JPG • Max 50 files • 200MB total</p>
                  </label>
                </div>

                {validFiles.length > 0 && (
                  <div className="mt-4 p-4 bg-teal-50 rounded-xl">
                    <div className="flex justify-between items-center mb-2">
                      <span className="font-semibold text-slate-700">{validFiles.length} files selected ({formatSize(totalSize)})</span>
                      <button onClick={clearFiles} className="text-sm text-red-600">Clear</button>
                    </div>
                    <div className="max-h-32 overflow-y-auto text-sm text-slate-600">
                      {validFiles.map((f, i) => <div key={i}>{f.name}</div>)}
                    </div>
                  </div>
                )}
              </div>

              {/* Analyze Button */}
              <button onClick={analyze} disabled={!canAnalyze} className={`w-full py-4 rounded-xl font-bold text-lg transition-all ${canAnalyze ? 'bg-gradient-to-r from-blue-600 to-teal-600 text-white hover:scale-105' : 'bg-gray-200 text-gray-500 cursor-not-allowed'}`}>
                {canAnalyze ? `Analyze ${validFiles.length} Files` : 'Select city, permit type & files'}
              </button>
              {!currentUser && <p className="text-center text-sm text-slate-500 mt-3">Sign up to save your analysis history</p>}
            </div>
          </div>
        )}

        {page === 'history' && (
          <div className="max-w-4xl mx-auto">
            <div className="flex justify-between items-center mb-8">
              <h1 className="text-3xl font-bold text-slate-900">Analysis History</h1>
              <button onClick={() => setPage('home')} className="px-6 py-3 bg-gradient-to-r from-blue-600 to-teal-600 text-white font-bold rounded-xl">New Analysis</button>
            </div>
            {historyLoading ? (
              <div className="text-center py-12"><div className="w-8 h-8 border-2 border-teal-500 border-t-transparent rounded-full animate-spin mx-auto"></div></div>
            ) : history.length === 0 ? (
              <div className="text-center py-12 bg-white rounded-2xl"><p className="text-slate-500">No analyses yet</p></div>
            ) : (
              <div className="bg-white rounded-2xl overflow-hidden">
                <table className="w-full">
                  <thead className="bg-teal-50">
                    <tr>
                      <th className="text-left px-6 py-4 text-sm font-semibold text-slate-700">Date</th>
                      <th className="text-left px-6 py-4 text-sm font-semibold text-slate-700">City</th>
                      <th className="text-left px-6 py-4 text-sm font-semibold text-slate-700">Type</th>
                      <th className="text-left px-6 py-4 text-sm font-semibold text-slate-700">Score</th>
                      <th className="px-6 py-4"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.map(h => (
                      <tr key={h.analysis_uuid} className="border-t hover:bg-teal-50">
                        <td className="px-6 py-4 text-sm">{new Date(h.created_at).toLocaleDateString()}</td>
                        <td className="px-6 py-4 text-sm font-semibold">{h.city}</td>
                        <td className="px-6 py-4 text-sm">{h.permit_type}</td>
                        <td className="px-6 py-4 text-sm font-bold text-teal-600">{h.compliance_score || '-'}%</td>
                        <td className="px-6 py-4"><button onClick={() => viewAnalysis(h.analysis_uuid)} className="text-teal-600 hover:underline text-sm">View</button></td>
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
            <div className="bg-white rounded-3xl shadow-xl overflow-hidden">
              <div className="p-8 border-b bg-gradient-to-r from-teal-50 to-blue-50">
                <div className="flex justify-between items-center">
                  <div>
                    <h2 className="text-2xl font-bold text-slate-900">Analysis Complete</h2>
                    <p className="text-slate-600">{results.city} - {results.permit_type}</p>
                  </div>
                  <div className="text-center">
                    <div className={`text-4xl font-black ${(results.analysis?.compliance_score || 0) >= 70 ? 'text-emerald-500' : (results.analysis?.compliance_score || 0) >= 40 ? 'text-amber-500' : 'text-red-500'}`}>
                      {results.analysis?.compliance_score || 0}%
                    </div>
                    <div className="text-sm text-slate-500">Compliance</div>
                  </div>
                </div>
              </div>
              <div className="p-8">
                {results.analysis?.summary && (
                  <div className="mb-6">
                    <h3 className="font-bold text-slate-900 mb-2">Summary</h3>
                    <p className="text-slate-600">{results.analysis.summary}</p>
                  </div>
                )}
                {results.analysis?.critical_issues?.length > 0 && (
                  <div className="mb-6">
                    <h3 className="font-bold text-red-600 mb-2">Critical Issues</h3>
                    <ul className="list-disc pl-5 text-red-600 space-y-1">
                      {results.analysis.critical_issues.map((issue, i) => <li key={i}>{issue}</li>)}
                    </ul>
                  </div>
                )}
                {results.analysis?.missing_documents?.length > 0 && (
                  <div className="mb-6">
                    <h3 className="font-bold text-amber-600 mb-2">Missing Documents</h3>
                    <ul className="list-disc pl-5 text-amber-600 space-y-1">
                      {results.analysis.missing_documents.map((doc, i) => <li key={i}>{doc}</li>)}
                    </ul>
                  </div>
                )}
                {results.analysis?.recommendations?.length > 0 && (
                  <div className="mb-6">
                    <h3 className="font-bold text-teal-600 mb-2">Recommendations</h3>
                    <ul className="list-disc pl-5 text-slate-600 space-y-1">
                      {results.analysis.recommendations.map((rec, i) => <li key={i}>{rec}</li>)}
                    </ul>
                  </div>
                )}
              </div>
              <div className="p-6 bg-slate-50 border-t flex justify-center">
                <button onClick={() => { setPage('home'); setResults(null); clearFiles() }} className="px-8 py-3 bg-gradient-to-r from-blue-600 to-teal-600 text-white font-bold rounded-xl">New Analysis</button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}