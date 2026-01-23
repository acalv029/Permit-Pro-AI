import { useState, useEffect } from 'react'

const API_BASE_URL = 'https://permit-pro-ai-production.up.railway.app' // TODO: Update if Railway URL changes

export default function App() {
  const [currentUser, setCurrentUser] = useState(null)
  const [authToken, setAuthToken] = useState(null)
  const [showLogin, setShowLogin] = useState(false)
  const [showRegister, setShowRegister] = useState(false)
  const [showForgotPassword, setShowForgotPassword] = useState(false)
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
  const [successMessage, setSuccessMessage] = useState('')
  const [isDragging, setIsDragging] = useState(false)
  const [agreedToTerms, setAgreedToTerms] = useState(false)
  const [profile, setProfile] = useState(null)
  const [profileLoading, setProfileLoading] = useState(false)
  const [editingProfile, setEditingProfile] = useState(false)
  const [resetToken, setResetToken] = useState(null)
  const [resetPasswordLoading, setResetPasswordLoading] = useState(false)

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const token = params.get('token')
    if (token) {
      setResetToken(token)
      setPage('reset-password')
      window.history.replaceState({}, document.title, window.location.pathname)
    }
  }, [])

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

  const handleForgotPassword = async (e) => {
    e.preventDefault()
    setError('')
    setSuccessMessage('')
    const email = e.target.email.value
    try {
      const res = await fetch(`${API_BASE_URL}/api/auth/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      })
      const data = await res.json()
      setSuccessMessage(data.message || 'If an account exists, you will receive a reset link.')
      e.target.reset()
    } catch (err) {
      setSuccessMessage('If an account exists with this email, you will receive a password reset link.')
    }
  }

  const handleResetPassword = async (e) => {
    e.preventDefault()
    setError('')
    setResetPasswordLoading(true)
    const newPassword = e.target.newPassword.value
    const confirmPassword = e.target.confirmPassword.value
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match')
      setResetPasswordLoading(false)
      return
    }
    if (newPassword.length < 8) {
      setError('Password must be at least 8 characters')
      setResetPasswordLoading(false)
      return
    }
    try {
      const res = await fetch(`${API_BASE_URL}/api/auth/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: resetToken, new_password: newPassword })
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Password reset failed')
      setSuccessMessage(data.message)
      setResetToken(null)
      setTimeout(() => {
        setPage('home')
        setShowLogin(true)
        setSuccessMessage('')
      }, 3000)
    } catch (err) {
      setError(err.message)
    } finally {
      setResetPasswordLoading(false)
    }
  }

  const logout = () => {
    setAuthToken(null)
    setCurrentUser(null)
    setProfile(null)
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

  const clearFiles = () => { setFiles([]); setValidFiles([]) }
  const formatSize = (bytes) => {
    if (bytes < 1024) return bytes + ' B'
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
  }
  const totalSize = validFiles.reduce((sum, f) => sum + f.size, 0)

  const analyze = async () => {
    if (!city || !permitType || validFiles.length === 0 || !agreedToTerms) return
    setLoading(true)
    setProgress(0)
    setLoadingStatus('Preparing files...')
    try {
      const formData = new FormData()
      formData.append('city', city)
      formData.append('permit_type', permitType)
      validFiles.forEach((f) => formData.append('files', f))
      setLoadingStatus('Uploading...')
      setProgress(50)
      const headers = {}
      if (authToken) headers['Authorization'] = `Bearer ${authToken}`
      const res = await fetch(`${API_BASE_URL}/api/analyze-permit-folder`, { method: 'POST', headers, body: formData })
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
      const res = await fetch(`${API_BASE_URL}/api/history`, { headers: { 'Authorization': `Bearer ${authToken}` } })
      if (res.ok) { const data = await res.json(); setHistory(data.analyses || []) }
    } catch (err) { console.error(err) }
    finally { setHistoryLoading(false) }
  }

  const loadProfile = async () => {
    if (!authToken) return
    setProfileLoading(true)
    try {
      const res = await fetch(`${API_BASE_URL}/api/profile`, { headers: { 'Authorization': `Bearer ${authToken}` } })
      if (res.ok) { const data = await res.json(); setProfile(data) }
    } catch (err) { console.error(err) }
    finally { setProfileLoading(false) }
  }

  const updateProfile = async (data) => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/profile`, {
        method: 'PUT',
        headers: { 'Authorization': `Bearer ${authToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      })
      if (res.ok) { await loadProfile(); setEditingProfile(false) }
    } catch (err) { alert('Error updating profile') }
  }

  const viewAnalysis = async (uuid) => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/history/${uuid}`, { headers: { 'Authorization': `Bearer ${authToken}` } })
      if (res.ok) {
        const data = await res.json()
        setResults({ city: data.city, permit_type: data.permit_type, files_analyzed: data.files_analyzed, file_tree: data.file_list, analysis: data.analysis })
        setPage('results')
      }
    } catch (err) { alert('Error loading analysis') }
  }

  const deleteAnalysis = async (uuid) => {
    if (!confirm('Delete this analysis?')) return
    try {
      await fetch(`${API_BASE_URL}/api/history/${uuid}`, { method: 'DELETE', headers: { 'Authorization': `Bearer ${authToken}` } })
      loadHistory()
    } catch (err) { alert('Error deleting') }
  }

  useEffect(() => {
    if (page === 'history' && authToken) loadHistory()
    if (page === 'profile' && authToken) loadProfile()
  }, [page])

  const canAnalyze = city && permitType && validFiles.length > 0 && totalSize <= 200 * 1024 * 1024 && agreedToTerms
  const getPermitTypes = () => {
    const basePermits = [{ value: 'building', label: 'Building' }, { value: 'electrical', label: 'Electrical' }, { value: 'plumbing', label: 'Plumbing' }, { value: 'mechanical', label: 'Mechanical/HVAC' }, { value: 'roofing', label: 'Roofing' }]
    const waterfrontCities = ['Fort Lauderdale', 'Pompano Beach', 'Hollywood', 'Lauderdale-by-the-Sea', 'Boca Raton', 'Deerfield Beach']
    if (waterfrontCities.includes(city)) return [...basePermits, { value: 'dock', label: 'Dock/Marine Structure' }, { value: 'seawall', label: 'Seawall' }, { value: 'boat_lift', label: 'Boat Lift' }]
    return basePermits
  }

  const NavBar = ({ showBack = false }) => (
    <nav className="fixed top-0 left-0 right-0 z-50 bg-black/80 backdrop-blur-xl border-b border-cyan-500/20">
      <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3 cursor-pointer" onClick={() => { setPage('home'); setResults(null) }}>
          <div className="w-11 h-11 bg-gradient-to-br from-cyan-400 to-emerald-400 rounded-xl flex items-center justify-center">
            <svg className="w-6 h-6 text-black" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" /></svg>
          </div>
          <div>
            <h1 className="text-xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent">Flo Permit</h1>
            <p className="text-xs text-cyan-500 font-semibold">SOUTH FLORIDA</p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          {showBack && <button onClick={() => setPage('home')} className="text-gray-400 hover:text-white">← Back</button>}
          {!showBack && currentUser && (<>
            <button onClick={() => setPage('profile')} className="text-sm font-semibold text-gray-400 hover:text-cyan-400">Profile</button>
            <button onClick={() => setPage('history')} className="text-sm font-semibold text-gray-400 hover:text-cyan-400">History</button>
            <button onClick={logout} className="text-sm text-red-400 hover:text-red-300">Logout</button>
          </>)}
          {!showBack && !currentUser && (<>
            <button onClick={() => setShowLogin(true)} className="text-sm font-semibold text-gray-400 hover:text-cyan-400">Log In</button>
            <button onClick={() => setShowRegister(true)} className="relative group">
              <div className="absolute -inset-0.5 bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-xl blur opacity-60 group-hover:opacity-100"></div>
              <div className="relative px-5 py-2.5 bg-black text-white text-sm font-bold rounded-xl">Sign Up</div>
            </button>
          </>)}
        </div>
      </div>
    </nav>
  )

  if (page === 'reset-password') return (
    <div className="min-h-screen bg-black text-white">
      <div className="fixed inset-0 z-0"><div className="absolute inset-0 bg-gradient-to-br from-black via-gray-900 to-black"></div></div>
      <NavBar showBack />
      <div className="relative z-10 pt-24 px-6 pb-12 flex items-center justify-center min-h-screen">
        <div className="relative max-w-md w-full">
          <div className="absolute -inset-1 bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-3xl blur-lg opacity-50"></div>
          <div className="relative bg-gray-900 rounded-2xl p-8 border border-cyan-500/20">
            <h2 className="text-2xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent mb-6">Reset Your Password</h2>
            {successMessage ? (
              <div className="text-center">
                <div className="w-16 h-16 mx-auto mb-4 bg-emerald-500/20 rounded-full flex items-center justify-center"><svg className="w-8 h-8 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg></div>
                <p className="text-emerald-400 mb-4">{successMessage}</p>
                <p className="text-gray-500 text-sm">Redirecting to login...</p>
              </div>
            ) : (
              <form onSubmit={handleResetPassword}>
                <div className="mb-4"><label className="block text-sm text-gray-400 mb-2">New Password</label><input name="newPassword" type="password" required minLength="8" placeholder="Min 8 characters" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none" /></div>
                <div className="mb-4"><label className="block text-sm text-gray-400 mb-2">Confirm Password</label><input name="confirmPassword" type="password" required minLength="8" placeholder="Confirm password" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none" /></div>
                {error && <p className="text-red-400 text-sm mb-4">{error}</p>}
                <button type="submit" disabled={resetPasswordLoading} className="w-full py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl disabled:opacity-50">{resetPasswordLoading ? 'Resetting...' : 'Reset Password'}</button>
              </form>
            )}
          </div>
        </div>
      </div>
    </div>
  )

  if (page === 'terms') return (
    <div className="min-h-screen bg-black text-white">
      <div className="fixed inset-0 z-0"><div className="absolute inset-0 bg-gradient-to-br from-black via-gray-900 to-black"></div></div>
      <NavBar showBack />
      <div className="relative z-10 pt-24 px-6 pb-12">
        <div className="max-w-3xl mx-auto bg-gray-900/80 rounded-3xl p-8 border border-gray-800">
          <h1 className="text-3xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent mb-6">Terms of Service & Disclaimer</h1>
          <div className="space-y-6 text-gray-300">
            <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-xl"><h2 className="text-lg font-bold text-red-400 mb-2">⚠️ IMPORTANT</h2><p>Flo Permit is an <strong className="text-white">informational tool only</strong>. NOT official permit advice.</p></div>
            <p><strong className="text-white">1. NOT OFFICIAL:</strong> We are NOT affiliated with any government office. We do NOT issue permits or guarantee approval.</p>
            <p><strong className="text-white">2. NO LIABILITY:</strong> We are NOT liable for permit denials, delays, fees, or any damages. USE AT YOUR OWN RISK.</p>
            <p><strong className="text-white">3. USER RESPONSIBILITY:</strong> You MUST verify all information with your local permitting office.</p>
            <p><strong className="text-white">4. GOVERNING LAW:</strong> Florida law applies. Disputes resolved in Broward County courts.</p>
            <div className="p-4 bg-cyan-500/10 border border-cyan-500/20 rounded-xl"><p>By using this service, you agree to these terms. <strong className="text-amber-400">If you disagree, do not use this service.</strong></p></div>
          </div>
          <div className="mt-8 text-center"><button onClick={() => setPage('home')} className="px-8 py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl">Back to Home</button></div>
        </div>
      </div>
    </div>
  )

  if (page === 'profile' && currentUser) return (
    <div className="min-h-screen bg-black text-white">
      <div className="fixed inset-0 z-0"><div className="absolute inset-0 bg-gradient-to-br from-black via-gray-900 to-black"></div></div>
      <NavBar />
      <div className="relative z-10 pt-24 px-6 pb-12">
        <div className="max-w-4xl mx-auto">
          <h1 className="text-3xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent mb-8">My Profile</h1>
          {profileLoading ? <div className="text-center py-12"><div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto"></div></div> : profile ? (
            <div className="grid md:grid-cols-3 gap-6">
              <div className="md:col-span-2 bg-gray-900/80 rounded-2xl p-6 border border-gray-800">
                <div className="flex justify-between items-start mb-6"><h2 className="text-xl font-bold text-white">Account Information</h2><button onClick={() => setEditingProfile(!editingProfile)} className="text-cyan-400 hover:text-cyan-300 text-sm">{editingProfile ? 'Cancel' : 'Edit'}</button></div>
                {editingProfile ? (
                  <form onSubmit={(e) => { e.preventDefault(); updateProfile({ full_name: e.target.fullName.value, company_name: e.target.company.value, phone: e.target.phone.value }) }}>
                    <div className="space-y-4">
                      <div><label className="block text-sm text-gray-400 mb-1">Full Name</label><input name="fullName" defaultValue={profile.user.full_name || ''} className="w-full px-4 py-2 bg-black/50 border border-gray-700 rounded-lg text-white focus:border-cyan-500 focus:outline-none" /></div>
                      <div><label className="block text-sm text-gray-400 mb-1">Company</label><input name="company" defaultValue={profile.user.company_name || ''} className="w-full px-4 py-2 bg-black/50 border border-gray-700 rounded-lg text-white focus:border-cyan-500 focus:outline-none" /></div>
                      <div><label className="block text-sm text-gray-400 mb-1">Phone</label><input name="phone" defaultValue={profile.user.phone || ''} className="w-full px-4 py-2 bg-black/50 border border-gray-700 rounded-lg text-white focus:border-cyan-500 focus:outline-none" /></div>
                      <button type="submit" className="px-6 py-2 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-lg">Save Changes</button>
                    </div>
                  </form>
                ) : (
                  <div className="space-y-4">
                    <div className="flex items-center gap-4">
                      <div className="w-16 h-16 bg-gradient-to-br from-cyan-500 to-emerald-500 rounded-full flex items-center justify-center text-2xl font-bold text-black">{(profile.user.full_name || profile.user.email)[0].toUpperCase()}</div>
                      <div><h3 className="text-lg font-bold text-white">{profile.user.full_name || 'No name set'}</h3><p className="text-gray-400">{profile.user.email}</p></div>
                    </div>
                    <div className="grid grid-cols-2 gap-4 pt-4 border-t border-gray-800">
                      <div><span className="text-gray-500 text-sm">Company</span><p className="text-white">{profile.user.company_name || '-'}</p></div>
                      <div><span className="text-gray-500 text-sm">Phone</span><p className="text-white">{profile.user.phone || '-'}</p></div>
                      <div><span className="text-gray-500 text-sm">Member Since</span><p className="text-white">{new Date(profile.user.created_at).toLocaleDateString()}</p></div>
                    </div>
                  </div>
                )}
              </div>
              <div className="bg-gray-900/80 rounded-2xl p-6 border border-gray-800">
                <h2 className="text-xl font-bold text-white mb-4">Subscription</h2>
                <div className={`inline-block px-3 py-1 rounded-full text-sm font-bold mb-4 ${profile.subscription.tier === 'pro' ? 'bg-cyan-500/20 text-cyan-400' : 'bg-gray-700 text-gray-300'}`}>{profile.subscription.tier.toUpperCase()}</div>
                <div className="space-y-3">
                  <div className="flex justify-between"><span className="text-gray-400">This Month</span><span className="text-white font-bold">{profile.subscription.analyses_this_month} analyses</span></div>
                  {profile.subscription.analyses_remaining >= 0 && <div className="flex justify-between"><span className="text-gray-400">Remaining</span><span className="text-cyan-400 font-bold">{profile.subscription.analyses_remaining}</span></div>}
                  <div className="flex justify-between"><span className="text-gray-400">Total</span><span className="text-white">{profile.stats.total_analyses}</span></div>
                </div>
                {profile.subscription.tier === 'free' && <button className="w-full mt-4 py-2 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-lg">Upgrade to Pro</button>}
              </div>
              <div className="md:col-span-3 bg-gray-900/80 rounded-2xl p-6 border border-gray-800">
                <div className="flex justify-between items-center mb-4"><h2 className="text-xl font-bold text-white">Recent Analyses</h2><button onClick={() => setPage('history')} className="text-cyan-400 text-sm">View All →</button></div>
                {profile.recent_analyses?.length === 0 ? <p className="text-gray-500 text-center py-4">No analyses yet</p> : (
                  <div className="space-y-2">{profile.recent_analyses?.map(a => (
                    <div key={a.id} className="flex items-center justify-between p-3 bg-black/30 rounded-lg hover:bg-black/50 cursor-pointer" onClick={() => viewAnalysis(a.analysis_uuid)}>
                      <div><span className="text-white font-medium">{a.city}</span><span className="text-gray-500 mx-2">•</span><span className="text-gray-400">{a.permit_type}</span></div>
                      <div className="flex items-center gap-4"><span className={`font-bold ${a.compliance_score >= 70 ? 'text-emerald-400' : a.compliance_score >= 40 ? 'text-amber-400' : 'text-red-400'}`}>{a.compliance_score}%</span><span className="text-gray-500 text-sm">{new Date(a.created_at).toLocaleDateString()}</span></div>
                    </div>
                  ))}</div>
                )}
              </div>
            </div>
          ) : <p className="text-gray-500">Could not load profile</p>}
        </div>
      </div>
    </div>
  )

  if (page === 'history') return (
    <div className="min-h-screen bg-black text-white">
      <div className="fixed inset-0 z-0"><div className="absolute inset-0 bg-gradient-to-br from-black via-gray-900 to-black"></div></div>
      <NavBar />
      <div className="relative z-10 pt-24 px-6 pb-12">
        <div className="max-w-4xl mx-auto">
          <div className="flex justify-between items-center mb-8"><h1 className="text-3xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent">Analysis History</h1><button onClick={() => setPage('home')} className="px-6 py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl">New Analysis</button></div>
          {historyLoading ? <div className="text-center py-12"><div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto"></div></div> : history.length === 0 ? <div className="text-center py-12 bg-gray-900/50 rounded-2xl border border-gray-800"><p className="text-gray-500">No analyses yet</p></div> : (
            <div className="space-y-3">{history.map(h => (
              <div key={h.analysis_uuid} className="bg-gray-900/50 rounded-xl border border-gray-800 p-4 flex items-center justify-between hover:border-gray-700">
                <div className="flex-1 cursor-pointer" onClick={() => viewAnalysis(h.analysis_uuid)}>
                  <div className="flex items-center gap-3"><span className="font-bold text-white">{h.city}</span><span className="text-gray-500">•</span><span className="text-gray-400">{h.permit_type}</span></div>
                  <div className="text-sm text-gray-500 mt-1">{h.files_analyzed} files • {new Date(h.created_at).toLocaleDateString()}</div>
                </div>
                <div className="flex items-center gap-4">
                  <span className={`text-2xl font-black ${h.compliance_score >= 70 ? 'text-emerald-400' : h.compliance_score >= 40 ? 'text-amber-400' : 'text-red-400'}`}>{h.compliance_score || '-'}%</span>
                  <button onClick={() => deleteAnalysis(h.analysis_uuid)} className="text-gray-500 hover:text-red-400 p-2"><svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg></button>
                </div>
              </div>
            ))}</div>
          )}
        </div>
      </div>
    </div>
  )

  if (page === 'results' && results) return (
    <div className="min-h-screen bg-black text-white">
      <div className="fixed inset-0 z-0"><div className="absolute inset-0 bg-gradient-to-br from-black via-gray-900 to-black"></div></div>
      <NavBar />
      <div className="relative z-10 pt-24 px-6 pb-12">
        <div className="max-w-4xl mx-auto">
          <div className="bg-gray-900/90 rounded-3xl overflow-hidden border border-gray-800">
            <div className="p-8 border-b border-gray-800 bg-gradient-to-r from-cyan-500/10 to-emerald-500/10 flex justify-between items-center">
              <div><h2 className="text-2xl font-black text-white">Analysis Complete</h2><p className="text-gray-400">{results.city} • {results.permit_type}</p></div>
              <div className="text-center"><div className={`text-5xl font-black ${(results.analysis?.compliance_score || 0) >= 70 ? 'text-emerald-400' : (results.analysis?.compliance_score || 0) >= 40 ? 'text-amber-400' : 'text-red-400'}`}>{results.analysis?.compliance_score || 0}%</div><div className="text-sm text-gray-500">Compliance</div></div>
            </div>
            <div className="p-8 space-y-6">
              {results.analysis?.summary && <div><h3 className="font-bold text-white mb-2">Summary</h3><p className="text-gray-400">{results.analysis.summary}</p></div>}
              {results.analysis?.documents_found?.length > 0 && <div><h3 className="font-bold text-emerald-400 mb-2">✓ Documents Found</h3><ul className="space-y-1">{results.analysis.documents_found.map((d,idx) => <li key={idx} className="text-emerald-300">✓ {d}</li>)}</ul></div>}
              {results.analysis?.critical_issues?.length > 0 && <div><h3 className="font-bold text-red-400 mb-2">✗ Critical Issues</h3><ul className="space-y-1">{results.analysis.critical_issues.map((i,idx) => <li key={idx} className="text-red-300">• {i}</li>)}</ul></div>}
              {results.analysis?.missing_documents?.length > 0 && <div><h3 className="font-bold text-amber-400 mb-2">⚠ Missing Documents</h3><ul className="space-y-1">{results.analysis.missing_documents.map((d,idx) => <li key={idx} className="text-amber-300">• {d}</li>)}</ul></div>}
              {results.analysis?.recommendations?.length > 0 && <div><h3 className="font-bold text-cyan-400 mb-2">💡 Recommendations</h3><ul className="space-y-1">{results.analysis.recommendations.map((r,idx) => <li key={idx} className="text-gray-400">• {r}</li>)}</ul></div>}
            </div>
            <div className="px-8 pb-4"><div className="p-3 bg-amber-500/10 border border-amber-500/20 rounded-lg"><p className="text-amber-300 text-xs"><strong>Disclaimer:</strong> Informational only. Verify with your local permitting office.</p></div></div>
            <div className="p-6 bg-black/50 border-t border-gray-800 text-center"><button onClick={() => { setPage('home'); setResults(null); clearFiles() }} className="px-8 py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl">New Analysis</button></div>
          </div>
        </div>
      </div>
    </div>
  )

  return (
    <div className="min-h-screen bg-black text-white overflow-hidden flex flex-col">
      <div className="fixed inset-0 z-0">
        <div className="absolute inset-0 bg-gradient-to-br from-black via-gray-900 to-black"></div>
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-cyan-500/20 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-purple-500/20 rounded-full blur-3xl animate-pulse" style={{animationDelay: '1s'}}></div>
        <div className="absolute inset-0 opacity-20" style={{backgroundImage: 'linear-gradient(rgba(6, 182, 212, 0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(6, 182, 212, 0.1) 1px, transparent 1px)', backgroundSize: '50px 50px'}}></div>
      </div>
      <NavBar />

      {showLogin && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="relative"><div className="absolute -inset-1 bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-3xl blur-lg opacity-50"></div>
            <div className="relative bg-gray-900 rounded-2xl p-8 max-w-md w-full border border-cyan-500/20">
              <div className="flex justify-between items-center mb-6"><h2 className="text-2xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent">Log In</h2><button onClick={() => { setShowLogin(false); setError('') }} className="text-2xl text-gray-500 hover:text-white">&times;</button></div>
              <form onSubmit={handleLogin}>
                <input name="email" type="email" required placeholder="Email" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl mb-4 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none" />
                <input name="password" type="password" required placeholder="Password" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl mb-4 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none" />
                {error && <p className="text-red-400 text-sm mb-4">{error}</p>}
                <button type="submit" className="w-full py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl">Log In</button>
              </form>
              <div className="mt-4 text-center"><button onClick={() => { setShowLogin(false); setShowForgotPassword(true); setError('') }} className="text-cyan-400 hover:text-cyan-300 text-sm">Forgot password?</button></div>
              <p className="text-center mt-4 text-sm text-gray-500">No account? <button onClick={() => { setShowLogin(false); setShowRegister(true); setError('') }} className="text-cyan-400 hover:text-cyan-300">Sign up</button></p>
            </div>
          </div>
        </div>
      )}

      {showForgotPassword && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="relative"><div className="absolute -inset-1 bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-3xl blur-lg opacity-50"></div>
            <div className="relative bg-gray-900 rounded-2xl p-8 max-w-md w-full border border-cyan-500/20">
              <div className="flex justify-between items-center mb-6"><h2 className="text-2xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent">Reset Password</h2><button onClick={() => { setShowForgotPassword(false); setError(''); setSuccessMessage('') }} className="text-2xl text-gray-500 hover:text-white">&times;</button></div>
              {successMessage ? (
                <div className="text-center">
                  <div className="w-16 h-16 mx-auto mb-4 bg-emerald-500/20 rounded-full flex items-center justify-center"><svg className="w-8 h-8 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg></div>
                  <p className="text-emerald-400 mb-4">{successMessage}</p>
                  <button onClick={() => { setShowForgotPassword(false); setSuccessMessage('') }} className="text-cyan-400 hover:text-cyan-300 text-sm">Close</button>
                </div>
              ) : (<>
                <p className="text-gray-400 text-sm mb-6">Enter your email address and we'll send you a link to reset your password.</p>
                <form onSubmit={handleForgotPassword}>
                  <input name="email" type="email" required placeholder="Email" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl mb-4 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none" />
                  {error && <p className="text-red-400 text-sm mb-4">{error}</p>}
                  <button type="submit" className="w-full py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl">Send Reset Link</button>
                </form>
                <p className="text-center mt-4 text-sm text-gray-500"><button onClick={() => { setShowForgotPassword(false); setShowLogin(true); setError('') }} className="text-cyan-400 hover:text-cyan-300">← Back to login</button></p>
              </>)}
            </div>
          </div>
        </div>
      )}

      {showRegister && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="relative"><div className="absolute -inset-1 bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-3xl blur-lg opacity-50"></div>
            <div className="relative bg-gray-900 rounded-2xl p-8 max-w-md w-full border border-cyan-500/20">
              <div className="flex justify-between items-center mb-6"><h2 className="text-2xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent">Create Account</h2><button onClick={() => { setShowRegister(false); setError('') }} className="text-2xl text-gray-500 hover:text-white">&times;</button></div>
              <form onSubmit={handleRegister}>
                <input name="fullName" type="text" placeholder="Full Name" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl mb-4 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none" />
                <input name="company" type="text" placeholder="Company (optional)" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl mb-4 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none" />
                <input name="email" type="email" required placeholder="Email" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl mb-4 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none" />
                <input name="password" type="password" required minLength="8" placeholder="Password (min 8)" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl mb-4 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none" />
                {error && <p className="text-red-400 text-sm mb-4">{error}</p>}
                <button type="submit" className="w-full py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl">Create Account</button>
              </form>
              <p className="text-center mt-4 text-sm text-gray-500">Have an account? <button onClick={() => { setShowRegister(false); setShowLogin(true); setError('') }} className="text-cyan-400 hover:text-cyan-300">Log in</button></p>
            </div>
          </div>
        </div>
      )}

      {loading && (
        <div className="fixed inset-0 z-50 bg-black/95 flex items-center justify-center">
          <div className="text-center">
            <div className="relative w-24 h-24 mx-auto mb-6"><div className="absolute inset-0 border-4 border-cyan-500/20 rounded-full"></div><div className="absolute inset-0 border-4 border-transparent border-t-cyan-500 rounded-full animate-spin"></div></div>
            <h3 className="text-2xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent mb-2">{loadingStatus}</h3>
            <div className="w-64 h-2 bg-gray-800 rounded-full mx-auto mt-4"><div className="h-full bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-full" style={{width:`${progress}%`}}></div></div>
          </div>
        </div>
      )}

      <div className="relative z-10 pt-24 px-6 pb-12 flex-grow">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <span className="px-4 py-1.5 bg-cyan-500/10 border border-cyan-500/20 rounded-full text-cyan-400 text-sm font-semibold">AI-POWERED PERMIT ANALYSIS</span>
            <h1 className="text-5xl md:text-7xl font-black mt-4 mb-6"><span className="bg-gradient-to-r from-white via-gray-200 to-gray-400 bg-clip-text text-transparent">South Florida</span><br/><span className="bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent">Permit Checker</span></h1>
            <p className="text-xl text-gray-400">Upload your permit package and get instant AI-powered analysis</p>
          </div>
          <div className="relative">
            <div className="absolute -inset-1 bg-gradient-to-r from-cyan-500/50 via-emerald-500/50 to-purple-500/50 rounded-3xl blur-xl opacity-30"></div>
            <div className="relative bg-gray-900/80 backdrop-blur-xl rounded-3xl p-8 border border-gray-800">
              <div className="grid md:grid-cols-2 gap-4 mb-6">
                <div><label className="block text-sm font-semibold text-gray-400 mb-2">CITY</label><select value={city} onChange={e => { setCity(e.target.value); setPermitType('') }} className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl text-white focus:border-cyan-500 focus:outline-none"><option value="">Select city...</option><option>Fort Lauderdale</option><option>Pompano Beach</option><option>Hollywood</option><option>Coral Springs</option><option>Boca Raton</option><option>Lauderdale-by-the-Sea</option><option>Deerfield Beach</option><option>Pembroke Pines</option></select></div>
                <div><label className="block text-sm font-semibold text-gray-400 mb-2">PERMIT TYPE</label><select value={permitType} onChange={e => setPermitType(e.target.value)} disabled={!city} className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl text-white focus:border-cyan-500 focus:outline-none disabled:opacity-50"><option value="">Select type...</option>{getPermitTypes().map(pt => <option key={pt.value} value={pt.value}>{pt.label}</option>)}</select></div>
              </div>
              <div className="mb-6">
                <label className="block text-sm font-semibold text-gray-400 mb-2">UPLOAD FILES</label>
                <div className={`border-2 border-dashed rounded-2xl p-8 text-center ${isDragging ? 'border-cyan-400 bg-cyan-500/10' : 'border-gray-700 bg-black/30'}`} onDragOver={e => { e.preventDefault(); setIsDragging(true) }} onDragLeave={() => setIsDragging(false)} onDrop={e => { e.preventDefault(); setIsDragging(false); handleFiles({ target: { files: e.dataTransfer.files } }) }}>
                  <input type="file" multiple webkitdirectory="" directory="" onChange={handleFiles} className="hidden" id="fileInput" />
                  <label htmlFor="fileInput" className="cursor-pointer">
                    <div className="w-16 h-16 mx-auto mb-4 bg-gradient-to-br from-cyan-500/20 to-emerald-500/20 rounded-2xl flex items-center justify-center border border-cyan-500/30"><svg className="w-8 h-8 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/></svg></div>
                    <p className="font-bold text-white mb-1">Drop your permit folder here</p>
                    <p className="text-sm text-gray-500">PDF, PNG, JPG • Max 50 files</p>
                  </label>
                </div>
                {validFiles.length > 0 && <div className="mt-4 p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-xl"><div className="flex justify-between"><span className="text-emerald-400 font-semibold">{validFiles.length} files ({formatSize(totalSize)})</span><button onClick={clearFiles} className="text-red-400 text-sm">Clear</button></div></div>}
              </div>
              <div className="mb-6"><label className="flex items-start gap-3 cursor-pointer"><input type="checkbox" checked={agreedToTerms} onChange={e => setAgreedToTerms(e.target.checked)} className="mt-1 w-5 h-5 rounded border-gray-600 bg-black/50 text-cyan-500" /><span className="text-sm text-gray-400">I agree to the <button type="button" onClick={() => setPage('terms')} className="text-cyan-400 underline">Terms of Service</button></span></label></div>
              <button onClick={analyze} disabled={!canAnalyze} className={`w-full py-4 rounded-xl font-bold text-lg ${canAnalyze ? 'bg-gradient-to-r from-cyan-500 to-emerald-500 text-black' : 'bg-gray-800 text-gray-500 cursor-not-allowed'}`}>{canAnalyze ? `Analyze ${validFiles.length} Files` : 'Select city, permit type & files'}</button>
            </div>
          </div>
          <div className="grid md:grid-cols-3 gap-6 mt-12">
            {[{icon:'⚡',title:'Instant Analysis',desc:'Results in seconds'},{icon:'🎯',title:'Compliance Score',desc:'Know where you stand'},{icon:'📋',title:'Missing Items',desc:'Never miss requirements'}].map((f,i) => (
              <div key={i} className="text-center p-6 bg-gray-900/50 rounded-2xl border border-gray-800"><div className="text-3xl mb-3">{f.icon}</div><h3 className="font-bold text-white mb-1">{f.title}</h3><p className="text-sm text-gray-500">{f.desc}</p></div>
            ))}
          </div>
        </div>
      </div>
      <footer className="relative z-10 border-t border-gray-800 bg-black/50 mt-auto">
        <div className="max-w-7xl mx-auto px-6 py-6 flex flex-col md:flex-row items-center justify-between gap-4">
          <p className="text-gray-500 text-sm">© 2025 Flo Permit</p>
          <div className="flex items-center gap-6"><button onClick={() => setPage('terms')} className="text-gray-500 hover:text-cyan-400 text-sm">Terms</button><span className="text-gray-700">|</span><span className="text-gray-500 text-sm">South Florida</span></div>
        </div>
      </footer>
      <style>{`select option{background:#111;color:white;}`}</style>
    </div>
  )
}