import { useState, useEffect } from 'react'
import * as Sentry from '@sentry/react'

const SENTRY_DSN = import.meta.env.VITE_SENTRY_DSN
if (SENTRY_DSN) {
  Sentry.init({
    dsn: SENTRY_DSN,
    integrations: [Sentry.browserTracingIntegration()],
    tracesSampleRate: 0.1,
    environment: import.meta.env.MODE,
  })
}

const API_BASE_URL = 'https://permit-pro-ai-production.up.railway.app'

export default function App() {
  const [currentUser, setCurrentUser] = useState(null)
  const [authToken, setAuthToken] = useState(null)
  const [showLogin, setShowLogin] = useState(false)
  const [showRegister, setShowRegister] = useState(false)
  const [showForgotPassword, setShowForgotPassword] = useState(false)
  const [page, setPage] = useState('home')
  const [county, setCounty] = useState('')
  const [city, setCity] = useState('')
  const [permitType, setPermitType] = useState('')
  const [files, setFiles] = useState([])
  const [validFiles, setValidFiles] = useState([])
  const [loading, setLoading] = useState(false)
  const [loadingStatus, setLoadingStatus] = useState('')
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
  const [adminStats, setAdminStats] = useState(null)
  const [adminLoading, setAdminLoading] = useState(false)
  const [subscription, setSubscription] = useState(null)
  const [checkoutLoading, setCheckoutLoading] = useState(false)
  const [singlePurchase, setSinglePurchase] = useState(null)
  const [singlePurchaseEmail, setSinglePurchaseEmail] = useState('')
  const [showSinglePurchase, setShowSinglePurchase] = useState(false)

  const ADMIN_EMAILS = ['toshygluestick@gmail.com']
  const isAdmin = currentUser && ADMIN_EMAILS.includes(currentUser.email)
  const [resetPasswordLoading, setResetPasswordLoading] = useState(false)
  const [contactLoading, setContactLoading] = useState(false)

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const token = params.get('token')
    const payment = params.get('payment')
    const purchase = params.get('purchase')
    const purchaseId = params.get('purchase_id')
    
    if (token) { setResetToken(token); setPage('reset-password'); window.history.replaceState({}, document.title, window.location.pathname) }
    if (payment === 'success') { setSuccessMessage('Payment successful! Your subscription is now active.'); setPage('profile'); window.history.replaceState({}, document.title, window.location.pathname) }
    if (payment === 'cancelled') { window.history.replaceState({}, document.title, window.location.pathname) }
    
    // Handle single purchase success
    if (purchase === 'success' && purchaseId) {
      setSuccessMessage('Payment successful! You can now analyze your permit.')
      loadSinglePurchase(purchaseId)
      setPage('single-analysis')
      window.history.replaceState({}, document.title, window.location.pathname)
    }
    if (purchase === 'cancelled') { window.history.replaceState({}, document.title, window.location.pathname) }
    
    // Check for pending purchase in localStorage
    const pendingPurchase = localStorage.getItem('pending_purchase')
    if (pendingPurchase && !purchaseId) {
      loadSinglePurchase(pendingPurchase)
    }
  }, [])

  useEffect(() => {
    const token = localStorage.getItem('authToken')
    const user = localStorage.getItem('currentUser')
    if (token && user) { setAuthToken(token); setCurrentUser(JSON.parse(user)) }
  }, [])

  const handleLogin = async (e) => {
    e.preventDefault(); setError('')
    try {
      const res = await fetch(`${API_BASE_URL}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: e.target.email.value, password: e.target.password.value }) })
      if (!res.ok) { const data = await res.json(); throw new Error(data.detail || 'Login failed') }
      const data = await res.json()
      setAuthToken(data.access_token); setCurrentUser(data.user)
      localStorage.setItem('authToken', data.access_token); localStorage.setItem('currentUser', JSON.stringify(data.user))
      setShowLogin(false)
    } catch (err) { setError(err.message) }
  }

  const handleRegister = async (e) => {
    e.preventDefault(); setError('')
    try {
      const res = await fetch(`${API_BASE_URL}/api/auth/register`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: e.target.email.value, password: e.target.password.value, full_name: e.target.fullName.value || null, company_name: e.target.company.value || null }) })
      if (!res.ok) { const data = await res.json(); throw new Error(data.detail || 'Registration failed') }
      const data = await res.json()
      setAuthToken(data.access_token); setCurrentUser(data.user)
      localStorage.setItem('authToken', data.access_token); localStorage.setItem('currentUser', JSON.stringify(data.user))
      setShowRegister(false)
    } catch (err) { setError(err.message) }
  }

  const handleForgotPassword = async (e) => {
    e.preventDefault(); setError(''); setSuccessMessage('')
    try {
      const res = await fetch(`${API_BASE_URL}/api/auth/forgot-password`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: e.target.email.value }) })
      const data = await res.json()
      setSuccessMessage(data.message || 'If an account exists, you will receive a reset link.'); e.target.reset()
    } catch (err) { setSuccessMessage('If an account exists with this email, you will receive a password reset link.') }
  }

  const handleResetPassword = async (e) => {
    e.preventDefault(); setError(''); setResetPasswordLoading(true)
    const newPassword = e.target.newPassword.value, confirmPassword = e.target.confirmPassword.value
    if (newPassword !== confirmPassword) { setError('Passwords do not match'); setResetPasswordLoading(false); return }
    if (newPassword.length < 8) { setError('Password must be at least 8 characters'); setResetPasswordLoading(false); return }
    try {
      const res = await fetch(`${API_BASE_URL}/api/auth/reset-password`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: resetToken, new_password: newPassword }) })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Password reset failed')
      setSuccessMessage(data.message); setResetToken(null)
      setTimeout(() => { setPage('home'); setShowLogin(true); setSuccessMessage('') }, 3000)
    } catch (err) { setError(err.message) } finally { setResetPasswordLoading(false) }
  }

  const handleContact = async (e) => {
    e.preventDefault(); setError(''); setSuccessMessage(''); setContactLoading(true)
    try {
      const res = await fetch(`${API_BASE_URL}/api/contact`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: e.target.name.value, email: e.target.email.value, subject: e.target.subject.value, message: e.target.message.value }) })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Failed to send message')
      setSuccessMessage(data.message); e.target.reset()
    } catch (err) { setError(err.message) } finally { setContactLoading(false) }
  }

  const logout = () => { setAuthToken(null); setCurrentUser(null); setProfile(null); localStorage.removeItem('authToken'); localStorage.removeItem('currentUser'); setPage('home') }

  const handleFiles = (e) => {
    const newFiles = Array.from(e.target.files)
    // Filter valid files from new uploads
    const newValid = newFiles.filter(f => { 
      const ext = f.name.split('.').pop().toLowerCase()
      return ['pdf', 'png', 'jpg', 'jpeg'].includes(ext) && f.size <= 25 * 1024 * 1024 
    })
    // Combine with existing files, avoiding duplicates by name
    const existingNames = new Set(validFiles.map(f => f.name))
    const uniqueNew = newValid.filter(f => !existingNames.has(f.name))
    const combined = [...validFiles, ...uniqueNew].slice(0, 50) // Max 50 files
    setFiles(combined)
    setValidFiles(combined)
    // Reset file input so same file can be added again if cleared
    e.target.value = ''
  }

  const clearFiles = () => { setFiles([]); setValidFiles([]) }
  const formatSize = (bytes) => { if (bytes < 1024) return bytes + ' B'; if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'; return (bytes / (1024 * 1024)).toFixed(1) + ' MB' }
  const totalSize = validFiles.reduce((sum, f) => sum + f.size, 0)

  const analyze = async () => {
    if (!city || !permitType || validFiles.length === 0 || !agreedToTerms) return
    setLoading(true); setLoadingStatus('Uploading files...')
    try {
      const formData = new FormData(); formData.append('city', city); formData.append('permit_type', permitType)
      validFiles.forEach((f) => formData.append('files', f))
      setLoadingStatus('Analyzing with AI...')
      const headers = {}; if (authToken) headers['Authorization'] = `Bearer ${authToken}`
      const res = await fetch(`${API_BASE_URL}/api/analyze-permit-folder`, { method: 'POST', headers, body: formData })
      if (!res.ok) { const err = await res.json().catch(() => ({})); throw new Error(err.detail || 'Analysis failed') }
      const data = await res.json(); setResults(data); setPage('results')
    } catch (err) { alert('Error: ' + err.message) } finally { setLoading(false) }
  }

  const loadHistory = async () => { setHistoryLoading(true); try { const res = await fetch(`${API_BASE_URL}/api/history`, { headers: { 'Authorization': `Bearer ${authToken}` } }); if (res.ok) { const data = await res.json(); setHistory(data.analyses || []) } } catch (err) { console.error(err) } finally { setHistoryLoading(false) } }
  const loadAdminStats = async () => { if (!authToken) return; setAdminLoading(true); try { const res = await fetch(`${API_BASE_URL}/api/admin/stats`, { headers: { 'Authorization': `Bearer ${authToken}` } }); if (res.ok) { const data = await res.json(); setAdminStats(data) } } catch (err) { console.error(err) } finally { setAdminLoading(false) } }
  const loadProfile = async () => { if (!authToken) return; setProfileLoading(true); try { const res = await fetch(`${API_BASE_URL}/api/profile`, { headers: { 'Authorization': `Bearer ${authToken}` } }); if (res.ok) { const data = await res.json(); setProfile(data) } } catch (err) { console.error(err) } finally { setProfileLoading(false) } }
  const loadSubscription = async () => { if (!authToken) return; try { const res = await fetch(`${API_BASE_URL}/api/subscription`, { headers: { 'Authorization': `Bearer ${authToken}` } }); if (res.ok) { const data = await res.json(); setSubscription(data) } } catch (err) { console.error(err) } }
  const updateProfile = async (data) => { try { const res = await fetch(`${API_BASE_URL}/api/profile`, { method: 'PUT', headers: { 'Authorization': `Bearer ${authToken}`, 'Content-Type': 'application/json' }, body: JSON.stringify(data) }); if (res.ok) { await loadProfile(); setEditingProfile(false) } } catch (err) { alert('Error updating profile') } }
  const viewAnalysis = async (uuid) => { try { const res = await fetch(`${API_BASE_URL}/api/history/${uuid}`, { headers: { 'Authorization': `Bearer ${authToken}` } }); if (res.ok) { const data = await res.json(); setResults({ city: data.city, permit_type: data.permit_type, files_analyzed: data.files_analyzed, file_tree: data.file_list, analysis: data.analysis }); setPage('results') } } catch (err) { alert('Error loading analysis') } }
  const deleteAnalysis = async (uuid) => { if (!confirm('Delete this analysis?')) return; try { await fetch(`${API_BASE_URL}/api/history/${uuid}`, { method: 'DELETE', headers: { 'Authorization': `Bearer ${authToken}` } }); loadHistory() } catch (err) { alert('Error deleting') } }
  
  const handleCheckout = async (tier) => {
    setCheckoutLoading(true)
    try {
      const formData = new FormData()
      formData.append('tier', tier)
      const res = await fetch(`${API_BASE_URL}/api/stripe/create-checkout-session`, { method: 'POST', headers: { 'Authorization': `Bearer ${authToken}` }, body: formData })
      if (res.ok) { const data = await res.json(); window.location.href = data.checkout_url }
      else { const data = await res.json(); alert(data.detail || 'Checkout failed') }
    } catch (err) { alert('Checkout error') }
    finally { setCheckoutLoading(false) }
  }
  
  const openBillingPortal = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/stripe/create-portal-session`, { method: 'POST', headers: { 'Authorization': `Bearer ${authToken}` } })
      if (res.ok) { const data = await res.json(); window.location.href = data.portal_url }
      else { alert('Could not open billing portal') }
    } catch (err) { alert('Error opening billing portal') }
  }

  const handleSinglePurchaseCheckout = async () => {
    if (!singlePurchaseEmail || !city || !permitType) {
      alert('Please enter your email and select city and permit type')
      return
    }
    setCheckoutLoading(true)
    try {
      const formData = new FormData()
      formData.append('email', singlePurchaseEmail)
      formData.append('city', city)
      formData.append('permit_type', permitType)
      const res = await fetch(`${API_BASE_URL}/api/stripe/create-single-checkout`, { method: 'POST', body: formData })
      if (res.ok) { 
        const data = await res.json()
        localStorage.setItem('pending_purchase', data.purchase_id)
        window.location.href = data.checkout_url 
      }
      else { const data = await res.json(); alert(data.detail || 'Checkout failed') }
    } catch (err) { alert('Checkout error') }
    finally { setCheckoutLoading(false) }
  }

  const loadSinglePurchase = async (purchaseId) => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/single-purchase/${purchaseId}`)
      if (res.ok) {
        const data = await res.json()
        setSinglePurchase(data)
        setCity(data.city)
        setPermitType(data.permit_type)
        // Set county based on city
        if (['Fort Lauderdale', 'Pompano Beach', 'Hollywood', 'Coral Springs', 'Coconut Creek', 'Davie', 'Deerfield Beach', 'Lauderdale-by-the-Sea', 'Lighthouse Point', 'Margate', 'Miramar', 'Pembroke Pines', 'Plantation', 'Sunrise', 'Tamarac', 'Weston'].includes(data.city)) {
          setCounty('Broward')
        } else if (['Boca Raton', 'Boynton Beach', 'Delray Beach', 'Lake Worth Beach', 'West Palm Beach'].includes(data.city)) {
          setCounty('Palm Beach')
        } else {
          setCounty('Miami-Dade')
        }
      }
    } catch (err) { console.error('Error loading purchase:', err) }
  }

  useEffect(() => { if (page === 'history' && authToken) loadHistory(); if (page === 'profile' && authToken) { loadProfile(); loadSubscription() }; if (page === 'admin' && authToken && isAdmin) loadAdminStats(); if (page === 'pricing' && authToken) loadSubscription() }, [page])

  const canAnalyze = city && permitType && validFiles.length > 0 && totalSize <= 200 * 1024 * 1024 && agreedToTerms
  const getPermitTypes = () => {
    return [
      { value: 'auto', label: 'Auto-Detect (Recommended)' },
      { value: '', label: '────────────────', disabled: true },
      { value: 'structural', label: 'Structural / Building' },
      { value: 'electrical', label: 'Electrical' },
      { value: 'mechanical', label: 'Mechanical / HVAC' },
      { value: 'plumbing', label: 'Plumbing' },
      { value: '', label: '────────────────', disabled: true },
      { value: 'marine', label: 'Marine (Dock, Seawall, Boat Lift)' },
    ]
  }


  const NavBar = ({ showBack = false }) => (
    <nav className="fixed top-0 left-0 right-0 z-50 bg-black/80 backdrop-blur-xl border-b border-cyan-500/20">
      <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3 cursor-pointer" onClick={() => { setPage('home'); setResults(null) }}>
          <div className="w-11 h-11 bg-gradient-to-br from-cyan-400 to-emerald-400 rounded-xl flex items-center justify-center p-1.5">
            <img src="/permit_logo.jpg" alt="Flo Permit" className="w-full h-full object-contain" />
          </div>
          <div><h1 className="text-xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent">Flo Permit</h1><p className="text-xs text-cyan-500 font-semibold">SOUTH FLORIDA</p></div>
        </div>
        <div className="flex items-center gap-4">
          {showBack && <button onClick={() => setPage('home')} className="text-gray-400 hover:text-white">← Back</button>}
          {!showBack && currentUser && (<>{isAdmin && <button onClick={() => setPage('admin')} className="text-sm font-semibold text-purple-400 hover:text-purple-300">Admin</button>}<button onClick={() => setPage('profile')} className="text-sm font-semibold text-gray-400 hover:text-cyan-400">Profile</button><button onClick={() => setPage('history')} className="text-sm font-semibold text-gray-400 hover:text-cyan-400">History</button><button onClick={logout} className="text-sm text-red-400 hover:text-red-300">Logout</button></>)}
          {!showBack && !currentUser && (<><button onClick={() => setShowLogin(true)} className="text-sm font-semibold text-gray-400 hover:text-cyan-400">Log In</button><button onClick={() => setShowRegister(true)} className="relative group"><div className="absolute -inset-0.5 bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-xl blur opacity-60 group-hover:opacity-100"></div><div className="relative px-5 py-2.5 bg-black text-white text-sm font-bold rounded-xl">Sign Up</div></button></>)}
        </div>
      </div>
    </nav>
  )

  const Footer = () => (
    <footer className="relative z-10 border-t border-gray-800 bg-black/50 mt-auto">
      <div className="max-w-7xl mx-auto px-6 py-8">
        <div className="grid md:grid-cols-4 gap-8 mb-8">
          <div><div className="flex items-center gap-2 mb-4"><div className="w-8 h-8 bg-gradient-to-br from-cyan-400 to-emerald-400 rounded-lg flex items-center justify-center p-1"><img src="/permit_logo.jpg" alt="Flo Permit" className="w-full h-full object-contain" /></div><span className="font-bold text-white">Flo Permit</span></div><p className="text-gray-500 text-sm">AI-powered permit analysis for South Florida contractors and homeowners.</p></div>
          <div><h4 className="font-semibold text-white mb-4">Product</h4><ul className="space-y-2"><li><button onClick={() => setPage('home')} className="text-gray-500 hover:text-cyan-400 text-sm">Analyze Permits</button></li><li><button onClick={() => setPage('pricing')} className="text-gray-500 hover:text-cyan-400 text-sm">Pricing</button></li><li><button onClick={() => setPage('about')} className="text-gray-500 hover:text-cyan-400 text-sm">About Us</button></li><li><button onClick={() => setPage('faq')} className="text-gray-500 hover:text-cyan-400 text-sm">FAQ</button></li></ul></div>
          <div><h4 className="font-semibold text-white mb-4">Legal</h4><ul className="space-y-2"><li><button onClick={() => setPage('terms')} className="text-gray-500 hover:text-cyan-400 text-sm">Terms of Service</button></li><li><button onClick={() => setPage('privacy')} className="text-gray-500 hover:text-cyan-400 text-sm">Privacy Policy</button></li></ul></div>
          <div><h4 className="font-semibold text-white mb-4">Support</h4><ul className="space-y-2"><li><button onClick={() => setPage('contact')} className="text-gray-500 hover:text-cyan-400 text-sm">Contact Us</button></li><li><button onClick={() => setPage('faq')} className="text-gray-500 hover:text-cyan-400 text-sm">FAQ</button></li><li><a href="mailto:support@flopermit.com" className="text-gray-500 hover:text-cyan-400 text-sm">support@flopermit.com</a></li></ul></div>
        </div>
        <div className="border-t border-gray-800 pt-6 flex flex-col md:flex-row items-center justify-between gap-4"><p className="text-gray-500 text-sm">© 2025 Flo Permit. All rights reserved.</p><p className="text-gray-600 text-xs">Serving Broward & Palm Beach Counties</p></div>
      </div>
    </footer>
  )

  if (page === 'contact') return (
    <div className="min-h-screen bg-black text-white flex flex-col">
      <div className="fixed inset-0 z-0"><div className="absolute inset-0 bg-gradient-to-br from-black via-gray-900 to-black"></div></div>
      <NavBar showBack />
      <div className="relative z-10 pt-24 px-6 pb-12 flex-grow">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12"><h1 className="text-4xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent mb-4">Contact Us</h1><p className="text-gray-400">Have a question? We'd love to hear from you.</p></div>
          <div className="grid md:grid-cols-2 gap-8">
            <div className="bg-gray-900/80 rounded-2xl p-8 border border-gray-800">
              <h2 className="text-xl font-bold text-white mb-6">Send us a message</h2>
              {successMessage ? (<div className="text-center py-8"><div className="w-16 h-16 mx-auto mb-4 bg-emerald-500/20 rounded-full flex items-center justify-center"><svg className="w-8 h-8 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg></div><p className="text-emerald-400 mb-4">{successMessage}</p><button onClick={() => setSuccessMessage('')} className="text-cyan-400 hover:text-cyan-300 text-sm">Send another message</button></div>) : (
                <form onSubmit={handleContact} className="space-y-4">
                  <div><label className="block text-sm text-gray-400 mb-1">Name</label><input name="name" required className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl text-white focus:border-cyan-500 focus:outline-none" /></div>
                  <div><label className="block text-sm text-gray-400 mb-1">Email</label><input name="email" type="email" required className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl text-white focus:border-cyan-500 focus:outline-none" /></div>
                  <div><label className="block text-sm text-gray-400 mb-1">Subject</label><input name="subject" required className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl text-white focus:border-cyan-500 focus:outline-none" /></div>
                  <div><label className="block text-sm text-gray-400 mb-1">Message</label><textarea name="message" required rows="4" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl text-white focus:border-cyan-500 focus:outline-none resize-none"></textarea></div>
                  {error && <p className="text-red-400 text-sm">{error}</p>}
                  <button type="submit" disabled={contactLoading} className="w-full py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl disabled:opacity-50">{contactLoading ? 'Sending...' : 'Send Message'}</button>
                </form>
              )}
            </div>
            <div className="space-y-6">
              <div className="bg-gray-900/80 rounded-2xl p-6 border border-gray-800"><div className="flex items-center gap-4"><div className="w-12 h-12 bg-cyan-500/20 rounded-xl flex items-center justify-center"><svg className="w-6 h-6 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg></div><div><h3 className="font-bold text-white">Email</h3><a href="mailto:support@flopermit.com" className="text-cyan-400">support@flopermit.com</a></div></div></div>
              <div className="bg-gray-900/80 rounded-2xl p-6 border border-gray-800"><div className="flex items-center gap-4"><div className="w-12 h-12 bg-emerald-500/20 rounded-xl flex items-center justify-center"><svg className="w-6 h-6 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg></div><div><h3 className="font-bold text-white">Response Time</h3><p className="text-gray-400">Within 24 hours</p></div></div></div>
              <div className="bg-gray-900/80 rounded-2xl p-6 border border-gray-800"><div className="flex items-center gap-4"><div className="w-12 h-12 bg-purple-500/20 rounded-xl flex items-center justify-center"><svg className="w-6 h-6 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 11a3 3 0 11-6 0 3 3 0 016 0z" /></svg></div><div><h3 className="font-bold text-white">Service Area</h3><p className="text-gray-400">Broward & Palm Beach Counties</p></div></div></div>
            </div>
          </div>
        </div>
      </div>
      <Footer />
    </div>
  )

  if (page === 'privacy') return (
    <div className="min-h-screen bg-black text-white flex flex-col">
      <div className="fixed inset-0 z-0"><div className="absolute inset-0 bg-gradient-to-br from-black via-gray-900 to-black"></div></div>
      <NavBar showBack />
      <div className="relative z-10 pt-24 px-6 pb-12 flex-grow">
        <div className="max-w-3xl mx-auto bg-gray-900/80 rounded-3xl p-8 border border-gray-800">
          <h1 className="text-3xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent mb-6">Privacy Policy</h1>
          <p className="text-gray-500 text-sm mb-6">Last updated: January 2025</p>
          <div className="space-y-6 text-gray-300">
            <div><h2 className="text-lg font-bold text-white mb-2">1. Information We Collect</h2><p>We collect information you provide directly: name, email, company name, and uploaded permit documents. We also collect usage data like pages visited and features used.</p></div>
            <div><h2 className="text-lg font-bold text-white mb-2">2. How We Use Your Information</h2><p>We use your information to: provide permit analysis services, send account-related emails, improve our services, and respond to support requests.</p></div>
            <div><h2 className="text-lg font-bold text-white mb-2">3. Document Storage</h2><p>Uploaded documents are processed for analysis and stored securely. Documents are automatically deleted after 30 days unless you choose to save them to your account history.</p></div>
            <div><h2 className="text-lg font-bold text-white mb-2">4. Data Sharing</h2><p>We do not sell your personal information. We may share data with: service providers who assist our operations (hosting, email), and when required by law.</p></div>
            <div><h2 className="text-lg font-bold text-white mb-2">5. Data Security</h2><p>We implement industry-standard security measures including encryption in transit and at rest, secure password hashing, and regular security audits.</p></div>
            <div><h2 className="text-lg font-bold text-white mb-2">6. Your Rights</h2><p>You can: access your data, request deletion of your account, opt out of marketing emails, and export your analysis history.</p></div>
            <div><h2 className="text-lg font-bold text-white mb-2">7. Contact</h2><p>For privacy questions, contact us at <a href="mailto:support@flopermit.com" className="text-cyan-400">support@flopermit.com</a></p></div>
          </div>
          <div className="mt-8 text-center"><button onClick={() => setPage('home')} className="px-8 py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl">Back to Home</button></div>
        </div>
      </div>
      <Footer />
    </div>
  )

  // === ABOUT PAGE ===
  if (page === 'about') return (
    <div className="min-h-screen bg-black text-white flex flex-col">
      <div className="fixed inset-0 z-0"><div className="absolute inset-0 bg-gradient-to-br from-black via-gray-900 to-black"></div></div>
      <NavBar showBack />
      <div className="relative z-10 pt-24 px-6 pb-12 flex-grow">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <h1 className="text-4xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent mb-4">About Flo Permit</h1>
            <p className="text-gray-400 text-lg">Simplifying the permit process for South Florida</p>
          </div>
          <div className="grid md:grid-cols-2 gap-8 mb-12">
            <div className="bg-gray-900/80 rounded-2xl p-8 border border-gray-800">
              <div className="w-14 h-14 bg-cyan-500/20 rounded-xl flex items-center justify-center mb-4"><span className="text-3xl">🎯</span></div>
              <h2 className="text-xl font-bold text-white mb-3">Our Mission</h2>
              <p className="text-gray-400">We're on a mission to make permit applications less stressful. No more guessing if your package is complete — get instant AI-powered feedback before you submit.</p>
            </div>
            <div className="bg-gray-900/80 rounded-2xl p-8 border border-gray-800">
              <div className="w-14 h-14 bg-emerald-500/20 rounded-xl flex items-center justify-center mb-4"><span className="text-3xl">⚡</span></div>
              <h2 className="text-xl font-bold text-white mb-3">How It Works</h2>
              <p className="text-gray-400">Upload your permit documents, select your city and permit type, and our AI analyzes everything in seconds. You'll know exactly what's missing and what needs attention.</p>
            </div>
            <div className="bg-gray-900/80 rounded-2xl p-8 border border-gray-800">
              <div className="w-14 h-14 bg-purple-500/20 rounded-xl flex items-center justify-center mb-4"><span className="text-3xl">🏗️</span></div>
              <h2 className="text-xl font-bold text-white mb-3">Built for Professionals</h2>
              <p className="text-gray-400">Whether you're a contractor, architect, engineer, or homeowner, Flo Permit helps you submit complete permit packages the first time.</p>
            </div>
            <div className="bg-gray-900/80 rounded-2xl p-8 border border-gray-800">
              <div className="w-14 h-14 bg-amber-500/20 rounded-xl flex items-center justify-center mb-4"><span className="text-3xl">📍</span></div>
              <h2 className="text-xl font-bold text-white mb-3">South Florida Focus</h2>
              <p className="text-gray-400">We specialize in Broward, Palm Beach, and Miami-Dade counties. Local knowledge, local requirements, local expertise.</p>
            </div>
          </div>
          <div className="bg-gray-900/80 rounded-2xl p-8 border border-gray-800 text-center">
            <h2 className="text-2xl font-bold text-white mb-4">Ready to streamline your permits?</h2>
            <p className="text-gray-400 mb-6">Join hundreds of South Florida professionals who trust Flo Permit.</p>
            <button onClick={() => setPage('home')} className="px-8 py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl">Get Started Free</button>
          </div>
        </div>
      </div>
      <Footer />
    </div>
  )

  // === FAQ PAGE ===
  if (page === 'faq') return (
    <div className="min-h-screen bg-black text-white flex flex-col">
      <div className="fixed inset-0 z-0"><div className="absolute inset-0 bg-gradient-to-br from-black via-gray-900 to-black"></div></div>
      <NavBar showBack />
      <div className="relative z-10 pt-24 px-6 pb-12 flex-grow">
        <div className="max-w-3xl mx-auto">
          <div className="text-center mb-12">
            <h1 className="text-4xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent mb-4">Frequently Asked Questions</h1>
            <p className="text-gray-400">Everything you need to know about Flo Permit</p>
          </div>
          <div className="space-y-4">
            {[
              { q: "What is Flo Permit?", a: "Flo Permit is an AI-powered tool that analyzes your permit documents and tells you if your package is complete. Upload your files, and we'll identify missing documents, issues, and provide recommendations." },
              { q: "Which cities do you support?", a: "We support 26 cities across Broward, Palm Beach, and Miami-Dade counties including Fort Lauderdale, Miami, Boca Raton, Hollywood, Pompano Beach, Hialeah, Coral Springs, Pembroke Pines, Weston, and many more!" },
              { q: "What permit types can you analyze?", a: "We support all major permit types: Roofing, HVAC/Mechanical, Electrical, Plumbing, Windows/Doors, Pool, Fence, Solar, Generator, Demolition, and Marine (Dock, Seawall, Boat Lift). Our AI auto-detects the permit type from your documents!" },
              { q: "What file types can I upload?", a: "We accept PDF, PNG, JPG, and JPEG files. You can upload up to 50 files at once, with a maximum total size of 200MB." },
              { q: "Is my data secure?", a: "Yes! We use industry-standard encryption, secure password hashing, and your documents are processed securely. We never share your data with third parties." },
              { q: "Does this guarantee my permit will be approved?", a: "No. Flo Permit is an informational tool only. We help identify potential issues, but you should always verify requirements with your local permitting office." },
              { q: "Is there a free tier?", a: "Yes! Free accounts get 3 analyses per month. Need more? Contact us about Pro plans." },
              { q: "How accurate is the AI analysis?", a: "Our AI is trained on South Florida permit requirements and is highly accurate. However, requirements can change, so always verify with your local office." },
              { q: "Can I save my analysis history?", a: "Yes! Create a free account to save all your analyses and access them anytime." },
              { q: "How do I contact support?", a: "Email us at support@flopermit.com or use the Contact page. We typically respond within 24 hours." },
            ].map((faq, i) => (
              <div key={i} className="bg-gray-900/80 rounded-xl p-6 border border-gray-800">
                <h3 className="font-bold text-white mb-2">{faq.q}</h3>
                <p className="text-gray-400">{faq.a}</p>
              </div>
            ))}
          </div>
          <div className="mt-12 text-center">
            <p className="text-gray-500 mb-4">Still have questions?</p>
            <button onClick={() => setPage('contact')} className="px-8 py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl">Contact Us</button>
          </div>
        </div>
      </div>
      <Footer />
    </div>
  )

  // === PRICING PAGE ===
  if (page === 'pricing') return (
    <div className="min-h-screen bg-black text-white flex flex-col">
      <div className="fixed inset-0 z-0"><div className="absolute inset-0 bg-gradient-to-br from-black via-gray-900 to-black"></div></div>
      <NavBar showBack />
      <div className="relative z-10 pt-24 px-6 pb-12 flex-grow">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-12">
            <h1 className="text-4xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent mb-4">Simple, Transparent Pricing</h1>
            <p className="text-gray-400 text-lg">Choose the plan that fits your needs</p>
          </div>
          
          {/* Homeowner Single Purchase Banner */}
          <div className="mb-8 p-6 bg-gradient-to-r from-amber-500/10 to-orange-500/10 border border-amber-500/30 rounded-2xl">
            <div className="flex flex-col md:flex-row items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-2xl">🏠</span>
                  <h3 className="text-xl font-bold text-amber-400">Homeowner? Just need one analysis?</h3>
                </div>
                <p className="text-gray-400">Get a single permit analysis for <span className="text-white font-bold">$15.99</span> — no subscription required. Includes full checklist!</p>
              </div>
              <button onClick={() => setShowSinglePurchase(true)} className="px-6 py-3 bg-gradient-to-r from-amber-500 to-orange-500 text-black font-bold rounded-xl whitespace-nowrap hover:scale-105 transition-transform">
                Get Single Analysis →
              </button>
            </div>
          </div>

          <div className="grid md:grid-cols-3 gap-6">
            {/* Free */}
            <div className="bg-gray-900/80 rounded-2xl p-8 border border-gray-800">
              <h3 className="text-xl font-bold text-white mb-2">Free</h3>
              <div className="mb-6"><span className="text-4xl font-black text-white">$0</span><span className="text-gray-500">/month</span></div>
              <ul className="space-y-3 mb-8">
                <li className="flex items-center gap-2 text-gray-400"><svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg>3 analyses/month</li>
                <li className="flex items-center gap-2 text-gray-400"><svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg>Basic AI analysis</li>
                <li className="flex items-center gap-2 text-gray-400"><svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg>Email support</li>
              </ul>
              {subscription?.tier === 'free' ? (
                <button disabled className="w-full py-3 border border-gray-700 text-gray-500 font-bold rounded-xl">Current Plan</button>
              ) : (
                <button onClick={() => setPage('home')} className="w-full py-3 border border-gray-700 text-white font-bold rounded-xl hover:bg-gray-800">Get Started</button>
              )}
            </div>
            {/* Pro */}
            <div className="bg-gray-900/80 rounded-2xl p-8 border-2 border-cyan-500 relative">
              <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-1 bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-full text-black text-xs font-bold">POPULAR</div>
              <h3 className="text-xl font-bold text-white mb-2">Pro</h3>
              <div className="mb-6"><span className="text-4xl font-black text-white">$29</span><span className="text-gray-500">/month</span></div>
              <ul className="space-y-3 mb-8">
                <li className="flex items-center gap-2 text-gray-400"><svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg>50 analyses/month</li>
                <li className="flex items-center gap-2 text-gray-400"><svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg>Priority AI analysis</li>
                <li className="flex items-center gap-2 text-gray-400"><svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg>Priority support</li>
                <li className="flex items-center gap-2 text-gray-400"><svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg>Analysis history</li>
              </ul>
              {subscription?.tier === 'pro' ? (
                <button onClick={openBillingPortal} className="w-full py-3 border border-cyan-500 text-cyan-400 font-bold rounded-xl hover:bg-cyan-500/10">Manage Subscription</button>
              ) : (
                <button onClick={() => handleCheckout('pro')} disabled={checkoutLoading || !currentUser} className="w-full py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl disabled:opacity-50">{checkoutLoading ? 'Loading...' : currentUser ? 'Upgrade to Pro' : 'Sign up first'}</button>
              )}
            </div>
            {/* Business */}
            <div className="bg-gray-900/80 rounded-2xl p-8 border border-gray-800">
              <h3 className="text-xl font-bold text-white mb-2">Business</h3>
              <div className="mb-6"><span className="text-4xl font-black text-white">$99</span><span className="text-gray-500">/month</span></div>
              <ul className="space-y-3 mb-8">
                <li className="flex items-center gap-2 text-gray-400"><svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg>Unlimited analyses</li>
                <li className="flex items-center gap-2 text-gray-400"><svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg>Priority AI analysis</li>
                <li className="flex items-center gap-2 text-gray-400"><svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg>Dedicated support</li>
                <li className="flex items-center gap-2 text-gray-400"><svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg>Analysis history</li>
                <li className="flex items-center gap-2 text-gray-400"><svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg>Team features (soon)</li>
              </ul>
              {subscription?.tier === 'business' ? (
                <button onClick={openBillingPortal} className="w-full py-3 border border-purple-500 text-purple-400 font-bold rounded-xl hover:bg-purple-500/10">Manage Subscription</button>
              ) : (
                <button onClick={() => handleCheckout('business')} disabled={checkoutLoading || !currentUser} className="w-full py-3 border border-gray-700 text-white font-bold rounded-xl hover:bg-gray-800 disabled:opacity-50">{checkoutLoading ? 'Loading...' : currentUser ? 'Upgrade to Business' : 'Sign up first'}</button>
              )}
            </div>
          </div>
          {subscription && (
            <div className="mt-8 p-4 bg-gray-900/50 rounded-xl border border-gray-800 text-center">
              <p className="text-gray-400">Current usage: <span className="text-white font-bold">{subscription.analyses_this_month}</span> / {subscription.analyses_limit === -1 ? '∞' : subscription.analyses_limit} analyses this month</p>
            </div>
          )}
        </div>
      </div>
      
      {/* Single Purchase Modal */}
      {showSinglePurchase && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="bg-gray-900 rounded-2xl p-8 max-w-md w-full border border-gray-800 relative max-h-[90vh] overflow-y-auto">
            <button onClick={() => setShowSinglePurchase(false)} className="absolute top-4 right-4 text-gray-500 hover:text-white">✕</button>
            <div className="text-center mb-6">
              <h2 className="text-2xl font-bold text-white mb-2">Homeowner Single Analysis</h2>
              <p className="text-gray-400">One-time purchase for <span className="text-amber-400 font-bold">$15.99</span></p>
            </div>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-semibold text-gray-400 mb-2">Your Email</label>
                <input 
                  type="email" 
                  value={singlePurchaseEmail} 
                  onChange={e => setSinglePurchaseEmail(e.target.value)}
                  placeholder="your@email.com"
                  className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl text-white focus:border-amber-500 focus:outline-none"
                />
              </div>
              
              <div>
                <label className="block text-sm font-semibold text-gray-400 mb-2">County</label>
                <select 
                  value={county} 
                  onChange={e => { setCounty(e.target.value); setCity(''); setPermitType('') }}
                  className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl text-white focus:border-amber-500 focus:outline-none"
                >
                  <option value="">Select county...</option>
                  <option value="Broward">Broward County</option>
                  <option value="Miami-Dade">Miami-Dade County</option>
                  <option value="Palm Beach">Palm Beach County</option>
                </select>
              </div>
              
              <div>
                <label className="block text-sm font-semibold text-gray-400 mb-2">City</label>
                <select 
                  value={city} 
                  onChange={e => { setCity(e.target.value); setPermitType('auto') }}
                  disabled={!county}
                  className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl text-white focus:border-amber-500 focus:outline-none disabled:opacity-50"
                >
                  <option value="">{county ? 'Select city...' : 'Select county first'}</option>
                  {county === 'Broward' && (
                    <>
                      <option value="Coconut Creek">Coconut Creek</option>
                      <option value="Coral Springs">Coral Springs</option>
                      <option value="Davie">Davie</option>
                      <option value="Deerfield Beach">Deerfield Beach</option>
                      <option value="Fort Lauderdale">Fort Lauderdale</option>
                      <option value="Hollywood">Hollywood</option>
                      <option value="Lauderdale-by-the-Sea">Lauderdale-by-the-Sea</option>
                      <option value="Lighthouse Point">Lighthouse Point</option>
                      <option value="Margate">Margate</option>
                      <option value="Miramar">Miramar</option>
                      <option value="Pembroke Pines">Pembroke Pines</option>
                      <option value="Plantation">Plantation</option>
                      <option value="Pompano Beach">Pompano Beach</option>
                      <option value="Sunrise">Sunrise</option>
                      <option value="Tamarac">Tamarac</option>
                      <option value="Weston">Weston</option>
                    </>
                  )}
                  {county === 'Palm Beach' && (
                    <>
                      <option value="Boca Raton">Boca Raton</option>
                      <option value="Boynton Beach">Boynton Beach</option>
                      <option value="Delray Beach">Delray Beach</option>
                      <option value="Lake Worth Beach">Lake Worth Beach</option>
                      <option value="West Palm Beach">West Palm Beach</option>
                    </>
                  )}
                  {county === 'Miami-Dade' && (
                    <>
                      <option value="Hialeah">Hialeah</option>
                      <option value="Homestead">Homestead</option>
                      <option value="Kendall">Kendall (Unincorporated)</option>
                      <option value="Miami">Miami</option>
                      <option value="Miami Gardens">Miami Gardens</option>
                    </>
                  )}
                </select>
              </div>
              
              <div>
                <label className="block text-sm font-semibold text-gray-400 mb-2">Permit Type</label>
                <select 
                  value={permitType} 
                  onChange={e => setPermitType(e.target.value)}
                  disabled={!city}
                  className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl text-white focus:border-amber-500 focus:outline-none disabled:opacity-50"
                >
                  {getPermitTypes().map((pt, i) => (
                    <option key={pt.value || `cat-${i}`} value={pt.value} disabled={pt.disabled}>
                      {pt.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            
            <div className="mt-6 p-4 bg-amber-500/10 border border-amber-500/20 rounded-xl">
              <p className="text-sm text-amber-400">✓ Full AI-powered permit analysis</p>
              <p className="text-sm text-amber-400">✓ Complete checklist for your permit type</p>
              <p className="text-sm text-amber-400">✓ 30 days to complete your analysis</p>
              <p className="text-sm text-amber-400">✓ No account or subscription required</p>
            </div>
            
            <button 
              onClick={handleSinglePurchaseCheckout}
              disabled={checkoutLoading || !singlePurchaseEmail || !city}
              className="w-full mt-6 py-4 bg-gradient-to-r from-amber-500 to-orange-500 text-black font-bold rounded-xl disabled:opacity-50 hover:scale-[1.02] transition-transform"
            >
              {checkoutLoading ? 'Processing...' : 'Pay $15.99 →'}
            </button>
          </div>
        </div>
      )}
      
      <Footer />
    </div>
  )

  // === 404 PAGE ===
  if (page === '404') return (
    <div className="min-h-screen bg-black text-white flex flex-col">
      <div className="fixed inset-0 z-0"><div className="absolute inset-0 bg-gradient-to-br from-black via-gray-900 to-black"></div></div>
      <NavBar />
      <div className="relative z-10 pt-24 px-6 pb-12 flex-grow flex items-center justify-center">
        <div className="text-center">
          <div className="text-8xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent mb-4">404</div>
          <h1 className="text-2xl font-bold text-white mb-4">Page Not Found</h1>
          <p className="text-gray-400 mb-8">Oops! The page you're looking for doesn't exist or has been moved.</p>
          <button onClick={() => setPage('home')} className="px-8 py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl">Go Home</button>
        </div>
      </div>
      <Footer />
    </div>
  )

  // === SINGLE ANALYSIS PAGE (Homeowner Purchase) ===
  if (page === 'single-analysis' && singlePurchase) return (
    <div className="min-h-screen bg-black text-white flex flex-col">
      <div className="fixed inset-0 z-0"><div className="absolute inset-0 bg-gradient-to-br from-black via-gray-900 to-black"></div></div>
      <NavBar />
      <div className="relative z-10 pt-24 px-6 pb-12 flex-grow">
        <div className="max-w-4xl mx-auto">
          {successMessage && (
            <div className="mb-6 p-4 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-emerald-400 flex items-center gap-2">
              <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd"/></svg>
              {successMessage}
            </div>
          )}
          
          <div className="text-center mb-8">
            <span className="text-5xl mb-4 block">🏠</span>
            <h1 className="text-3xl font-black text-white mb-2">Your Permit Analysis</h1>
            <p className="text-gray-400">{singlePurchase.city} • {singlePurchase.permit_type}</p>
          </div>
          
          {singlePurchase.analysis_used ? (
            <div className="bg-gray-900/80 rounded-2xl p-8 border border-gray-800 text-center">
              <div className="text-6xl mb-4">✅</div>
              <h2 className="text-2xl font-bold text-white mb-4">Analysis Complete!</h2>
              <p className="text-gray-400 mb-6">Your single analysis has been used. Thank you for using Flo Permit!</p>
              <button onClick={() => setPage('home')} className="px-6 py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl">Back to Home</button>
            </div>
          ) : (
            <>
              {/* Checklist Section */}
              <div className="bg-gray-900/80 rounded-2xl p-8 border border-amber-500/30 mb-8">
                <h2 className="text-xl font-bold text-amber-400 mb-4 flex items-center gap-2">
                  <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/></svg>
                  Required Documents Checklist
                </h2>
                <p className="text-gray-400 text-sm mb-4">Gather these documents before uploading. Items you have will be darkened after analysis.</p>
                <div className="space-y-2">
                  {singlePurchase.checklist?.map((doc, i) => (
                    <div key={i} className="flex items-center gap-3 p-3 bg-black/30 rounded-lg border border-gray-800">
                      <div className="w-5 h-5 border-2 border-amber-500/50 rounded flex-shrink-0"></div>
                      <span className="text-gray-300">{doc}</span>
                    </div>
                  ))}
                </div>
              </div>
              
              {/* Gotchas/Tips */}
              {singlePurchase.gotchas?.length > 0 && (
                <div className="bg-red-500/10 rounded-2xl p-6 border border-red-500/30 mb-8">
                  <h3 className="text-lg font-bold text-red-400 mb-3 flex items-center gap-2">
                    <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd"/></svg>
                    Watch Out For ({singlePurchase.city})
                  </h3>
                  <ul className="space-y-2">
                    {singlePurchase.gotchas.map((g, i) => (
                      <li key={i} className="text-red-300 text-sm flex items-start gap-2">
                        <span className="text-red-500">⚠️</span>
                        {g}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              
              {/* File Upload for Single Purchase */}
              <div className="bg-gray-900/80 rounded-2xl p-8 border border-gray-800">
                <h2 className="text-xl font-bold text-white mb-4">Upload Your Permit Documents</h2>
                <div 
                  className={`border-2 border-dashed rounded-2xl p-8 text-center transition-all duration-200 ${isDragging ? 'border-amber-400 bg-amber-500/10' : 'border-gray-700 bg-black/30'}`}
                  onDragOver={e => { e.preventDefault(); setIsDragging(true) }}
                  onDragLeave={() => setIsDragging(false)}
                  onDrop={e => { e.preventDefault(); setIsDragging(false); handleFiles({ target: { files: e.dataTransfer.files } }) }}
                >
                  <input type="file" multiple onChange={handleFiles} className="hidden" id="singleFileInput" accept=".pdf,.png,.jpg,.jpeg" />
                  <input type="file" multiple webkitdirectory="" directory="" onChange={handleFiles} className="hidden" id="singleFolderInput" />
                  
                  <div className="w-16 h-16 mx-auto mb-4 bg-gradient-to-br from-amber-500/20 to-orange-500/20 rounded-2xl flex items-center justify-center border border-amber-500/30">
                    <svg className="w-8 h-8 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/>
                    </svg>
                  </div>
                  
                  <p className="font-bold text-white mb-2">Drag & drop files here</p>
                  <p className="text-sm text-gray-500 mb-4">PDF, PNG, JPG • Max 50 files</p>
                  
                  <div className="flex items-center justify-center gap-3">
                    <label htmlFor="singleFileInput" className="cursor-pointer px-4 py-2 bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/30 rounded-lg text-amber-400 text-sm font-semibold transition-all">
                      Select Files
                    </label>
                    <span className="text-gray-600">or</span>
                    <label htmlFor="singleFolderInput" className="cursor-pointer px-4 py-2 bg-orange-500/20 hover:bg-orange-500/30 border border-orange-500/30 rounded-lg text-orange-400 text-sm font-semibold transition-all">
                      Select Folder
                    </label>
                  </div>
                </div>
                
                {validFiles.length > 0 && (
                  <div className="mt-4 p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-xl">
                    <div className="flex justify-between items-center">
                      <span className="text-emerald-400 font-semibold">{validFiles.length} files ready ({formatSize(totalSize)})</span>
                      <button onClick={clearFiles} className="text-red-400 hover:text-red-300 text-sm">Clear</button>
                    </div>
                  </div>
                )}
                
                <button 
                  onClick={async () => {
                    if (validFiles.length === 0) return alert('Please upload files first')
                    setLoading(true)
                    setLoadingStatus('Analyzing your permit package...')
                    try {
                      const formData = new FormData()
                      validFiles.forEach(f => formData.append('files', f))
                      const res = await fetch(`${API_BASE_URL}/api/analyze-single/${singlePurchase.purchase_uuid}`, { method: 'POST', body: formData })
                      if (res.ok) {
                        const data = await res.json()
                        setResults({ ...data, checklist: singlePurchase.checklist })
                        localStorage.removeItem('pending_purchase')
                        setPage('results')
                      } else {
                        const err = await res.json()
                        alert(err.detail || 'Analysis failed')
                      }
                    } catch (err) { alert('Error analyzing files') }
                    finally { setLoading(false); setLoadingStatus('') }
                  }}
                  disabled={loading || validFiles.length === 0}
                  className="w-full mt-6 py-4 bg-gradient-to-r from-amber-500 to-orange-500 text-black font-bold rounded-xl disabled:opacity-50"
                >
                  {loading ? loadingStatus : `Analyze ${validFiles.length} Files`}
                </button>
                
                <p className="text-center text-gray-500 text-sm mt-4">⚡ This is your one-time analysis. Make sure all documents are included!</p>
              </div>
              
              {/* Expiration Notice */}
              {singlePurchase.expires_at && (
                <p className="text-center text-gray-500 text-sm mt-4">
                  Purchase expires: {new Date(singlePurchase.expires_at).toLocaleDateString()}
                </p>
              )}
            </>
          )}
        </div>
      </div>
      <Footer />
    </div>
  )

  if (page === 'admin' && isAdmin) return (
    <div className="min-h-screen bg-black text-white flex flex-col">
      <div className="fixed inset-0 z-0"><div className="absolute inset-0 bg-gradient-to-br from-black via-gray-900 to-black"></div></div>
      <NavBar />
      <div className="relative z-10 pt-24 px-6 pb-12 flex-grow">
        <div className="max-w-6xl mx-auto">
          <div className="flex items-center justify-between mb-8">
            <h1 className="text-3xl font-black bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent">Admin Dashboard</h1>
            <button onClick={loadAdminStats} className="px-4 py-2 bg-purple-500/20 text-purple-400 rounded-lg hover:bg-purple-500/30">↻ Refresh</button>
          </div>
          {adminLoading ? <div className="text-center py-12"><div className="w-8 h-8 border-2 border-purple-500 border-t-transparent rounded-full animate-spin mx-auto"></div></div> : adminStats ? (
            <div className="space-y-6">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-gray-900/80 rounded-xl p-4 border border-gray-800"><p className="text-gray-500 text-sm">Total Users</p><p className="text-3xl font-black text-white">{adminStats.overview.total_users}</p><p className="text-emerald-400 text-sm">+{adminStats.overview.new_users_this_month} this month</p></div>
                <div className="bg-gray-900/80 rounded-xl p-4 border border-gray-800"><p className="text-gray-500 text-sm">Total Analyses</p><p className="text-3xl font-black text-white">{adminStats.overview.total_analyses}</p><p className="text-cyan-400 text-sm">+{adminStats.overview.analyses_this_month} this month</p></div>
                <div className="bg-gray-900/80 rounded-xl p-4 border border-gray-800"><p className="text-gray-500 text-sm">Avg Score</p><p className="text-3xl font-black text-white">{adminStats.overview.average_compliance_score}%</p></div>
                <div className="bg-gray-900/80 rounded-xl p-4 border border-gray-800"><p className="text-gray-500 text-sm">API Requests</p><p className="text-3xl font-black text-white">{adminStats.overview.api_requests_today}</p><p className="text-purple-400 text-sm">{adminStats.overview.api_requests_this_month} this month</p></div>
              </div>
              <div className="grid md:grid-cols-2 gap-6">
                <div className="bg-gray-900/80 rounded-xl p-6 border border-gray-800">
                  <h3 className="font-bold text-white mb-4">Popular Cities</h3>
                  {adminStats.popular_cities.length === 0 ? <p className="text-gray-500">No data yet</p> : adminStats.popular_cities.map((c, i) => (
                    <div key={i} className="flex justify-between py-2 border-b border-gray-800 last:border-0"><span className="text-gray-300">{c.city}</span><span className="text-cyan-400 font-bold">{c.count}</span></div>
                  ))}
                </div>
                <div className="bg-gray-900/80 rounded-xl p-6 border border-gray-800">
                  <h3 className="font-bold text-white mb-4">Popular Permit Types</h3>
                  {adminStats.popular_permits.length === 0 ? <p className="text-gray-500">No data yet</p> : adminStats.popular_permits.map((p, i) => (
                    <div key={i} className="flex justify-between py-2 border-b border-gray-800 last:border-0"><span className="text-gray-300">{p.permit_type}</span><span className="text-emerald-400 font-bold">{p.count}</span></div>
                  ))}
                </div>
              </div>
              <div className="bg-gray-900/80 rounded-xl p-6 border border-gray-800">
                <h3 className="font-bold text-white mb-4">Recent Users</h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead><tr className="text-gray-500 border-b border-gray-800"><th className="text-left py-2">Email</th><th className="text-left py-2">Name</th><th className="text-left py-2">Company</th><th className="text-left py-2">Joined</th></tr></thead>
                    <tbody>{adminStats.recent_users.map(u => (
                      <tr key={u.id} className="border-b border-gray-800/50"><td className="py-2 text-white">{u.email}</td><td className="py-2 text-gray-400">{u.full_name || '-'}</td><td className="py-2 text-gray-400">{u.company_name || '-'}</td><td className="py-2 text-gray-500">{new Date(u.created_at).toLocaleDateString()}</td></tr>
                    ))}</tbody>
                  </table>
                </div>
              </div>
              <div className="bg-gray-900/80 rounded-xl p-6 border border-gray-800">
                <h3 className="font-bold text-white mb-4">Recent Analyses</h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead><tr className="text-gray-500 border-b border-gray-800"><th className="text-left py-2">City</th><th className="text-left py-2">Type</th><th className="text-left py-2">Files</th><th className="text-left py-2">Score</th><th className="text-left py-2">Date</th></tr></thead>
                    <tbody>{adminStats.recent_analyses.map(a => (
                      <tr key={a.id} className="border-b border-gray-800/50"><td className="py-2 text-white">{a.city}</td><td className="py-2 text-gray-400">{a.permit_type}</td><td className="py-2 text-gray-400">{a.files_analyzed}</td><td className={`py-2 font-bold ${a.compliance_score >= 70 ? 'text-emerald-400' : a.compliance_score >= 40 ? 'text-amber-400' : 'text-red-400'}`}>{a.compliance_score}%</td><td className="py-2 text-gray-500">{new Date(a.created_at).toLocaleDateString()}</td></tr>
                    ))}</tbody>
                  </table>
                </div>
              </div>
              <div className="bg-gray-900/80 rounded-xl p-6 border border-gray-800">
                <h3 className="font-bold text-white mb-4">API Endpoint Stats (This Month)</h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead><tr className="text-gray-500 border-b border-gray-800"><th className="text-left py-2">Endpoint</th><th className="text-left py-2">Requests</th><th className="text-left py-2">Avg Response</th></tr></thead>
                    <tbody>{adminStats.endpoint_stats.map((e, i) => (
                      <tr key={i} className="border-b border-gray-800/50"><td className="py-2 text-white font-mono text-xs">{e.endpoint}</td><td className="py-2 text-cyan-400 font-bold">{e.count}</td><td className="py-2 text-gray-400">{e.avg_response_ms}ms</td></tr>
                    ))}</tbody>
                  </table>
                </div>
              </div>
            </div>
          ) : <p className="text-gray-500 text-center">Failed to load stats</p>}
        </div>
      </div>
      <Footer />
    </div>
  )


  if (page === 'reset-password') return (
    <div className="min-h-screen bg-black text-white flex flex-col">
      <div className="fixed inset-0 z-0"><div className="absolute inset-0 bg-gradient-to-br from-black via-gray-900 to-black"></div></div>
      <NavBar showBack />
      <div className="relative z-10 pt-24 px-6 pb-12 flex items-center justify-center flex-grow">
        <div className="relative max-w-md w-full">
          <div className="absolute -inset-1 bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-3xl blur-lg opacity-50"></div>
          <div className="relative bg-gray-900 rounded-2xl p-8 border border-cyan-500/20">
            <h2 className="text-2xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent mb-6">Reset Your Password</h2>
            {successMessage ? (<div className="text-center"><div className="w-16 h-16 mx-auto mb-4 bg-emerald-500/20 rounded-full flex items-center justify-center"><svg className="w-8 h-8 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg></div><p className="text-emerald-400 mb-4">{successMessage}</p><p className="text-gray-500 text-sm">Redirecting to login...</p></div>) : (
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
      <Footer />
    </div>
  )

  if (page === 'terms') return (
    <div className="min-h-screen bg-black text-white flex flex-col">
      <div className="fixed inset-0 z-0"><div className="absolute inset-0 bg-gradient-to-br from-black via-gray-900 to-black"></div></div>
      <NavBar showBack />
      <div className="relative z-10 pt-24 px-6 pb-12 flex-grow">
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
      <Footer />
    </div>
  )

  if (page === 'profile' && currentUser) return (
    <div className="min-h-screen bg-black text-white flex flex-col">
      <div className="fixed inset-0 z-0"><div className="absolute inset-0 bg-gradient-to-br from-black via-gray-900 to-black"></div></div>
      <NavBar />
      <div className="relative z-10 pt-24 px-6 pb-12 flex-grow">
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
                    <div className="flex items-center gap-4"><div className="w-16 h-16 bg-gradient-to-br from-cyan-500 to-emerald-500 rounded-full flex items-center justify-center text-2xl font-bold text-black">{(profile.user.full_name || profile.user.email)[0].toUpperCase()}</div><div><h3 className="text-lg font-bold text-white">{profile.user.full_name || 'No name set'}</h3><p className="text-gray-400">{profile.user.email}</p></div></div>
                    <div className="grid grid-cols-2 gap-4 pt-4 border-t border-gray-800"><div><span className="text-gray-500 text-sm">Company</span><p className="text-white">{profile.user.company_name || '-'}</p></div><div><span className="text-gray-500 text-sm">Phone</span><p className="text-white">{profile.user.phone || '-'}</p></div><div><span className="text-gray-500 text-sm">Member Since</span><p className="text-white">{new Date(profile.user.created_at).toLocaleDateString()}</p></div></div>
                  </div>
                )}
              </div>
              <div className="bg-gray-900/80 rounded-2xl p-6 border border-gray-800">
                <h2 className="text-xl font-bold text-white mb-4">Subscription</h2>
                <div className={`inline-block px-3 py-1 rounded-full text-sm font-bold mb-4 ${profile.subscription.tier === 'pro' ? 'bg-cyan-500/20 text-cyan-400' : profile.subscription.tier === 'business' ? 'bg-purple-500/20 text-purple-400' : 'bg-gray-700 text-gray-300'}`}>{profile.subscription.tier.toUpperCase()}</div>
                <div className="space-y-3"><div className="flex justify-between"><span className="text-gray-400">This Month</span><span className="text-white font-bold">{profile.subscription.analyses_this_month} analyses</span></div>{profile.subscription.analyses_remaining >= 0 && <div className="flex justify-between"><span className="text-gray-400">Remaining</span><span className="text-cyan-400 font-bold">{profile.subscription.analyses_remaining}</span></div>}<div className="flex justify-between"><span className="text-gray-400">Total</span><span className="text-white">{profile.stats.total_analyses}</span></div></div>
                {profile.subscription.tier === 'free' ? (
                  <button onClick={() => setPage('pricing')} className="w-full mt-4 py-2 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-lg">Upgrade to Pro</button>
                ) : (
                  <button onClick={openBillingPortal} className="w-full mt-4 py-2 border border-gray-700 text-white font-bold rounded-lg hover:bg-gray-800">Manage Subscription</button>
                )}
              </div>
            </div>
          ) : <p className="text-gray-500">Could not load profile</p>}
        </div>
      </div>
      <Footer />
    </div>
  )

  if (page === 'history') return (
    <div className="min-h-screen bg-black text-white flex flex-col">
      <div className="fixed inset-0 z-0"><div className="absolute inset-0 bg-gradient-to-br from-black via-gray-900 to-black"></div></div>
      <NavBar />
      <div className="relative z-10 pt-24 px-6 pb-12 flex-grow">
        <div className="max-w-4xl mx-auto">
          <div className="flex justify-between items-center mb-8"><h1 className="text-3xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent">Analysis History</h1><button onClick={() => setPage('home')} className="px-6 py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl">New Analysis</button></div>
          {historyLoading ? <div className="text-center py-12"><div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto"></div></div> : history.length === 0 ? <div className="text-center py-12 bg-gray-900/50 rounded-2xl border border-gray-800"><p className="text-gray-500">No analyses yet</p></div> : (
            <div className="space-y-3">{history.map(h => (
              <div key={h.analysis_uuid} className="bg-gray-900/50 rounded-xl border border-gray-800 p-4 flex items-center justify-between hover:border-gray-700">
                <div className="flex-1 cursor-pointer" onClick={() => viewAnalysis(h.analysis_uuid)}><div className="flex items-center gap-3"><span className="font-bold text-white">{h.city}</span><span className="text-gray-500">•</span><span className="text-gray-400">{h.permit_type}</span></div><div className="text-sm text-gray-500 mt-1">{h.files_analyzed} files • {new Date(h.created_at).toLocaleDateString()}</div></div>
                <div className="flex items-center gap-4"><span className={`text-2xl font-black ${h.compliance_score >= 70 ? 'text-emerald-400' : h.compliance_score >= 40 ? 'text-amber-400' : 'text-red-400'}`}>{h.compliance_score || '-'}%</span><button onClick={() => deleteAnalysis(h.analysis_uuid)} className="text-gray-500 hover:text-red-400 p-2"><svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg></button></div>
              </div>
            ))}</div>
          )}
        </div>
      </div>
      <Footer />
    </div>
  )

  if (page === 'results' && results) {
    // Organize checklist: missing at top (white), found at bottom (darkened)
    const missingDocs = results.analysis?.missing_documents || []
    const foundDocs = results.analysis?.documents_found || []
    
    return (
      <div className="min-h-screen bg-black text-white flex flex-col">
        <div className="fixed inset-0 z-0"><div className="absolute inset-0 bg-gradient-to-br from-black via-gray-900 to-black"></div></div>
        <NavBar />
        <div className="relative z-10 pt-24 px-6 pb-12 flex-grow">
          <div className="max-w-4xl mx-auto">
            <div className="bg-gray-900/90 rounded-3xl overflow-hidden border border-gray-800">
              {/* Header with score */}
              <div className="p-8 border-b border-gray-800 bg-gradient-to-r from-cyan-500/10 to-emerald-500/10">
                <div className="flex justify-between items-center">
                  <div>
                    <h2 className="text-2xl font-black text-white">Analysis Complete</h2>
                    <p className="text-gray-400">{results.city} • {results.analysis?.detected_permit_description || results.permit_type}</p>
                  </div>
                  <div className="text-center">
                    <div className={`text-5xl font-black ${(results.analysis?.compliance_score || 0) >= 70 ? 'text-emerald-400' : (results.analysis?.compliance_score || 0) >= 40 ? 'text-amber-400' : 'text-red-400'}`}>
                      {results.analysis?.compliance_score || 0}%
                    </div>
                    <div className="text-sm text-gray-500">Compliance</div>
                  </div>
                </div>
              </div>
              
              <div className="p-8 space-y-6">
                {/* Summary */}
                {results.analysis?.summary && (
                  <div className="p-4 bg-gray-800/50 rounded-xl">
                    <p className="text-gray-300">{results.analysis.summary}</p>
                  </div>
                )}
                
                {/* Document Checklist - Organized */}
                <div>
                  <h3 className="font-bold text-white mb-4 flex items-center gap-2">
                    <svg className="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/></svg>
                    Document Checklist
                  </h3>
                  
                  <div className="space-y-2">
                    {/* Missing Documents - At Top - White/Bright */}
                    {missingDocs.map((doc, idx) => (
                      <div key={`missing-${idx}`} className="flex items-center gap-3 p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
                        <div className="w-5 h-5 border-2 border-red-400 rounded flex-shrink-0 flex items-center justify-center">
                          <svg className="w-3 h-3 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="3" d="M6 18L18 6M6 6l12 12"/></svg>
                        </div>
                        <span className="text-white font-medium">{doc}</span>
                        <span className="ml-auto text-xs text-red-400 font-semibold">NEEDED</span>
                      </div>
                    ))}
                    
                    {/* Found Documents - At Bottom - Darkened */}
                    {foundDocs.map((doc, idx) => (
                      <div key={`found-${idx}`} className="flex items-center gap-3 p-3 bg-gray-800/30 rounded-lg opacity-60">
                        <div className="w-5 h-5 bg-emerald-500/20 border border-emerald-500/50 rounded flex-shrink-0 flex items-center justify-center">
                          <svg className="w-3 h-3 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="3" d="M5 13l4 4L19 7"/></svg>
                        </div>
                        <span className="text-gray-400">{doc}</span>
                        <span className="ml-auto text-xs text-emerald-500">✓ Found</span>
                      </div>
                    ))}
                  </div>
                </div>
                
                {/* Critical Issues */}
                {results.analysis?.critical_issues?.length > 0 && (
                  <div>
                    <h3 className="font-bold text-red-400 mb-3 flex items-center gap-2">
                      <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd"/></svg>
                      Critical Issues
                    </h3>
                    <ul className="space-y-2">
                      {results.analysis.critical_issues.map((issue, idx) => (
                        <li key={idx} className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-red-300">{issue}</li>
                      ))}
                    </ul>
                  </div>
                )}
                
                {/* Recommendations */}
                {results.analysis?.recommendations?.length > 0 && (
                  <div>
                    <h3 className="font-bold text-cyan-400 mb-3 flex items-center gap-2">
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/></svg>
                      Recommendations
                    </h3>
                    <ul className="space-y-2">
                      {results.analysis.recommendations.map((rec, idx) => (
                        <li key={idx} className="p-3 bg-cyan-500/10 border border-cyan-500/20 rounded-lg text-gray-300">{rec}</li>
                      ))}
                    </ul>
                  </div>
                )}
                
                {/* City Specific Warnings */}
                {results.analysis?.city_specific_warnings?.length > 0 && (
                  <div>
                    <h3 className="font-bold text-amber-400 mb-3">{results.city} Specific Warnings</h3>
                    <ul className="space-y-2">
                      {results.analysis.city_specific_warnings.map((warn, idx) => (
                        <li key={idx} className="p-3 bg-amber-500/10 border border-amber-500/20 rounded-lg text-amber-300">{warn}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
              
              {/* Disclaimer */}
              <div className="px-8 pb-4">
                <div className="p-3 bg-gray-800/50 border border-gray-700 rounded-lg">
                  <p className="text-gray-500 text-xs"><strong>Disclaimer:</strong> This analysis is informational only. Always verify requirements with your local permitting office.</p>
                </div>
              </div>
              
              {/* Action Button */}
              <div className="p-6 bg-black/50 border-t border-gray-800 text-center">
                <button onClick={() => { setPage('home'); setResults(null); clearFiles() }} className="px-8 py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl hover:scale-105 transition-transform">
                  New Analysis
                </button>
              </div>
            </div>
          </div>
        </div>
        <Footer />
      </div>
    )
  }

  // ============================================================================
  // LANDING PAGE (NOT LOGGED IN)
  // ============================================================================
  if (!currentUser) return (
    <div className="min-h-screen bg-black text-white overflow-hidden flex flex-col">
      <div className="fixed inset-0 z-0">
        <div className="absolute inset-0 bg-gradient-to-br from-black via-gray-900 to-black"></div>
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-cyan-500/20 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-purple-500/20 rounded-full blur-3xl animate-pulse" style={{animationDelay: '1s'}}></div>
        <div className="absolute inset-0 opacity-20" style={{backgroundImage: 'linear-gradient(rgba(6, 182, 212, 0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(6, 182, 212, 0.1) 1px, transparent 1px)', backgroundSize: '50px 50px'}}></div>
      </div>

      <nav className="fixed top-0 left-0 right-0 z-50 bg-black/80 backdrop-blur-xl border-b border-cyan-500/20">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-11 h-11 bg-gradient-to-br from-cyan-400 to-emerald-400 rounded-xl flex items-center justify-center p-1.5">
              <img src="/permit_logo.jpg" alt="Flo Permit" className="w-full h-full object-contain" />
            </div>
            <div><h1 className="text-xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent">Flo Permit</h1><p className="text-xs text-cyan-500 font-semibold">SOUTH FLORIDA</p></div>
          </div>
        </div>
      </nav>

      <div className="relative z-10 flex-grow flex items-center justify-center px-6 py-24">
        <div className="max-w-5xl mx-auto grid md:grid-cols-2 gap-12 items-center">
          
          {/* Left side - Hero */}
          <div className="text-center md:text-left">
            <span className="px-4 py-1.5 bg-cyan-500/10 border border-cyan-500/20 rounded-full text-cyan-400 text-sm font-semibold">AI-POWERED PERMIT ANALYSIS</span>
            <h1 className="text-4xl md:text-5xl font-black mt-4 mb-6">
              <span className="bg-gradient-to-r from-white via-gray-200 to-gray-400 bg-clip-text text-transparent">South Florida</span><br/>
              <span className="bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent">Permit Checker</span>
            </h1>
            <p className="text-lg text-gray-400 mb-8">Upload your permit package and get instant AI-powered analysis. Know what's missing before you submit.</p>
            <div className="grid grid-cols-3 gap-4">
              {[{icon:'⚡',title:'Instant'},{icon:'🎯',title:'Accurate'},{icon:'📋',title:'Complete'}].map((f,i) => (
                <div key={i} className="text-center p-3 bg-gray-900/50 rounded-xl border border-gray-800">
                  <div className="text-2xl mb-1">{f.icon}</div>
                  <p className="text-sm text-gray-400">{f.title}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Right side - Auth Form */}
          <div className="relative">
            <div className="absolute -inset-1 bg-gradient-to-r from-cyan-500/50 via-emerald-500/50 to-purple-500/50 rounded-3xl blur-xl opacity-30"></div>
            <div className="relative bg-gray-900/90 backdrop-blur-xl rounded-2xl p-8 border border-gray-800">
              
              {showForgotPassword ? (
                <>
                  <h2 className="text-2xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent mb-6">Reset Password</h2>
                  {successMessage ? (
                    <div className="text-center">
                      <div className="w-16 h-16 mx-auto mb-4 bg-emerald-500/20 rounded-full flex items-center justify-center"><svg className="w-8 h-8 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg></div>
                      <p className="text-emerald-400 mb-4">{successMessage}</p>
                      <button onClick={() => { setShowForgotPassword(false); setSuccessMessage('') }} className="text-cyan-400 hover:text-cyan-300 text-sm">← Back to login</button>
                    </div>
                  ) : (
                    <>
                      <p className="text-gray-400 text-sm mb-6">Enter your email and we'll send you a reset link.</p>
                      <form onSubmit={handleForgotPassword}>
                        <input name="email" type="email" required placeholder="Email" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl mb-4 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none" />
                        {error && <p className="text-red-400 text-sm mb-4">{error}</p>}
                        <button type="submit" className="w-full py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl">Send Reset Link</button>
                      </form>
                      <p className="text-center mt-4 text-sm text-gray-500"><button onClick={() => { setShowForgotPassword(false); setError('') }} className="text-cyan-400 hover:text-cyan-300">← Back to login</button></p>
                    </>
                  )}
                </>
              ) : showRegister ? (
                <>
                  <h2 className="text-2xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent mb-6">Create Account</h2>
                  <form onSubmit={handleRegister}>
                    <input name="fullName" type="text" placeholder="Full Name" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl mb-4 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none" />
                    <input name="company" type="text" placeholder="Company (optional)" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl mb-4 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none" />
                    <input name="email" type="email" required placeholder="Email" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl mb-4 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none" />
                    <input name="password" type="password" required minLength="8" placeholder="Password (min 8 characters)" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl mb-4 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none" />
                    {error && <p className="text-red-400 text-sm mb-4">{error}</p>}
                    <button type="submit" className="w-full py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl">Create Account</button>
                  </form>
                  <p className="text-center mt-4 text-sm text-gray-500">Already have an account? <button onClick={() => { setShowRegister(false); setError('') }} className="text-cyan-400 hover:text-cyan-300">Log in</button></p>
                </>
              ) : (
                <>
                  <h2 className="text-2xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent mb-6">Welcome Back</h2>
                  <form onSubmit={handleLogin}>
                    <input name="email" type="email" required placeholder="Email" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl mb-4 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none" />
                    <input name="password" type="password" required placeholder="Password" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl mb-4 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none" />
                    {error && <p className="text-red-400 text-sm mb-4">{error}</p>}
                    <button type="submit" className="w-full py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl">Log In</button>
                  </form>
                  <div className="mt-4 text-center"><button onClick={() => { setShowForgotPassword(true); setError('') }} className="text-cyan-400 hover:text-cyan-300 text-sm">Forgot password?</button></div>
                  <div className="relative my-6"><div className="absolute inset-0 flex items-center"><div className="w-full border-t border-gray-700"></div></div><div className="relative flex justify-center text-sm"><span className="px-4 bg-gray-900 text-gray-500">or</span></div></div>
                  <button onClick={() => { setShowRegister(true); setError('') }} className="w-full py-3 border border-gray-700 text-white font-bold rounded-xl hover:bg-gray-800">Create New Account</button>
                </>
              )}
            </div>
          </div>
        </div>
      </div>
      <Footer />
    </div>
  )

  // ============================================================================
  // MAIN APP (LOGGED IN)
  // ============================================================================
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
              {successMessage ? (<div className="text-center"><div className="w-16 h-16 mx-auto mb-4 bg-emerald-500/20 rounded-full flex items-center justify-center"><svg className="w-8 h-8 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg></div><p className="text-emerald-400 mb-4">{successMessage}</p><button onClick={() => { setShowForgotPassword(false); setSuccessMessage('') }} className="text-cyan-400 hover:text-cyan-300 text-sm">Close</button></div>) : (<>
                <p className="text-gray-400 text-sm mb-6">Enter your email address and we'll send you a link to reset your password.</p>
                <form onSubmit={handleForgotPassword}><input name="email" type="email" required placeholder="Email" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl mb-4 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none" />{error && <p className="text-red-400 text-sm mb-4">{error}</p>}<button type="submit" className="w-full py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl">Send Reset Link</button></form>
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
            <div className="relative w-20 h-20 mx-auto mb-6">
              <div className="absolute inset-0 border-4 border-cyan-500/20 rounded-full"></div>
              <div className="absolute inset-0 border-4 border-transparent border-t-cyan-500 border-r-cyan-500 rounded-full animate-spin"></div>
            </div>
            <h3 className="text-2xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent mb-2">{loadingStatus}</h3>
            <p className="text-gray-500 text-sm">This may take a moment...</p>
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
              {/* Professional County/City/Permit Selection */}
              <div className="grid md:grid-cols-3 gap-4 mb-6">
                {/* County Select */}
                <div className="relative group">
                  <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-2">County</label>
                  <div className="relative">
                    <select 
                      value={county} 
                      onChange={e => { setCounty(e.target.value); setCity(''); setPermitType('') }} 
                      className="w-full px-4 py-3.5 bg-black/60 border border-gray-700/50 rounded-xl text-white appearance-none cursor-pointer transition-all duration-200 hover:border-gray-600 focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 focus:outline-none"
                    >
                      <option value="">Select county...</option>
                      <option value="Broward">Broward County</option>
                      <option value="Miami-Dade">Miami-Dade County</option>
                      <option value="Palm Beach">Palm Beach County</option>
                    </select>
                    <div className="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
                      <svg className="w-5 h-5 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7"/></svg>
                    </div>
                  </div>
                </div>

                {/* City Select */}
                <div className="relative group">
                  <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-2">City</label>
                  <div className="relative">
                    <select 
                      value={city} 
                      onChange={e => { setCity(e.target.value); setPermitType('') }} 
                      disabled={!county}
                      className={`w-full px-4 py-3.5 bg-black/60 border border-gray-700/50 rounded-xl text-white appearance-none cursor-pointer transition-all duration-200 hover:border-gray-600 focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 focus:outline-none ${!county ? 'opacity-50 cursor-not-allowed' : ''}`}
                    >
                      <option value="">{county ? 'Select city...' : 'Select county first'}</option>
                      {county === 'Broward' && (
                        <>
                          <option value="Coconut Creek">Coconut Creek</option>
                          <option value="Coral Springs">Coral Springs</option>
                          <option value="Davie">Davie</option>
                          <option value="Deerfield Beach">Deerfield Beach</option>
                          <option value="Fort Lauderdale">Fort Lauderdale</option>
                          <option value="Hollywood">Hollywood</option>
                          <option value="Lauderdale-by-the-Sea">Lauderdale-by-the-Sea</option>
                          <option value="Lighthouse Point">Lighthouse Point</option>
                          <option value="Margate">Margate</option>
                          <option value="Miramar">Miramar</option>
                          <option value="Pembroke Pines">Pembroke Pines</option>
                          <option value="Plantation">Plantation</option>
                          <option value="Pompano Beach">Pompano Beach</option>
                          <option value="Sunrise">Sunrise</option>
                          <option value="Tamarac">Tamarac</option>
                          <option value="Weston">Weston</option>
                        </>
                      )}
                      {county === 'Palm Beach' && (
                        <>
                          <option value="Boca Raton">Boca Raton</option>
                          <option value="Boynton Beach">Boynton Beach</option>
                          <option value="Delray Beach">Delray Beach</option>
                          <option value="Lake Worth Beach">Lake Worth Beach</option>
                          <option value="West Palm Beach">West Palm Beach</option>
                        </>
                      )}
                      {county === 'Miami-Dade' && (
                        <>
                          <option value="Hialeah">Hialeah</option>
                          <option value="Homestead">Homestead</option>
                          <option value="Kendall">Kendall (Unincorporated)</option>
                          <option value="Miami">Miami</option>
                          <option value="Miami Gardens">Miami Gardens</option>
                        </>
                      )}
                    </select>
                    <div className="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
                      <svg className="w-5 h-5 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7"/></svg>
                    </div>
                  </div>
                </div>

                {/* Permit Type Select */}
                <div className="relative group">
                  <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-2">Permit Type</label>
                  <div className="relative">
                    <select 
                      value={permitType} 
                      onChange={e => setPermitType(e.target.value)} 
                      disabled={!city}
                      className={`w-full px-4 py-3.5 bg-black/60 border border-gray-700/50 rounded-xl text-white appearance-none cursor-pointer transition-all duration-200 hover:border-gray-600 focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 focus:outline-none ${!city ? 'opacity-50 cursor-not-allowed' : ''}`}
                    >
                      <option value="">{city ? 'Select permit type...' : 'Select city first'}</option>
                      {getPermitTypes().map((pt, i) => (
                        <option key={pt.value || `cat-${i}`} value={pt.value} disabled={pt.disabled}>
                          {pt.label}
                        </option>
                      ))}
                    </select>
                    <div className="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
                      <svg className="w-5 h-5 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7"/></svg>
                    </div>
                  </div>
                </div>
              </div>

              {/* City count indicator */}
              {county && (
                <div className="mb-4 flex items-center gap-2 text-sm">
                  <span className="inline-flex items-center px-2.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
                    <svg className="w-3.5 h-3.5 mr-1.5" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd"/></svg>
                    {county === 'Broward' ? '16 cities' : county === 'Palm Beach' ? '5 cities' : '5 cities'} with expert-level AI knowledge
                  </span>
                </div>
              )}
              <div className="mb-6">
                <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-2">Upload Documents</label>
                <div 
                  className={`border-2 border-dashed rounded-2xl p-8 text-center transition-all duration-200 ${isDragging ? 'border-cyan-400 bg-cyan-500/10 scale-[1.02]' : 'border-gray-700 bg-black/30 hover:border-gray-600'}`} 
                  onDragOver={e => { e.preventDefault(); setIsDragging(true) }} 
                  onDragLeave={() => setIsDragging(false)} 
                  onDrop={e => { e.preventDefault(); setIsDragging(false); handleFiles({ target: { files: e.dataTransfer.files } }) }}
                >
                  {/* Hidden inputs */}
                  <input type="file" multiple onChange={handleFiles} className="hidden" id="fileInput" accept=".pdf,.png,.jpg,.jpeg" />
                  <input type="file" multiple webkitdirectory="" directory="" onChange={handleFiles} className="hidden" id="folderInput" />
                  
                  <div className="w-16 h-16 mx-auto mb-4 bg-gradient-to-br from-cyan-500/20 to-emerald-500/20 rounded-2xl flex items-center justify-center border border-cyan-500/30">
                    <svg className="w-8 h-8 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/>
                    </svg>
                  </div>
                  
                  <p className="font-bold text-white mb-2">Drag & drop files here</p>
                  <p className="text-sm text-gray-500 mb-4">PDF, PNG, JPG • Max 50 files</p>
                  
                  <div className="flex items-center justify-center gap-3">
                    <label htmlFor="fileInput" className="cursor-pointer px-4 py-2 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/30 rounded-lg text-cyan-400 text-sm font-semibold transition-all">
                      <span className="flex items-center gap-2">
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                        Select Files
                      </span>
                    </label>
                    <span className="text-gray-600">or</span>
                    <label htmlFor="folderInput" className="cursor-pointer px-4 py-2 bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/30 rounded-lg text-emerald-400 text-sm font-semibold transition-all">
                      <span className="flex items-center gap-2">
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>
                        Select Folder
                      </span>
                    </label>
                  </div>
                </div>
                
                {validFiles.length > 0 && (
                  <div className="mt-4 p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-xl">
                    <div className="flex justify-between items-center">
                      <span className="text-emerald-400 font-semibold flex items-center gap-2">
                        <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd"/></svg>
                        {validFiles.length} files ready ({formatSize(totalSize)})
                      </span>
                      <button onClick={clearFiles} className="text-red-400 hover:text-red-300 text-sm font-medium transition-colors">Clear all</button>
                    </div>
                  </div>
                )}
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
      <Footer />
      <style>{`
        select option { background: #0a0a0a; color: white; padding: 12px; }
        select option:disabled { color: #6b7280; font-style: italic; }
        select option:checked { background: linear-gradient(to right, #06b6d4, #10b981); color: black; }
        select::-webkit-scrollbar { width: 8px; }
        select::-webkit-scrollbar-track { background: #1f2937; border-radius: 4px; }
        select::-webkit-scrollbar-thumb { background: #4b5563; border-radius: 4px; }
        select::-webkit-scrollbar-thumb:hover { background: #6b7280; }
      `}</style>
    </div>
  )
}