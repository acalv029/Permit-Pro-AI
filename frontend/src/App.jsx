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
const RECAPTCHA_SITE_KEY = import.meta.env.VITE_RECAPTCHA_SITE_KEY || '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI' // Test key as fallback

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
  const [additionalFiles, setAdditionalFiles] = useState([])
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
  const [recaptchaLoaded, setRecaptchaLoaded] = useState(false)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const [newsletterEmail, setNewsletterEmail] = useState('')
  const [newsletterStatus, setNewsletterStatus] = useState('')
  const [viewingAnalysis, setViewingAnalysis] = useState(null)
  const [activeTestimonial, setActiveTestimonial] = useState(0)
  const [showReviewForm, setShowReviewForm] = useState(false)
  const [reviewSubmitting, setReviewSubmitting] = useState(false)
  const [adminReviews, setAdminReviews] = useState([])
  const [publicReviews, setPublicReviews] = useState([])

  // Default testimonials (shown when no user reviews yet)
  const defaultTestimonials = [
    { name: 'ADC Builders', role: 'General Contractor', city: 'Coconut Creek', stars: 5, review_text: 'We run everything through this before we go to the building dept now. Way less back and forth, way less headaches.' },
    { name: 'Peter Calvo', role: 'City Wide Group', city: 'South Florida', stars: 5, review_text: 'Honestly didn\'t think we needed this until we tried it. Now the whole office uses it on every job. Residential, commercial, doesn\'t matter.' },
    { name: 'Carlos M.', role: 'General Contractor', city: 'Fort Lauderdale', stars: 5, review_text: 'It flagged two docs I forgot to include. Would\'ve been another trip to the permit office and like a week wasted. Paid for itself right there.' },
    { name: 'Marc McGowan', role: 'Boat Lift Installers', city: 'Broward County', stars: 5, review_text: 'Marine permitting is a nightmare with all the different agencies. This thing actually knows what each city wants. Been using it for every project.' },
    { name: 'Jennifer Benitez', role: 'Permit Expediter', city: 'Pembroke Pines', stars: 5, review_text: 'I pull permits all day every day and this catches stuff I miss when I\'m moving fast. The city-specific warnings alone are worth it.' },
    { name: 'Sarah T.', role: 'Homeowner', city: 'Coral Springs', stars: 4, review_text: 'First time pulling a permit for my kitchen reno and I had no clue what I needed. This walked me through it. Super helpful.' },
    { name: 'Mike R.', role: 'GC / Owner', city: 'Boca Raton', stars: 5, review_text: 'We do probably 10-15 permits a month. My office manager runs them through Flo before we submit anything now. Saves us so much time.' }
  ]

  // Combine default + user reviews
  const allTestimonials = [...defaultTestimonials, ...publicReviews.filter(r => !r.is_featured)]
  const featuredTestimonials = [
    defaultTestimonials[0], // ADC Builders always first
    ...publicReviews.filter(r => r.is_featured).slice(0, 3),
    ...defaultTestimonials.slice(1, 4 - publicReviews.filter(r => r.is_featured).length)
  ].slice(0, 4)

  // Fetch public reviews on load
  useEffect(() => {
    fetch(`${API_BASE_URL}/api/reviews`)
      .then(res => res.json())
      .then(data => setPublicReviews(data.reviews || []))
      .catch(err => console.error('Error loading reviews:', err))
  }, [])

  // Rotate featured testimonials
  useEffect(() => {
    const interval = setInterval(() => {
      setActiveTestimonial(prev => (prev + 1) % featuredTestimonials.length)
    }, 4000)
    return () => clearInterval(interval)
  }, [featuredTestimonials.length])

  // Load reCAPTCHA script
  useEffect(() => {
    if (window.grecaptcha) {
      setRecaptchaLoaded(true)
      return
    }
    const script = document.createElement('script')
    script.src = `https://www.google.com/recaptcha/api.js?render=${RECAPTCHA_SITE_KEY}`
    script.async = true
    script.onload = () => setRecaptchaLoaded(true)
    document.head.appendChild(script)
  }, [])

  // Helper to get reCAPTCHA token
  const getRecaptchaToken = async (action) => {
    if (!recaptchaLoaded || !window.grecaptcha) return null
    try {
      await window.grecaptcha.ready(() => {})
      return await window.grecaptcha.execute(RECAPTCHA_SITE_KEY, { action })
    } catch (err) {
      console.error('reCAPTCHA error:', err)
      return null
    }
  }

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
      const recaptchaToken = await getRecaptchaToken('login')
      const res = await fetch(`${API_BASE_URL}/api/auth/login`, { 
        method: 'POST', 
        headers: { 'Content-Type': 'application/json' }, 
        body: JSON.stringify({ 
          email: e.target.email.value, 
          password: e.target.password.value,
          recaptcha_token: recaptchaToken
        }) 
      })
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
      const recaptchaToken = await getRecaptchaToken('register')
      const res = await fetch(`${API_BASE_URL}/api/auth/register`, { 
        method: 'POST', 
        headers: { 'Content-Type': 'application/json' }, 
        body: JSON.stringify({ 
          email: e.target.email.value, 
          password: e.target.password.value, 
          full_name: e.target.fullName.value || null, 
          company_name: e.target.company.value || null,
          recaptcha_token: recaptchaToken
        }) 
      })
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
      const data = await res.json(); setResults(data); setPage('results'); setAdditionalFiles([])
    } catch (err) { alert('Error: ' + err.message) } finally { setLoading(false) }
  }

  const reanalyzeWithAdditionalFiles = async () => {
    if (additionalFiles.length === 0 || !results) return
    setLoading(true); setLoadingStatus('Adding new files...')
    try {
      const formData = new FormData()
      formData.append('city', results.city)
      formData.append('permit_type', results.permit_type || 'auto')
      // Add original files if we have them, plus new files
      validFiles.forEach((f) => formData.append('files', f))
      additionalFiles.forEach((f) => formData.append('files', f))
      setLoadingStatus('Re-analyzing with AI...')
      const headers = {}; if (authToken) headers['Authorization'] = `Bearer ${authToken}`
      const res = await fetch(`${API_BASE_URL}/api/analyze-permit-folder`, { method: 'POST', headers, body: formData })
      if (!res.ok) { const err = await res.json().catch(() => ({})); throw new Error(err.detail || 'Analysis failed') }
      const data = await res.json()
      // Merge the additional files into validFiles for future re-analyses
      setValidFiles(prev => [...prev, ...additionalFiles])
      setResults(data)
      setAdditionalFiles([])
    } catch (err) { alert('Error: ' + err.message) } finally { setLoading(false) }
  }

  const loadHistory = async () => { setHistoryLoading(true); try { const res = await fetch(`${API_BASE_URL}/api/history`, { headers: { 'Authorization': `Bearer ${authToken}` } }); if (res.ok) { const data = await res.json(); setHistory(data.analyses || []) } } catch (err) { console.error(err) } finally { setHistoryLoading(false) } }
  const loadAdminStats = async () => { if (!authToken) return; setAdminLoading(true); try { const res = await fetch(`${API_BASE_URL}/api/admin/stats`, { headers: { 'Authorization': `Bearer ${authToken}` } }); if (res.ok) { const data = await res.json(); setAdminStats(data) } } catch (err) { console.error(err) } finally { setAdminLoading(false) } }
  const loadAdminReviews = async () => { if (!authToken) return; try { const res = await fetch(`${API_BASE_URL}/api/admin/reviews`, { headers: { 'Authorization': `Bearer ${authToken}` } }); if (res.ok) { const data = await res.json(); setAdminReviews(data.reviews || []) } } catch (err) { console.error(err) } }
  const submitReview = async (e) => {
    e.preventDefault()
    setReviewSubmitting(true)
    try {
      const form = e.target
      const res = await fetch(`${API_BASE_URL}/api/reviews`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
        body: JSON.stringify({
          name: form.name.value,
          role: form.role.value,
          city: form.city.value,
          stars: parseInt(form.stars.value),
          review_text: form.review_text.value
        })
      })
      if (res.ok) {
        alert('Thank you! Your review has been submitted for approval.')
        setShowReviewForm(false)
        form.reset()
      } else {
        const data = await res.json()
        alert(data.detail || 'Failed to submit review')
      }
    } catch (err) { alert('Error submitting review') }
    finally { setReviewSubmitting(false) }
  }
  const updateReview = async (reviewId, updates) => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/admin/reviews/${reviewId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
        body: JSON.stringify(updates)
      })
      if (res.ok) loadAdminReviews()
    } catch (err) { console.error(err) }
  }
  const deleteReview = async (reviewId) => {
    if (!confirm('Delete this review?')) return
    try {
      const res = await fetch(`${API_BASE_URL}/api/admin/reviews/${reviewId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${authToken}` }
      })
      if (res.ok) loadAdminReviews()
    } catch (err) { console.error(err) }
  }
  const loadProfile = async () => { if (!authToken) return; setProfileLoading(true); try { const res = await fetch(`${API_BASE_URL}/api/profile`, { headers: { 'Authorization': `Bearer ${authToken}` } }); if (res.ok) { const data = await res.json(); setProfile(data) } } catch (err) { console.error(err) } finally { setProfileLoading(false) } }
  const loadSubscription = async () => { if (!authToken) return; try { const res = await fetch(`${API_BASE_URL}/api/subscription`, { headers: { 'Authorization': `Bearer ${authToken}` } }); if (res.ok) { const data = await res.json(); setSubscription(data) } } catch (err) { console.error(err) } }
  const updateProfile = async (data) => { try { const res = await fetch(`${API_BASE_URL}/api/profile`, { method: 'PUT', headers: { 'Authorization': `Bearer ${authToken}`, 'Content-Type': 'application/json' }, body: JSON.stringify(data) }); if (res.ok) { await loadProfile(); setEditingProfile(false) } } catch (err) { alert('Error updating profile') } }
  const viewAnalysis = async (uuid) => { setViewingAnalysis(uuid); try { const res = await fetch(`${API_BASE_URL}/api/history/${uuid}`, { headers: { 'Authorization': `Bearer ${authToken}` } }); if (res.ok) { const data = await res.json(); setResults({ city: data.city, permit_type: data.permit_type, files_analyzed: data.files_analyzed, file_tree: data.file_list, analysis: data.analysis }); setPage('results') } } catch (err) { alert('Error loading analysis') } finally { setViewingAnalysis(null) } }
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
        if (['Fort Lauderdale', 'Pompano Beach', 'Hollywood', 'Coral Springs', 'Coconut Creek', 'Davie', 'Deerfield Beach', 'Lauderdale-by-the-Sea', 'Lighthouse Point', 'Margate', 'Miramar', 'Oakland Park', 'Pembroke Pines', 'Plantation', 'Sunrise', 'Tamarac', 'Weston'].includes(data.city)) {
          setCounty('Broward')
        } else if (['Boca Raton', 'Boynton Beach', 'Delray Beach', 'Lake Worth Beach', 'West Palm Beach'].includes(data.city)) {
          setCounty('Palm Beach')
        } else {
          setCounty('Miami-Dade')
        }
      }
    } catch (err) { console.error('Error loading purchase:', err) }
  }

  useEffect(() => { if (page === 'history' && authToken) loadHistory(); if (page === 'profile' && authToken) { loadProfile(); loadSubscription() }; if (page === 'admin' && authToken && isAdmin) { loadAdminStats(); loadAdminReviews() }; if (page === 'pricing' && authToken) loadSubscription(); setMobileMenuOpen(false); window.scrollTo(0, 0) }, [page])

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
        <div className="flex items-center gap-3" onClick={() => { setPage('home'); setResults(null); setMobileMenuOpen(false) }}>
          <div className="w-11 h-11 rounded-xl overflow-hidden">
            <img src="/adc_logo.png" alt="Flo Permit" className="w-full h-full object-contain" />
          </div>
          <div><h1 className="text-xl font-black"><span className="text-cyan-400">Flo</span> <span className="text-white">Permit</span></h1><p className="text-xs text-cyan-500 font-semibold">SOUTH FLORIDA</p></div>
        </div>
        
        {/* Desktop Nav */}
        <div className="hidden md:flex items-center gap-4">
          {showBack && <button onClick={() => setPage('home')} className="text-gray-400 hover:text-white">← Back</button>}
          {!showBack && currentUser && (<>{isAdmin && <button onClick={() => setPage('admin')} className="text-sm font-semibold text-purple-400 hover:text-purple-300">Admin</button>}<button onClick={() => { setPage('home'); setResults(null) }} className="text-sm font-semibold text-gray-400 hover:text-cyan-400">Home</button><button onClick={() => setPage('how-it-works')} className="text-sm font-semibold text-gray-400 hover:text-cyan-400">How It Works</button><button onClick={() => setPage('pricing')} className="text-sm font-semibold text-gray-400 hover:text-cyan-400">Pricing</button><button onClick={() => setPage('profile')} className="text-sm font-semibold text-gray-400 hover:text-cyan-400">Profile</button><button onClick={() => setPage('history')} className="text-sm font-semibold text-gray-400 hover:text-cyan-400">History</button><button onClick={logout} className="text-sm text-red-400 hover:text-red-300">Logout</button></>)}
          {!showBack && !currentUser && (<><button onClick={() => setPage('pricing')} className="text-sm font-semibold text-gray-400 hover:text-cyan-400">Pricing</button><button onClick={() => setPage('faq')} className="text-sm font-semibold text-gray-400 hover:text-cyan-400">FAQ</button><button onClick={() => setShowLogin(true)} className="text-sm font-semibold text-gray-400 hover:text-cyan-400">Log In</button><button onClick={() => setShowRegister(true)} className="relative group"><div className="absolute -inset-0.5 bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-xl blur opacity-60 group-hover:opacity-100"></div><div className="relative px-5 py-2.5 bg-black text-white text-sm font-bold rounded-xl">Sign Up</div></button></>)}
        </div>

        {/* Mobile Hamburger */}
        <button className="md:hidden relative w-8 h-8 flex flex-col items-center justify-center gap-1.5" onClick={() => setMobileMenuOpen(!mobileMenuOpen)}>
          <span className={`w-6 h-0.5 bg-white transition-all duration-300 ${mobileMenuOpen ? 'rotate-45 translate-y-2' : ''}`}></span>
          <span className={`w-6 h-0.5 bg-white transition-all duration-300 ${mobileMenuOpen ? 'opacity-0' : ''}`}></span>
          <span className={`w-6 h-0.5 bg-white transition-all duration-300 ${mobileMenuOpen ? '-rotate-45 -translate-y-2' : ''}`}></span>
        </button>
      </div>

      {/* Mobile Menu Dropdown */}
      {mobileMenuOpen && (
        <div className="md:hidden bg-gray-900/95 backdrop-blur-xl border-t border-gray-800 px-6 py-4 space-y-3">
          {showBack && <button onClick={() => { setPage('home'); setMobileMenuOpen(false) }} className="block w-full text-left text-gray-300 hover:text-cyan-400 py-2">← Back</button>}
          {!showBack && currentUser && (
            <>
              {isAdmin && <button onClick={() => { setPage('admin'); setMobileMenuOpen(false) }} className="block w-full text-left text-purple-400 hover:text-purple-300 py-2 font-semibold">Admin</button>}
              <button onClick={() => { setPage('home'); setResults(null); setMobileMenuOpen(false) }} className="block w-full text-left text-gray-300 hover:text-cyan-400 py-2">Home</button>
              <button onClick={() => { setPage('how-it-works'); setMobileMenuOpen(false) }} className="block w-full text-left text-gray-300 hover:text-cyan-400 py-2">How It Works</button>
              <button onClick={() => { setPage('pricing'); setMobileMenuOpen(false) }} className="block w-full text-left text-gray-300 hover:text-cyan-400 py-2">Pricing</button>
              <button onClick={() => { setPage('profile'); setMobileMenuOpen(false) }} className="block w-full text-left text-gray-300 hover:text-cyan-400 py-2">Profile</button>
              <button onClick={() => { setPage('history'); setMobileMenuOpen(false) }} className="block w-full text-left text-gray-300 hover:text-cyan-400 py-2">History</button>
              <div className="border-t border-gray-800 pt-3 mt-3">
                <button onClick={() => { logout(); setMobileMenuOpen(false) }} className="block w-full text-left text-red-400 hover:text-red-300 py-2">Logout</button>
              </div>
            </>
          )}
          {!showBack && !currentUser && (
            <>
              <button onClick={() => { setPage('how-it-works'); setMobileMenuOpen(false) }} className="block w-full text-left text-gray-300 hover:text-cyan-400 py-2">How It Works</button>
              <button onClick={() => { setPage('pricing'); setMobileMenuOpen(false) }} className="block w-full text-left text-gray-300 hover:text-cyan-400 py-2">Pricing</button>
              <button onClick={() => { setPage('faq'); setMobileMenuOpen(false) }} className="block w-full text-left text-gray-300 hover:text-cyan-400 py-2">FAQ</button>
              <button onClick={() => { setPage('about'); setMobileMenuOpen(false) }} className="block w-full text-left text-gray-300 hover:text-cyan-400 py-2">About</button>
              <button onClick={() => { setPage('contact'); setMobileMenuOpen(false) }} className="block w-full text-left text-gray-300 hover:text-cyan-400 py-2">Contact</button>
              <div className="border-t border-gray-800 pt-3 mt-3 flex gap-3">
                <button onClick={() => { setShowLogin(true); setMobileMenuOpen(false) }} className="flex-1 py-2.5 border border-gray-700 text-white font-semibold rounded-xl hover:bg-gray-800 text-sm">Log In</button>
                <button onClick={() => { setShowRegister(true); setMobileMenuOpen(false) }} className="flex-1 py-2.5 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl text-sm">Sign Up</button>
              </div>
            </>
          )}
        </div>
      )}
    </nav>
  )

  const Footer = () => (
    <footer className="relative z-10 border-t border-gray-800 bg-black/50 mt-auto">
      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* Newsletter Section */}
        <div className="mb-8 p-6 bg-gradient-to-r from-cyan-500/5 to-emerald-500/5 border border-gray-800 rounded-2xl">
          <div className="max-w-xl mx-auto text-center">
            <h3 className="text-lg font-bold text-white mb-2">Stay Updated</h3>
            <p className="text-gray-500 text-sm mb-4">Get permit tips, new city announcements, and product updates. No spam, ever.</p>
            <div className="flex gap-2 max-w-md mx-auto">
              <input 
                type="email" 
                placeholder="Enter your email" 
                value={newsletterEmail}
                onChange={(e) => setNewsletterEmail(e.target.value)}
                className="flex-1 px-4 py-2.5 bg-black/50 border border-gray-700 rounded-xl text-white text-sm placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
              />
              <button 
                onClick={() => {
                  if (newsletterEmail && newsletterEmail.includes('@')) {
                    setNewsletterStatus('success')
                    setNewsletterEmail('')
                    setTimeout(() => setNewsletterStatus(''), 3000)
                  }
                }}
                className="px-5 py-2.5 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl text-sm hover:scale-105 transition-transform whitespace-nowrap"
              >
                Subscribe
              </button>
            </div>
            {newsletterStatus === 'success' && <p className="text-emerald-400 text-sm mt-2">Thanks for subscribing! 🎉</p>}
          </div>
        </div>

        <div className="grid md:grid-cols-4 gap-8 mb-8">
          <div><div className="flex items-center gap-2 mb-4"><div className="w-8 h-8 rounded-lg overflow-hidden"><img src="/adc_logo.png" alt="Flo Permit" className="w-full h-full object-contain" /></div><span className="font-bold"><span className="text-cyan-400">Flo</span> <span className="text-white">Permit</span></span></div><p className="text-gray-500 text-sm">AI-powered permit analysis for South Florida contractors and homeowners.</p></div>
          <div><h4 className="font-semibold text-white mb-4">Product</h4><ul className="space-y-2"><li><button onClick={() => setPage('home')} className="text-gray-500 hover:text-cyan-400 text-sm">Analyze Permits</button></li><li><button onClick={() => setPage('how-it-works')} className="text-gray-500 hover:text-cyan-400 text-sm">How It Works</button></li><li><button onClick={() => setPage('pricing')} className="text-gray-500 hover:text-cyan-400 text-sm">Pricing</button></li><li><button onClick={() => setPage('about')} className="text-gray-500 hover:text-cyan-400 text-sm">About Us</button></li><li><button onClick={() => setPage('faq')} className="text-gray-500 hover:text-cyan-400 text-sm">FAQ</button></li></ul></div>
          <div><h4 className="font-semibold text-white mb-4">Legal</h4><ul className="space-y-2"><li><button onClick={() => setPage('terms')} className="text-gray-500 hover:text-cyan-400 text-sm">Terms & Conditions</button></li><li><button onClick={() => setPage('privacy')} className="text-gray-500 hover:text-cyan-400 text-sm">Privacy Policy</button></li></ul></div>
          <div><h4 className="font-semibold text-white mb-4">Support</h4><ul className="space-y-2"><li><button onClick={() => setPage('contact')} className="text-gray-500 hover:text-cyan-400 text-sm">Contact Us</button></li><li><button onClick={() => setPage('faq')} className="text-gray-500 hover:text-cyan-400 text-sm">FAQ</button></li><li><a href="mailto:support@flopermit.com" className="text-gray-500 hover:text-cyan-400 text-sm">support@flopermit.com</a></li></ul></div>
        </div>
        <div className="border-t border-gray-800 pt-6 flex flex-col md:flex-row items-center justify-between gap-4"><p className="text-gray-500 text-sm">© 2026 Flo Permit. All rights reserved.</p><p className="text-gray-600 text-xs">Serving South Florida</p></div>
      </div>
    </footer>
  )

  if (page === 'how-it-works') return (
    <div className="min-h-screen bg-black text-white flex flex-col">
      <div className="fixed inset-0 z-0"><div className="absolute inset-0 bg-gradient-to-br from-black via-gray-900 to-black"></div></div>
      <NavBar showBack />
      <div className="relative z-10 pt-24 px-6 pb-12 flex-grow">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <h1 className="text-4xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent mb-4">How It Works</h1>
            <p className="text-gray-400">Understanding your permit analysis results</p>
          </div>
          
          <div className="space-y-8">
            {/* Step 1: Upload */}
            <div className="bg-gray-900/80 rounded-2xl p-8 border border-gray-800">
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 bg-cyan-500/20 rounded-xl flex items-center justify-center flex-shrink-0">
                  <span className="text-2xl font-black text-cyan-400">1</span>
                </div>
                <div>
                  <h2 className="text-xl font-bold text-white mb-2">Upload Your Documents</h2>
                  <p className="text-gray-400 mb-4">Drag and drop your permit package files or folders. We accept PDFs, images, and common document formats. Our AI will analyze everything together as a complete package.</p>
                  <div className="flex flex-wrap gap-2">
                    <span className="px-3 py-1 bg-gray-800 rounded-full text-xs text-gray-400">.pdf</span>
                    <span className="px-3 py-1 bg-gray-800 rounded-full text-xs text-gray-400">.jpg/.png</span>
                    <span className="px-3 py-1 bg-gray-800 rounded-full text-xs text-gray-400">.doc/.docx</span>
                    <span className="px-3 py-1 bg-gray-800 rounded-full text-xs text-gray-400">.tif/.tiff</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Step 2: AI Analysis */}
            <div className="bg-gray-900/80 rounded-2xl p-8 border border-gray-800">
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 bg-emerald-500/20 rounded-xl flex items-center justify-center flex-shrink-0">
                  <span className="text-2xl font-black text-emerald-400">2</span>
                </div>
                <div>
                  <h2 className="text-xl font-bold text-white mb-2">AI Analyzes Your Package</h2>
                  <p className="text-gray-400">Our AI reads every document, identifies what you have, and compares it against what your city requires. It automatically detects the permit type (roofing, HVAC, plumbing, etc.) from your documents.</p>
                </div>
              </div>
            </div>

            {/* Compliance Score */}
            <div className="bg-gray-900/80 rounded-2xl p-8 border border-gray-800">
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 bg-gradient-to-br from-emerald-500/20 to-cyan-500/20 rounded-xl flex items-center justify-center flex-shrink-0">
                  <svg className="w-6 h-6 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>
                </div>
                <div>
                  <h2 className="text-xl font-bold text-white mb-2">Compliance Score</h2>
                  <p className="text-gray-400 mb-4">Your compliance score shows how ready your package is for submission:</p>
                  <div className="grid md:grid-cols-3 gap-4">
                    <div className="p-4 bg-emerald-500/10 border border-emerald-500/30 rounded-xl">
                      <div className="text-2xl font-black text-emerald-400 mb-1">90-100%</div>
                      <div className="text-sm text-emerald-300">Ready to Submit</div>
                      <p className="text-xs text-gray-500 mt-2">All required documents present and properly executed</p>
                    </div>
                    <div className="p-4 bg-amber-500/10 border border-amber-500/30 rounded-xl">
                      <div className="text-2xl font-black text-amber-400 mb-1">50-89%</div>
                      <div className="text-sm text-amber-300">Needs Attention</div>
                      <p className="text-xs text-gray-500 mt-2">Some documents missing or issues to fix</p>
                    </div>
                    <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-xl">
                      <div className="text-2xl font-black text-red-400 mb-1">Below 50%</div>
                      <div className="text-sm text-red-300">Incomplete</div>
                      <p className="text-xs text-gray-500 mt-2">Major documents missing, not ready for submission</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Document Checklist */}
            <div className="bg-gray-900/80 rounded-2xl p-8 border border-gray-800">
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 bg-cyan-500/20 rounded-xl flex items-center justify-center flex-shrink-0">
                  <svg className="w-6 h-6 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/></svg>
                </div>
                <div className="flex-1">
                  <h2 className="text-xl font-bold text-white mb-2">Document Checklist</h2>
                  <p className="text-gray-400 mb-4">See exactly what you have and what you're missing:</p>
                  <div className="space-y-3">
                    <div className="flex items-center gap-3 p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
                      <div className="w-5 h-5 border-2 border-red-400 rounded flex-shrink-0 flex items-center justify-center">
                        <svg className="w-3 h-3 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="3" d="M6 18L18 6M6 6l12 12"/></svg>
                      </div>
                      <span className="text-white font-medium">Missing Document Example</span>
                      <span className="ml-auto text-xs text-red-400 font-semibold">NEEDED</span>
                    </div>
                    <div className="flex items-center gap-3 p-3 bg-gray-800/30 rounded-lg opacity-60">
                      <div className="w-5 h-5 bg-emerald-500/20 border border-emerald-500/50 rounded flex-shrink-0 flex items-center justify-center">
                        <svg className="w-3 h-3 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="3" d="M5 13l4 4L19 7"/></svg>
                      </div>
                      <span className="text-gray-400">Found Document Example</span>
                      <span className="ml-auto text-xs text-emerald-500">✓ Found</span>
                    </div>
                  </div>
                  <p className="text-sm text-gray-500 mt-4">Missing documents appear at the top in white so you can quickly see what's needed. Found documents are faded at the bottom.</p>
                </div>
              </div>
            </div>

            {/* Critical Issues */}
            <div className="bg-gray-900/80 rounded-2xl p-8 border border-gray-800">
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 bg-red-500/20 rounded-xl flex items-center justify-center flex-shrink-0">
                  <svg className="w-6 h-6 text-red-400" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd"/></svg>
                </div>
                <div>
                  <h2 className="text-xl font-bold text-white mb-2">Critical Issues</h2>
                  <p className="text-gray-400 mb-4">Problems that will likely cause your permit to be rejected:</p>
                  <ul className="space-y-2 text-gray-400">
                    <li className="flex items-start gap-2"><span className="text-red-400">•</span>Missing signatures or seals on drawings</li>
                    <li className="flex items-start gap-2"><span className="text-red-400">•</span>Expired documents (surveys over 1 year old)</li>
                    <li className="flex items-start gap-2"><span className="text-red-400">•</span>Missing product approvals (NOAs) for exterior products</li>
                    <li className="flex items-start gap-2"><span className="text-red-400">•</span>Required pre-approvals not obtained (EPD, DERM, etc.)</li>
                  </ul>
                </div>
              </div>
            </div>

            {/* City-Specific Warnings */}
            <div className="bg-gray-900/80 rounded-2xl p-8 border border-gray-800">
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 bg-amber-500/20 rounded-xl flex items-center justify-center flex-shrink-0">
                  <svg className="w-6 h-6 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                </div>
                <div>
                  <h2 className="text-xl font-bold text-white mb-2">City-Specific Warnings</h2>
                  <p className="text-gray-400 mb-4">Every city has their own quirks and common rejection reasons. We know them all:</p>
                  <ul className="space-y-2 text-gray-400">
                    <li className="flex items-start gap-2"><span className="text-amber-400">•</span><strong className="text-white">Fort Lauderdale:</strong> NOC threshold is $5,000, circle (don't highlight) NOA info</li>
                    <li className="flex items-start gap-2"><span className="text-amber-400">•</span><strong className="text-white">Pompano Beach:</strong> BLACK INK only, all applications require Fire Review</li>
                    <li className="flex items-start gap-2"><span className="text-amber-400">•</span><strong className="text-white">Miami-Dade:</strong> DERM approval required BEFORE building permit</li>
                    <li className="flex items-start gap-2"><span className="text-amber-400">•</span><strong className="text-white">Lighthouse Point:</strong> NO owner/builder for roofing or electrical</li>
                  </ul>
                </div>
              </div>
            </div>

            {/* Add More Files */}
            <div className="bg-gray-900/80 rounded-2xl p-8 border border-cyan-500/30">
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 bg-cyan-500/20 rounded-xl flex items-center justify-center flex-shrink-0">
                  <svg className="w-6 h-6 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"/></svg>
                </div>
                <div>
                  <h2 className="text-xl font-bold text-white mb-2">Add Missing Documents & Re-Analyze</h2>
                  <p className="text-gray-400 mb-4">Don't start over! When you see missing documents in your results:</p>
                  <ol className="space-y-2 text-gray-400 list-decimal list-inside">
                    <li>Click <strong className="text-cyan-400">"+ Add Files"</strong> or <strong className="text-cyan-400">"+ Add Folder"</strong> at the bottom of your results</li>
                    <li>Select the missing documents from your computer</li>
                    <li>Click <strong className="text-cyan-400">"Update Analysis"</strong></li>
                    <li>Your checklist updates automatically - watch items move from "NEEDED" to "Found"!</li>
                  </ol>
                  <p className="text-sm text-emerald-400 mt-4">💡 This saves you time and helps you build a complete package step by step.</p>
                </div>
              </div>
            </div>

            {/* CTA */}
            <div className="text-center pt-8">
              <button onClick={() => setPage('home')} className="px-8 py-4 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl hover:scale-105 transition-transform text-lg">
                Try It Now - Analyze Your Permits
              </button>
              <p className="text-gray-500 text-sm mt-4">3 free analyses, no credit card required</p>
            </div>
          </div>
        </div>
      </div>
      <Footer />
    </div>
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
              { q: "Which cities do you support?", a: "We support 30 cities across Broward, Palm Beach, and Miami-Dade counties including Fort Lauderdale, Miami, Miami Beach, Boca Raton, Hollywood, Wellington, Pompano Beach, Hialeah, Coral Springs, Oakland Park, and many more!" },
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


  // === TERMS AND CONDITIONS PAGE ===
  if (page === 'terms') return (
    <div className="min-h-screen bg-black text-white flex flex-col">
      <div className="fixed inset-0 z-0"><div className="absolute inset-0 bg-gradient-to-br from-black via-gray-900 to-black"></div></div>
      <NavBar showBack />
      <div className="relative z-10 pt-24 px-6 pb-12 flex-grow">
        <div className="max-w-3xl mx-auto">
          <div className="text-center mb-12">
            <h1 className="text-4xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent mb-4">Terms and Conditions</h1>
            <p className="text-gray-400">Last updated: February 02, 2026</p>
          </div>
          
          {/* Permit Disclaimer - stays separate and prominent */}
          <div className="bg-amber-500/10 border-2 border-amber-500/40 rounded-2xl p-8 mb-8">
            <h2 className="text-2xl font-black text-amber-400 mb-4">{"⚠️"} SERVICE DISCLAIMER — PLEASE READ</h2>
            <p className="text-gray-200 mb-4 font-semibold">Flo Permit provides AI-powered permit document analysis for informational purposes only.</p>
            <p className="text-gray-300 mb-4 font-bold uppercase">By using this service, you acknowledge and agree that:</p>
            <ul className="space-y-3 text-gray-300">
              <li className="flex gap-3"><span className="text-amber-400 font-bold shrink-0">1.</span>Flo Permit does <strong className="text-white">NOT guarantee</strong> that your permit application will be approved by any government agency or permitting office.</li>
              <li className="flex gap-3"><span className="text-amber-400 font-bold shrink-0">2.</span>Our analysis is generated by artificial intelligence and <strong className="text-white">may contain errors, omissions, or inaccuracies</strong>.</li>
              <li className="flex gap-3"><span className="text-amber-400 font-bold shrink-0">3.</span>Permit requirements vary by jurisdiction and <strong className="text-white">change frequently</strong>. Our database may not reflect the most current requirements.</li>
              <li className="flex gap-3"><span className="text-amber-400 font-bold shrink-0">4.</span>You are <strong className="text-white">solely responsible</strong> for verifying all requirements with your local permitting office before submission.</li>
              <li className="flex gap-3"><span className="text-amber-400 font-bold shrink-0">5.</span>Flo Permit is <strong className="text-white">NOT</strong> a licensed contractor, architect, engineer, or permit consultant.</li>
              <li className="flex gap-3"><span className="text-amber-400 font-bold shrink-0">6.</span>Our service does <strong className="text-white">NOT</strong> constitute professional, legal, engineering, architectural, or expert advice of any kind.</li>
              <li className="flex gap-3"><span className="text-amber-400 font-bold shrink-0">7.</span>We are <strong className="text-white">NOT liable</strong> for permit denials, project delays, fines, penalties, or any damages resulting from reliance on our analysis.</li>
              <li className="flex gap-3"><span className="text-amber-400 font-bold shrink-0">8.</span>Compliance scores and checklists are <strong className="text-white">estimates only</strong> and should not be treated as definitive assessments.</li>
            </ul>
            <div className="mt-6 p-4 bg-amber-500/10 rounded-xl">
              <p className="text-amber-300 font-bold text-center">Always consult with qualified professionals and your local building department before submitting permit applications.</p>
            </div>
          </div>

          {/* All terms in one block */}
          <div className="bg-gray-900/80 rounded-2xl p-8 md:p-10 border border-gray-800 text-gray-400 space-y-8">
            <p>Please read these terms and conditions carefully before using Our Service.</p>

            <div>
              <h2 className="text-xl font-bold text-white mb-3">Interpretation and Definitions</h2>
              <p className="mb-4">The words whose initial letters are capitalized have meanings defined under the following conditions. The following definitions shall have the same meaning regardless of whether they appear in singular or in plural.</p>
              <p className="mb-3">For the purposes of these Terms and Conditions:</p>
              <ul className="space-y-2 ml-4">
                <li><strong className="text-gray-300">Application</strong> means the software program provided by the Company, named Flo Permit.</li>
                <li><strong className="text-gray-300">Account</strong> means a unique account created for You to access our Service or parts of our Service.</li>
                <li><strong className="text-gray-300">Company</strong> (referred to as either {"\""}the Company{"\""}, {"\""}We{"\""}, {"\""}Us{"\""} or {"\""}Our{"\""}) refers to ADC Builders, 6740 NW 25th Way.</li>
                <li><strong className="text-gray-300">Content</strong> refers to content such as text, images, or other information that can be posted, uploaded, linked to or otherwise made available by You.</li>
                <li><strong className="text-gray-300">Country</strong> refers to: Florida, United States.</li>
                <li><strong className="text-gray-300">Device</strong> means any device that can access the Service such as a computer, a cell phone or a digital tablet.</li>
                <li><strong className="text-gray-300">Feedback</strong> means feedback, innovations or suggestions sent by You regarding the attributes, performance or features of our Service.</li>
                <li><strong className="text-gray-300">In-app Purchase</strong> refers to the purchase of a product, item, service or Subscription made through the Application.</li>
                <li><strong className="text-gray-300">Service</strong> refers to the Application or the Website or both.</li>
                <li><strong className="text-gray-300">Subscriptions</strong> refer to the services or access to the Service offered on a subscription basis by the Company to You.</li>
                <li><strong className="text-gray-300">Terms and Conditions</strong> means these Terms and Conditions that form the entire agreement between You and the Company regarding the Service.</li>
                <li><strong className="text-gray-300">Website</strong> refers to Flo Permit, accessible from <a href="https://flopermit.vercel.app" className="text-cyan-400 hover:underline">https://flopermit.vercel.app</a>.</li>
                <li><strong className="text-gray-300">You</strong> means the individual accessing or using the Service, or the company, or other legal entity on behalf of which such individual is accessing or using the Service.</li>
              </ul>
            </div>

            <div>
              <h2 className="text-xl font-bold text-white mb-3">Acknowledgment</h2>
              <p className="mb-3">These are the Terms and Conditions governing the use of this Service and the agreement between You and the Company. Your access to and use of the Service is conditioned on Your acceptance of and compliance with these Terms and Conditions. By accessing or using the Service You agree to be bound by these Terms and Conditions. If You disagree with any part then You may not access the Service.</p>
              <p className="mb-3">You represent that you are over the age of 18. The Company does not permit those under 18 to use the Service.</p>
              <p>Your access to and use of the Service is also subject to Our <button onClick={() => setPage('privacy')} className="text-cyan-400 hover:underline">Privacy Policy</button>. Please read it carefully before using Our Service.</p>
            </div>

            <div>
              <h2 className="text-xl font-bold text-white mb-3">Subscriptions</h2>
              <p className="mb-3"><strong className="text-gray-300">Subscription Period:</strong> The Service or some parts of the Service are available only with a paid Subscription. You will be billed in advance on a recurring and periodic basis depending on the type of Subscription plan you select. At the end of each period, Your Subscription will automatically renew under the exact same conditions unless You cancel it or the Company cancels it.</p>
              <p className="mb-3"><strong className="text-gray-300">Cancellations:</strong> You may cancel Your Subscription renewal either through Your Account settings page or by contacting the Company. You will not receive a refund for fees already paid for Your current Subscription period and You will be able to access the Service until the end of Your current Subscription period.</p>
              <p className="mb-3"><strong className="text-gray-300">Billing:</strong> You shall provide the Company with accurate and complete billing information. Should automatic billing fail, the Company will issue an electronic invoice indicating that you must proceed manually with payment.</p>
              <p className="mb-3"><strong className="text-gray-300">Fee Changes:</strong> The Company may modify Subscription fees at any time. Changes become effective at the end of the then-current Subscription period with reasonable prior notice.</p>
              <p><strong className="text-gray-300">Refunds:</strong> Except when required by law, paid Subscription fees are non-refundable. Certain refund requests may be considered on a case-by-case basis at the sole discretion of the Company.</p>
            </div>

            <div>
              <h2 className="text-xl font-bold text-white mb-3">In-app Purchases</h2>
              <p className="mb-3">The Application may include In-app Purchases that allow you to buy products, services or Subscriptions. In-app Purchases can only be consumed within the Application and cannot be cancelled after purchase or redeemed for cash.</p>
              <p>In the unlikely event that we are unable to deliver the relevant In-app Purchase within a reasonable period of time, We will authorize a refund up to the cost of the relevant In-app Purchase. All billing and transaction processes are handled by our payment processor.</p>
            </div>

            <div>
              <h2 className="text-xl font-bold text-white mb-3">User Accounts</h2>
              <p className="mb-3">When You create an Account with Us, You must provide information that is accurate, complete, and current at all times. Failure to do so constitutes a breach of the Terms, which may result in immediate termination of Your Account.</p>
              <p>You are responsible for safeguarding Your password and for any activities under Your Account. You agree not to disclose Your password to any third party and must notify Us immediately upon becoming aware of any breach of security or unauthorized use.</p>
            </div>

            <div>
              <h2 className="text-xl font-bold text-white mb-3">Content</h2>
              <p className="mb-3">Our Service allows You to upload Content. You are responsible for the Content that You post, including its legality, reliability, and appropriateness. By posting Content, You grant Us the right and license to use, modify, reproduce, and distribute such Content on and through the Service. You retain all of Your rights to any Content You submit.</p>
              <p className="mb-3">You may not transmit any Content that is unlawful, offensive, threatening, libelous, defamatory, obscene or otherwise objectionable, including content promoting unlawful activity, spam, viruses or malware, content infringing on proprietary rights, or impersonation of any person or entity.</p>
              <p>Although regular backups of Content are performed, the Company does not guarantee there will be no loss or corruption of data. You agree to maintain a complete and accurate copy of any Content in a location independent of the Service.</p>
            </div>

            <div>
              <h2 className="text-xl font-bold text-white mb-3">Copyright Policy</h2>
              <p className="mb-3">We respect the intellectual property rights of others. If You believe that copyrighted work has been infringed through the Service, submit Your DMCA notice in writing to <a href="mailto:support@flopermit.com" className="text-cyan-400 hover:underline">support@flopermit.com</a> including: an electronic or physical signature of the authorized person, a description of the copyrighted work, identification of the infringing material, your contact information, a good faith statement, and a statement under penalty of perjury that the information is accurate.</p>
            </div>

            <div>
              <h2 className="text-xl font-bold text-white mb-3">Intellectual Property</h2>
              <p>The Service and its original content, features and functionality are and will remain the exclusive property of the Company and its licensors. Our trademarks and trade dress may not be used without prior written consent.</p>
            </div>

            <div>
              <h2 className="text-xl font-bold text-white mb-3">Your Feedback to Us</h2>
              <p>You assign all rights, title and interest in any Feedback You provide the Company. If such assignment is ineffective, You grant the Company a non-exclusive, perpetual, irrevocable, royalty free, worldwide license to use, reproduce, disclose, sub-license, distribute, modify and exploit such Feedback without restriction.</p>
            </div>

            <div>
              <h2 className="text-xl font-bold text-white mb-3">Links to Other Websites</h2>
              <p>Our Service may contain links to third-party websites or services not owned or controlled by the Company. The Company has no control over, and assumes no responsibility for, the content, privacy policies, or practices of any third-party websites or services.</p>
            </div>

            <div>
              <h2 className="text-xl font-bold text-white mb-3">Termination</h2>
              <p className="mb-3">We may terminate or suspend Your Account immediately, without prior notice or liability, for any reason whatsoever, including if You breach these Terms. Upon termination, Your right to use the Service will cease immediately.</p>
              <p>If We terminate Your Subscription for convenience (and not due to Your breach), We will refund any prepaid fees covering the remainder of the term.</p>
            </div>

            <div>
              <h2 className="text-xl font-bold text-white mb-3">Limitation of Liability</h2>
              <p className="mb-3 text-gray-300">The entire liability of the Company shall be limited to the amount actually paid by You through the Service or 100 USD if You have not purchased anything.</p>
              <p className="text-gray-300">To the maximum extent permitted by applicable law, in no event shall the Company be liable for any special, incidental, indirect, or consequential damages whatsoever, including damages for loss of profits, loss of data, business interruption, personal injury, loss of privacy, permit denials, project delays, construction delays, fines from permitting authorities, or any damages arising from use of or inability to use the Service. Some states do not allow these exclusions; in those states, liability will be limited to the greatest extent permitted by law.</p>
            </div>

            <div>
              <h2 className="text-xl font-bold text-white mb-3">{"\""}AS IS{"\""} and {"\""}AS AVAILABLE{"\""} Disclaimer</h2>
              <p className="text-gray-300">The Service is provided {"\""}AS IS{"\""} and {"\""}AS AVAILABLE{"\""} without warranty of any kind. The Company expressly disclaims all warranties, whether express, implied, statutory or otherwise, including all implied warranties of merchantability, fitness for a particular purpose, title and non-infringement. The Company makes no representation that the Service will meet Your requirements, achieve any intended results, be compatible with any other software, operate without interruption, or be error free.</p>
            </div>

            <div>
              <h2 className="text-xl font-bold text-white mb-3">Governing Law</h2>
              <p>The laws of the Country, excluding its conflicts of law rules, shall govern these Terms and Your use of the Service.</p>
            </div>

            <div>
              <h2 className="text-xl font-bold text-white mb-3">Disputes Resolution</h2>
              <p>If You have any concern or dispute about the Service, You agree to first try to resolve the dispute informally by contacting the Company.</p>
            </div>

            <div>
              <h2 className="text-xl font-bold text-white mb-3">United States Legal Compliance</h2>
              <p>You represent and warrant that (i) You are not located in a country subject to a United States government embargo or designated as a {"\""}terrorist supporting{"\""} country, and (ii) You are not listed on any United States government list of prohibited or restricted parties.</p>
            </div>

            <div>
              <h2 className="text-xl font-bold text-white mb-3">Severability and Waiver</h2>
              <p className="mb-3">If any provision of these Terms is held to be unenforceable or invalid, such provision will be changed and interpreted to accomplish its objectives to the greatest extent possible under applicable law and the remaining provisions will continue in full force and effect.</p>
              <p>The failure to exercise a right or to require performance of an obligation under these Terms shall not affect a party{"'"}s ability to exercise such right at any time thereafter nor shall the waiver of a breach constitute a waiver of any subsequent breach.</p>
            </div>

            <div>
              <h2 className="text-xl font-bold text-white mb-3">Changes to These Terms</h2>
              <p>We reserve the right to modify or replace these Terms at any time. If a revision is material We will provide at least 30 days{"'"} notice. By continuing to access the Service after revisions become effective, You agree to be bound by the revised terms.</p>
            </div>

            <div>
              <h2 className="text-xl font-bold text-white mb-3">Contact Us</h2>
              <p>If you have any questions about these Terms and Conditions, You can contact us by email at <a href="mailto:support@flopermit.com" className="text-cyan-400 hover:underline">support@flopermit.com</a> or by visiting our <button onClick={() => setPage('contact')} className="text-cyan-400 hover:underline">Contact page</button>.</p>
            </div>
          </div>
        </div>
      </div>
      <Footer />
    </div>
  )

  // === PRIVACY POLICY PAGE ===
  if (page === 'privacy') return (
    <div className="min-h-screen bg-black text-white flex flex-col">
      <div className="fixed inset-0 z-0"><div className="absolute inset-0 bg-gradient-to-br from-black via-gray-900 to-black"></div></div>
      <NavBar showBack />
      <div className="relative z-10 pt-24 px-6 pb-12 flex-grow">
        <div className="max-w-3xl mx-auto">
          <div className="text-center mb-12">
            <h1 className="text-4xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent mb-4">Privacy Policy</h1>
            <p className="text-gray-400">Last updated: February 02, 2026</p>
          </div>
          <div className="space-y-8">
            <div className="bg-gray-900/80 rounded-xl p-6 border border-gray-800">
              <h2 className="text-xl font-bold text-white mb-4">1. Information We Collect</h2>
              <p className="text-gray-400 mb-3">We collect information you provide directly:</p>
              <ul className="list-disc list-inside text-gray-400 space-y-2">
                <li><strong>Account Information:</strong> Email address, name, company name (optional)</li>
                <li><strong>Payment Information:</strong> Processed securely by Stripe — we do not store card numbers</li>
                <li><strong>Uploaded Documents:</strong> Permit documents you submit for analysis</li>
                <li><strong>Usage Data:</strong> How you interact with our Service, pages visited, features used</li>
              </ul>
            </div>
            
            <div className="bg-gray-900/80 rounded-xl p-6 border border-gray-800">
              <h2 className="text-xl font-bold text-white mb-4">2. How We Use Your Information</h2>
              <ul className="list-disc list-inside text-gray-400 space-y-2">
                <li>Provide and improve our permit analysis Service</li>
                <li>Process payments and manage subscriptions via Stripe</li>
                <li>Send important service updates and notifications via Resend</li>
                <li>Respond to support requests</li>
                <li>Analyze usage patterns to improve our Service</li>
                <li>Process your documents using AI analysis via Anthropic</li>
              </ul>
            </div>
            
            <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-xl p-6">
              <h2 className="text-xl font-bold text-emerald-400 mb-4">{"🔒"} 3. Document Security</h2>
              <ul className="list-disc list-inside text-gray-400 space-y-2">
                <li>Your uploaded documents are processed securely via encrypted connections</li>
                <li>Documents are used <strong>only</strong> for the purpose of providing you analysis</li>
                <li>We do not share your documents with third parties except our AI provider (Anthropic) for processing</li>
                <li>Documents are not used to train AI models without your explicit consent</li>
                <li>You can request deletion of your data at any time</li>
              </ul>
            </div>
            
            <div className="bg-gray-900/80 rounded-xl p-6 border border-gray-800">
              <h2 className="text-xl font-bold text-white mb-4">4. Third-Party Service Providers</h2>
              <p className="text-gray-400 mb-3">We share data with the following service providers to operate our Service:</p>
              <ul className="list-disc list-inside text-gray-400 space-y-2">
                <li><strong>Stripe</strong> — Payment processing</li>
                <li><strong>Anthropic</strong> — AI document analysis</li>
                <li><strong>Resend</strong> — Transactional emails</li>
                <li><strong>Sentry</strong> — Error monitoring and performance</li>
                <li><strong>Vercel</strong> — Website hosting</li>
                <li><strong>Railway</strong> — Backend hosting</li>
              </ul>
              <p className="text-gray-400 mt-3">We do <strong>NOT</strong> sell your personal information to anyone.</p>
            </div>
            
            <div className="bg-gray-900/80 rounded-xl p-6 border border-gray-800">
              <h2 className="text-xl font-bold text-white mb-4">5. Data Security</h2>
              <ul className="list-disc list-inside text-gray-400 space-y-2">
                <li>Industry-standard encryption (HTTPS/TLS) for all data in transit</li>
                <li>Secure password hashing (bcrypt)</li>
                <li>JWT-based authentication tokens</li>
                <li>Rate limiting to prevent abuse</li>
                <li>reCAPTCHA to prevent bot access</li>
                <li>Regular security monitoring via Sentry</li>
              </ul>
            </div>
            
            <div className="bg-gray-900/80 rounded-xl p-6 border border-gray-800">
              <h2 className="text-xl font-bold text-white mb-4">6. Cookies and Local Storage</h2>
              <p className="text-gray-400">We use browser local storage to keep you logged in and remember your preferences. We use Google reCAPTCHA which may use cookies for bot detection. We do not use third-party advertising cookies.</p>
            </div>
            
            <div className="bg-gray-900/80 rounded-xl p-6 border border-gray-800">
              <h2 className="text-xl font-bold text-white mb-4">7. Your Rights</h2>
              <p className="text-gray-400 mb-3">You have the right to:</p>
              <ul className="list-disc list-inside text-gray-400 space-y-2">
                <li>Access your personal data</li>
                <li>Correct inaccurate information</li>
                <li>Delete your account and associated data</li>
                <li>Export your analysis history</li>
                <li>Opt out of marketing communications</li>
                <li>Request information about how your data is used</li>
              </ul>
              <p className="text-gray-400 mt-3">To exercise any of these rights, contact us at <a href="mailto:support@flopermit.com" className="text-cyan-400 hover:underline">support@flopermit.com</a></p>
            </div>
            
            <div className="bg-gray-900/80 rounded-xl p-6 border border-gray-800">
              <h2 className="text-xl font-bold text-white mb-4">8. Data Retention</h2>
              <p className="text-gray-400">We retain your account information as long as your account is active. Analysis history is retained to provide you access to past results. You can request deletion of all your data at any time by contacting us.</p>
            </div>
            
            <div className="bg-gray-900/80 rounded-xl p-6 border border-gray-800">
              <h2 className="text-xl font-bold text-white mb-4">9. Children{"'"}s Privacy</h2>
              <p className="text-gray-400">Our Service is not intended for users under 18 years of age. We do not knowingly collect personal information from children under 18. If we become aware that we have collected personal data from a child under 18, we will take steps to delete that information.</p>
            </div>
            
            <div className="bg-gray-900/80 rounded-xl p-6 border border-gray-800">
              <h2 className="text-xl font-bold text-white mb-4">10. Changes to This Privacy Policy</h2>
              <p className="text-gray-400">We may update this Privacy Policy from time to time. We will notify you of significant changes via email or through the Service. Your continued use after changes constitutes acceptance of the updated policy.</p>
            </div>
            
            <div className="bg-gray-900/80 rounded-xl p-6 border border-gray-800">
              <h2 className="text-xl font-bold text-white mb-4">11. Contact Us</h2>
              <p className="text-gray-400 mb-2">For privacy-related questions or to exercise your rights, contact us:</p>
              <ul className="list-disc list-inside text-gray-400 space-y-2">
                <li>By email: <a href="mailto:support@flopermit.com" className="text-cyan-400 hover:underline">support@flopermit.com</a></li>
                <li>By visiting our <button onClick={() => setPage('contact')} className="text-cyan-400 hover:underline">Contact page</button></li>
              </ul>
            </div>
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
          
          {/* Single Purchase Banner */}
          <div className="mb-8 p-6 bg-gradient-to-r from-cyan-500/10 to-emerald-500/10 border border-cyan-500/30 rounded-2xl">
            <div className="flex flex-col md:flex-row items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <h3 className="text-xl font-bold text-cyan-400">Just need one analysis?</h3>
                </div>
                <p className="text-gray-400">Get a single permit analysis for <span className="text-white font-bold">$15.99</span> — no subscription required. Valid for 30 days.</p>
              </div>
              <button onClick={() => setShowSinglePurchase(true)} className="px-6 py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl whitespace-nowrap hover:scale-105 transition-transform">
                Get Single Analysis →
              </button>
            </div>
          </div>

          <div className="grid md:grid-cols-3 gap-6">
            {/* Free */}
            <div className="bg-gray-900/80 rounded-2xl p-8 border border-gray-800 flex flex-col">
              <h3 className="text-xl font-bold text-white mb-2">Free</h3>
              <div className="mb-6"><span className="text-4xl font-black text-white">$0</span><span className="text-gray-500">/month</span></div>
              <ul className="space-y-3 mb-8 flex-grow">
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
            <div className="bg-gray-900/80 rounded-2xl p-8 border-2 border-cyan-500 relative flex flex-col">
              <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-1 bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-full text-black text-xs font-bold">POPULAR</div>
              <h3 className="text-xl font-bold text-white mb-2">Pro</h3>
              <div className="mb-6"><span className="text-4xl font-black text-white">$29</span><span className="text-gray-500">/month</span></div>
              <ul className="space-y-3 mb-8 flex-grow">
                <li className="flex items-center gap-2 text-gray-400"><svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg>30 analyses/month</li>
                <li className="flex items-center gap-2 text-gray-400"><svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg>Enhanced AI (deeper analysis)</li>
                <li className="flex items-center gap-2 text-gray-400"><svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg>Email support</li>
                <li className="flex items-center gap-2 text-gray-400"><svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg>Analysis history</li>
              </ul>
              {subscription?.tier === 'pro' ? (
                <button onClick={openBillingPortal} className="w-full py-3 border border-cyan-500 text-cyan-400 font-bold rounded-xl hover:bg-cyan-500/10">Manage Subscription</button>
              ) : (
                <button onClick={() => handleCheckout('pro')} disabled={checkoutLoading || !currentUser} className="w-full py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl disabled:opacity-50 flex items-center justify-center gap-2">{checkoutLoading ? <><div className="w-4 h-4 border-2 border-black border-t-transparent rounded-full animate-spin"></div>Processing...</> : currentUser ? 'Upgrade to Pro' : 'Sign up first'}</button>
              )}
            </div>
            {/* Business */}
            <div className="bg-gray-900/80 rounded-2xl p-8 border border-gray-800 flex flex-col">
              <h3 className="text-xl font-bold text-white mb-2">Business</h3>
              <div className="mb-6"><span className="text-4xl font-black text-white">$99</span><span className="text-gray-500">/month</span></div>
              <ul className="space-y-3 mb-8 flex-grow">
                <li className="flex items-center gap-2 text-gray-400"><svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg>Unlimited analyses</li>
                <li className="flex items-center gap-2 text-gray-400"><svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg>Enhanced AI (deeper analysis)</li>
                <li className="flex items-center gap-2 text-gray-400"><svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg>Email support</li>
                <li className="flex items-center gap-2 text-gray-400"><svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg>Analysis history</li>
                <li className="flex items-center gap-2 text-gray-400"><svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg>Team features (soon)</li>
              </ul>
              {subscription?.tier === 'business' ? (
                <button onClick={openBillingPortal} className="w-full py-3 border border-purple-500 text-purple-400 font-bold rounded-xl hover:bg-purple-500/10">Manage Subscription</button>
              ) : (
                <button onClick={() => handleCheckout('business')} disabled={checkoutLoading || !currentUser} className="w-full py-3 border border-gray-700 text-white font-bold rounded-xl hover:bg-gray-800 disabled:opacity-50 flex items-center justify-center gap-2">{checkoutLoading ? <><div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>Processing...</> : currentUser ? 'Upgrade to Business' : 'Sign up first'}</button>
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
              <h2 className="text-2xl font-bold text-white mb-2">Single Analysis</h2>
              <p className="text-gray-400">One-time purchase for <span className="text-cyan-400 font-bold">$15.99</span></p>
            </div>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-semibold text-gray-400 mb-2">Your Email</label>
                <input 
                  type="email" 
                  value={singlePurchaseEmail} 
                  onChange={e => setSinglePurchaseEmail(e.target.value)}
                  placeholder="your@email.com"
                  className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl text-white focus:border-cyan-500 focus:outline-none"
                />
              </div>
              
              <div>
                <label className="block text-sm font-semibold text-gray-400 mb-2">County</label>
                <select 
                  value={county} 
                  onChange={e => { setCounty(e.target.value); setCity(''); setPermitType('') }}
                  className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl text-white focus:border-cyan-500 focus:outline-none"
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
                  className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl text-white focus:border-cyan-500 focus:outline-none disabled:opacity-50"
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
                      <option value="Oakland Park">Oakland Park</option>
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
                      <option value="Wellington">Wellington</option>
                      <option value="West Palm Beach">West Palm Beach</option>
                    </>
                  )}
                  {county === 'Miami-Dade' && (
                    <>
                      <option value="Hialeah">Hialeah</option>
                      <option value="Homestead">Homestead</option>
                      <option value="Kendall">Kendall (Unincorporated)</option>
                      <option value="Miami">Miami</option>
                      <option value="Miami Beach">Miami Beach</option>
                      <option value="Miami Gardens">Miami Gardens</option>
                      <option value="North Miami">North Miami</option>
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
                  className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl text-white focus:border-cyan-500 focus:outline-none disabled:opacity-50"
                >
                  {getPermitTypes().map((pt, i) => (
                    <option key={pt.value || `cat-${i}`} value={pt.value} disabled={pt.disabled}>
                      {pt.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            
            <div className="mt-6 p-4 bg-cyan-500/10 border border-cyan-500/20 rounded-xl">
              <p className="text-sm text-cyan-400">✓ Full AI-powered permit analysis</p>
              <p className="text-sm text-cyan-400">✓ Complete checklist for your permit type</p>
              <p className="text-sm text-cyan-400">✓ 30 days to complete your analysis</p>
              <p className="text-sm text-cyan-400">✓ No account or subscription required</p>
            </div>
            
            <button 
              onClick={handleSinglePurchaseCheckout}
              disabled={checkoutLoading || !singlePurchaseEmail || !city}
              className="w-full mt-6 py-4 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl disabled:opacity-50 hover:scale-[1.02] transition-transform"
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
        <div className="text-center max-w-lg">
          <div className="text-9xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent mb-2">404</div>
          <h1 className="text-3xl font-bold text-white mb-3">Permit Denied!</h1>
          <p className="text-gray-400 mb-8">Just kidding — this page just doesn't exist. Unlike your permit package, which we can actually help with.</p>
          
          <div className="flex flex-col sm:flex-row gap-4 justify-center mb-10">
            <button onClick={() => setPage('home')} className="px-8 py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl hover:scale-105 transition-transform">
              Analyze My Permits →
            </button>
            <button onClick={() => setPage('pricing')} className="px-8 py-3 border border-gray-700 text-white font-semibold rounded-xl hover:bg-gray-800 transition-colors">
              View Pricing
            </button>
          </div>

          <div className="border-t border-gray-800 pt-8">
            <p className="text-gray-500 text-sm mb-4">Looking for something specific?</p>
            <div className="flex flex-wrap justify-center gap-3">
              <button onClick={() => setPage('how-it-works')} className="text-cyan-400 hover:text-cyan-300 text-sm">How It Works</button>
              <span className="text-gray-700">•</span>
              <button onClick={() => setPage('faq')} className="text-cyan-400 hover:text-cyan-300 text-sm">FAQ</button>
              <span className="text-gray-700">•</span>
              <button onClick={() => setPage('contact')} className="text-cyan-400 hover:text-cyan-300 text-sm">Contact Us</button>
            </div>
          </div>
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
                  <input type="file" accept="image/*" capture="environment" onChange={handleFiles} className="hidden" id="singleCameraInput" />
                  
                  <div className="w-16 h-16 mx-auto mb-4 bg-gradient-to-br from-amber-500/20 to-orange-500/20 rounded-2xl flex items-center justify-center border border-amber-500/30">
                    <svg className="w-8 h-8 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/>
                    </svg>
                  </div>
                  
                  <p className="font-bold text-white mb-2">Drag & drop files here</p>
                  <p className="text-sm text-gray-500 mb-4">PDF, PNG, JPG • Max 50 files</p>
                  
                  <div className="flex flex-wrap items-center justify-center gap-3">
                    <label htmlFor="singleFileInput" className="cursor-pointer px-4 py-2 bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/30 rounded-lg text-amber-400 text-sm font-semibold transition-all">
                      Select Files
                    </label>
                    <label htmlFor="singleFolderInput" className="cursor-pointer px-4 py-2 bg-orange-500/20 hover:bg-orange-500/30 border border-orange-500/30 rounded-lg text-orange-400 text-sm font-semibold transition-all">
                      Select Folder
                    </label>
                    <label htmlFor="singleCameraInput" className="cursor-pointer px-4 py-2 bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/30 rounded-lg text-purple-400 text-sm font-semibold transition-all md:hidden">
                      📸 Take Photo
                    </label>
                  </div>
                  <p className="text-xs text-gray-600 mt-4">💡 For best results, use scanned PDFs. Phone photos work but may be harder to read.</p>
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
          {adminLoading ? (
            <div className="text-center py-16 bg-gray-900/50 rounded-2xl border border-gray-800">
              <div className="w-12 h-12 border-3 border-purple-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
              <p className="text-gray-400">Loading admin stats...</p>
            </div>
          ) : adminStats ? (
            <div className="space-y-6">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-gray-900/80 rounded-xl p-4 border border-gray-800"><p className="text-gray-500 text-sm">Total Users</p><p className="text-3xl font-black text-white">{adminStats.overview.total_users}</p><p className="text-emerald-400 text-sm">+{adminStats.overview.new_users_this_month} this month</p></div>
                <div className="bg-gray-900/80 rounded-xl p-4 border border-gray-800"><p className="text-gray-500 text-sm">Total Analyses</p><p className="text-3xl font-black text-white">{adminStats.overview.total_analyses}</p><p className="text-cyan-400 text-sm">+{adminStats.overview.analyses_this_month} this month</p></div>
                <div className="bg-gray-900/80 rounded-xl p-4 border border-gray-800"><p className="text-gray-500 text-sm">Avg Score</p><p className="text-3xl font-black text-white">{adminStats.overview.average_compliance_score}%</p></div>
                <div className="bg-gray-900/80 rounded-xl p-4 border border-gray-800"><p className="text-gray-500 text-sm">API Requests</p><p className="text-3xl font-black text-white">{adminStats.overview.api_requests_today}</p><p className="text-purple-400 text-sm">{adminStats.overview.api_requests_this_month} this month</p></div>
              </div>
              
              {/* AI Costs Section */}
              {adminStats.ai_costs && (
                <div className="bg-gradient-to-r from-purple-900/50 to-pink-900/50 rounded-xl p-6 border border-purple-500/30">
                  <h3 className="font-bold text-white mb-4 flex items-center gap-2">
                    <span className="text-xl">🤖</span> AI Usage & Costs
                  </h3>
                  <div className="grid md:grid-cols-2 gap-6">
                    <div>
                      <p className="text-gray-400 text-sm mb-2">Today</p>
                      <div className="space-y-2">
                        <div className="flex justify-between"><span className="text-gray-300">Analyses</span><span className="text-white font-bold">{adminStats.ai_costs.today.analyses}</span></div>
                        <div className="flex justify-between"><span className="text-gray-300">Input Tokens</span><span className="text-cyan-400">{adminStats.ai_costs.today.input_tokens?.toLocaleString()}</span></div>
                        <div className="flex justify-between"><span className="text-gray-300">Output Tokens</span><span className="text-emerald-400">{adminStats.ai_costs.today.output_tokens?.toLocaleString()}</span></div>
                        <div className="flex justify-between border-t border-purple-500/30 pt-2 mt-2"><span className="text-white font-semibold">Cost</span><span className="text-2xl font-black text-purple-400">${adminStats.ai_costs.today.cost_dollars}</span></div>
                      </div>
                    </div>
                    <div>
                      <p className="text-gray-400 text-sm mb-2">This Month</p>
                      <div className="space-y-2">
                        <div className="flex justify-between"><span className="text-gray-300">Analyses</span><span className="text-white font-bold">{adminStats.ai_costs.this_month.analyses}</span></div>
                        <div className="flex justify-between"><span className="text-gray-300">Input Tokens</span><span className="text-cyan-400">{adminStats.ai_costs.this_month.input_tokens?.toLocaleString()}</span></div>
                        <div className="flex justify-between"><span className="text-gray-300">Output Tokens</span><span className="text-emerald-400">{adminStats.ai_costs.this_month.output_tokens?.toLocaleString()}</span></div>
                        <div className="flex justify-between border-t border-purple-500/30 pt-2 mt-2"><span className="text-white font-semibold">Cost</span><span className="text-2xl font-black text-pink-400">${adminStats.ai_costs.this_month.cost_dollars}</span></div>
                      </div>
                    </div>
                  </div>
                </div>
              )}
              
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
              
              {/* Reviews Management */}
              <div className="bg-gradient-to-r from-amber-900/30 to-orange-900/30 rounded-xl p-6 border border-amber-500/30">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-bold text-white flex items-center gap-2"><span className="text-xl">★</span> Reviews Management</h3>
                  <button onClick={loadAdminReviews} className="px-3 py-1 bg-amber-500/20 text-amber-400 rounded-lg text-sm hover:bg-amber-500/30">↻ Refresh</button>
                </div>
                {adminReviews.length === 0 ? (
                  <p className="text-gray-500">No reviews yet</p>
                ) : (
                  <div className="space-y-4">
                    {adminReviews.map(r => (
                      <div key={r.id} className={`p-4 rounded-xl border ${r.is_approved ? 'bg-emerald-900/20 border-emerald-500/30' : 'bg-gray-800/50 border-gray-700'}`}>
                        <div className="flex items-start justify-between gap-4">
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-2">
                              <span className="font-semibold text-white">{r.name}</span>
                              {r.role && <span className="text-gray-500">• {r.role}</span>}
                              {r.city && <span className="text-gray-500">• {r.city}</span>}
                            </div>
                            <div className="flex items-center gap-1 mb-2">
                              {[...Array(5)].map((_, i) => (
                                <span key={i} className={i < r.stars ? 'text-amber-400' : 'text-gray-600'}>★</span>
                              ))}
                            </div>
                            <p className="text-gray-300 text-sm italic">"{r.review_text}"</p>
                            <p className="text-gray-600 text-xs mt-2">{new Date(r.created_at).toLocaleDateString()}</p>
                          </div>
                          <div className="flex flex-col gap-2">
                            <button 
                              onClick={() => updateReview(r.id, { is_approved: !r.is_approved })}
                              className={`px-3 py-1 rounded-lg text-xs font-bold ${r.is_approved ? 'bg-emerald-500/20 text-emerald-400' : 'bg-gray-700 text-gray-300'}`}
                            >
                              {r.is_approved ? '✓ Approved' : 'Approve'}
                            </button>
                            <button 
                              onClick={() => updateReview(r.id, { is_featured: !r.is_featured })}
                              className={`px-3 py-1 rounded-lg text-xs font-bold ${r.is_featured ? 'bg-amber-500/20 text-amber-400' : 'bg-gray-700 text-gray-300'}`}
                            >
                              {r.is_featured ? '★ Featured' : 'Feature'}
                            </button>
                            <button 
                              onClick={() => deleteReview(r.id)}
                              className="px-3 py-1 bg-red-500/20 text-red-400 rounded-lg text-xs font-bold hover:bg-red-500/30"
                            >
                              Delete
                            </button>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
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
          {profileLoading ? (
            <div className="text-center py-16 bg-gray-900/50 rounded-2xl border border-gray-800">
              <div className="w-12 h-12 border-3 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
              <p className="text-gray-400">Loading profile...</p>
            </div>
          ) : profile ? (
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
              
              {/* Leave a Review */}
              <div className="bg-gray-900/80 rounded-2xl p-6 border border-gray-800">
                <h2 className="text-xl font-bold text-white mb-4">Leave a Review</h2>
                <p className="text-gray-400 text-sm mb-4">Love Flo Permit? We'd appreciate your feedback!</p>
                <button onClick={() => setShowReviewForm(true)} className="w-full py-2 bg-amber-500/20 border border-amber-500/30 text-amber-400 font-bold rounded-lg hover:bg-amber-500/30 flex items-center justify-center gap-2">
                  <span>★</span> Write a Review
                </button>
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
          {historyLoading ? (
            <div className="text-center py-16 bg-gray-900/50 rounded-2xl border border-gray-800">
              <div className="w-12 h-12 border-3 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
              <p className="text-gray-400">Loading your analyses...</p>
            </div>
          ) : history.length === 0 ? (
            <div className="text-center py-16 bg-gray-900/50 rounded-2xl border border-gray-800">
              <div className="w-16 h-16 mx-auto mb-4 bg-gray-800 rounded-full flex items-center justify-center">
                <svg className="w-8 h-8 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
              </div>
              <h3 className="text-xl font-bold text-white mb-2">No analyses yet</h3>
              <p className="text-gray-500 mb-6">Upload your first permit package to get started</p>
              <button onClick={() => setPage('home')} className="px-6 py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl hover:scale-105 transition-transform">Start Your First Analysis →</button>
            </div>
          ) : (
            <div className="space-y-3">{history.map(h => (
              <div key={h.analysis_uuid} className={`bg-gray-900/50 rounded-xl border border-gray-800 p-4 flex items-center justify-between hover:border-gray-700 transition-all ${viewingAnalysis === h.analysis_uuid ? 'opacity-60' : ''}`}>
                <div className="flex-1 cursor-pointer" onClick={() => viewAnalysis(h.analysis_uuid)}>
                  <div className="flex items-center gap-3">
                    {viewingAnalysis === h.analysis_uuid && <div className="w-4 h-4 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin"></div>}
                    <span className="font-bold text-white">{h.city}</span><span className="text-gray-500">•</span><span className="text-gray-400">{h.permit_type}</span>
                  </div>
                  <div className="text-sm text-gray-500 mt-1">{h.files_analyzed} files • {new Date(h.created_at).toLocaleDateString()}</div>
                </div>
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
                {/* Disclaimer Banner */}
                <div className="p-3 bg-amber-500/10 border border-amber-500/20 rounded-lg flex items-start gap-2">
                  <span className="text-amber-400 shrink-0">⚠️</span>
                  <p className="text-amber-300/80 text-xs">This analysis is for <strong>informational purposes only</strong> and does not guarantee permit approval. Always verify requirements with your local permitting office. <button onClick={() => setPage('terms')} className="underline hover:text-amber-200">View full terms</button></p>
                </div>

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
                
                {/* Add More Files Section */}
                {missingDocs.length > 0 && (
                  <div className="mt-6 p-6 bg-gradient-to-r from-cyan-500/10 to-emerald-500/10 border border-cyan-500/30 rounded-xl">
                    <h3 className="font-bold text-white mb-3 flex items-center gap-2">
                      <svg className="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"/></svg>
                      Add Missing Documents
                    </h3>
                    <p className="text-gray-400 text-sm mb-4">Upload the missing documents and we'll update your analysis automatically.</p>
                    
                    {/* Additional Files List */}
                    {additionalFiles.length > 0 && (
                      <div className="mb-4 p-3 bg-black/30 rounded-lg">
                        <p className="text-sm text-gray-400 mb-2">Files to add ({additionalFiles.length}):</p>
                        <div className="flex flex-wrap gap-2">
                          {additionalFiles.map((f, i) => (
                            <span key={i} className="px-2 py-1 bg-cyan-500/20 text-cyan-300 text-xs rounded-full flex items-center gap-1">
                              {f.name}
                              <button onClick={() => setAdditionalFiles(prev => prev.filter((_, idx) => idx !== i))} className="hover:text-red-400">×</button>
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                    
                    <div className="flex gap-3">
                      <label className="flex-1 cursor-pointer">
                        <input
                          type="file"
                          multiple
                          className="hidden"
                          accept=".pdf,.doc,.docx,.jpg,.jpeg,.png,.tif,.tiff"
                          onChange={(e) => {
                            const newFiles = Array.from(e.target.files || [])
                            setAdditionalFiles(prev => [...prev, ...newFiles])
                            e.target.value = ''
                          }}
                        />
                        <div className="px-4 py-2 bg-gray-800 hover:bg-gray-700 border border-gray-600 rounded-lg text-center text-sm text-gray-300 transition-colors">
                          + Add Files
                        </div>
                      </label>
                      <label className="flex-1 cursor-pointer">
                        <input
                          type="file"
                          webkitdirectory=""
                          directory=""
                          multiple
                          className="hidden"
                          onChange={(e) => {
                            const newFiles = Array.from(e.target.files || []).filter(f => 
                              /\.(pdf|doc|docx|jpg|jpeg|png|tif|tiff)$/i.test(f.name)
                            )
                            setAdditionalFiles(prev => [...prev, ...newFiles])
                            e.target.value = ''
                          }}
                        />
                        <div className="px-4 py-2 bg-gray-800 hover:bg-gray-700 border border-gray-600 rounded-lg text-center text-sm text-gray-300 transition-colors">
                          + Add Folder
                        </div>
                      </label>
                      {additionalFiles.length > 0 && (
                        <button
                          onClick={reanalyzeWithAdditionalFiles}
                          disabled={loading}
                          className="flex-1 px-4 py-2 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-lg hover:scale-105 transition-transform disabled:opacity-50"
                        >
                          {loading ? 'Analyzing...' : `Update Analysis (${additionalFiles.length} new)`}
                        </button>
                      )}
                    </div>
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
                <button onClick={() => { setPage('home'); setResults(null); clearFiles(); setAdditionalFiles([]) }} className="px-8 py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl hover:scale-105 transition-transform">
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
    <div className="min-h-screen bg-black text-white overflow-hidden flex flex-col relative">
      {/* Animated background with floating particles */}
      <div className="fixed inset-0 z-0">
        <div className="absolute inset-0 bg-gradient-to-br from-black via-gray-900 to-black"></div>
        
        {/* Floating cyan particles */}
        <div className="absolute w-2 h-2 bg-cyan-400 rounded-full animate-float-1 opacity-60" style={{top: '10%', left: '10%'}}></div>
        <div className="absolute w-3 h-3 bg-cyan-500 rounded-full animate-float-2 opacity-40" style={{top: '20%', left: '80%'}}></div>
        <div className="absolute w-2 h-2 bg-emerald-400 rounded-full animate-float-3 opacity-50" style={{top: '60%', left: '15%'}}></div>
        <div className="absolute w-4 h-4 bg-cyan-300 rounded-full animate-float-1 opacity-30" style={{top: '70%', left: '70%'}}></div>
        <div className="absolute w-2 h-2 bg-emerald-500 rounded-full animate-float-2 opacity-60" style={{top: '40%', left: '5%'}}></div>
        <div className="absolute w-3 h-3 bg-cyan-400 rounded-full animate-float-3 opacity-40" style={{top: '85%', left: '40%'}}></div>
        <div className="absolute w-2 h-2 bg-cyan-500 rounded-full animate-float-1 opacity-50" style={{top: '15%', left: '50%'}}></div>
        <div className="absolute w-3 h-3 bg-emerald-400 rounded-full animate-float-2 opacity-30" style={{top: '50%', left: '90%'}}></div>
        <div className="absolute w-2 h-2 bg-cyan-300 rounded-full animate-float-3 opacity-60" style={{top: '30%', left: '25%'}}></div>
        <div className="absolute w-4 h-4 bg-cyan-500 rounded-full animate-float-1 opacity-20" style={{top: '80%', left: '85%'}}></div>
        <div className="absolute w-2 h-2 bg-emerald-500 rounded-full animate-float-2 opacity-50" style={{top: '5%', left: '65%'}}></div>
        <div className="absolute w-3 h-3 bg-cyan-400 rounded-full animate-float-3 opacity-40" style={{top: '45%', left: '45%'}}></div>
        
        {/* Larger glowing orbs */}
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/20 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-emerald-500/15 rounded-full blur-3xl animate-pulse" style={{animationDelay: '1s'}}></div>
        <div className="absolute top-1/2 right-1/3 w-64 h-64 bg-purple-500/10 rounded-full blur-3xl animate-pulse" style={{animationDelay: '2s'}}></div>
        
        {/* Grid overlay */}
        <div className="absolute inset-0 opacity-10" style={{backgroundImage: 'linear-gradient(rgba(6, 182, 212, 0.15) 1px, transparent 1px), linear-gradient(90deg, rgba(6, 182, 212, 0.15) 1px, transparent 1px)', backgroundSize: '60px 60px'}}></div>
      </div>

      {/* Navigation */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-black/50 backdrop-blur-xl border-b border-cyan-500/20">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-11 h-11 rounded-xl overflow-hidden">
              <img src="/adc_logo.png" alt="Flo Permit" className="w-full h-full object-contain" />
            </div>
            <div>
              <h1 className="text-xl font-black"><span className="text-cyan-400">Flo</span> <span className="text-white">Permit</span></h1>
              <p className="text-xs text-cyan-500 font-semibold">SOUTH FLORIDA</p>
            </div>
          </div>
          {/* Desktop */}
          <div className="hidden md:flex items-center gap-4">
            <button onClick={() => setPage('pricing')} className="text-sm font-semibold text-gray-400 hover:text-cyan-400">Pricing</button>
            <button onClick={() => setPage('faq')} className="text-sm font-semibold text-gray-400 hover:text-cyan-400">FAQ</button>
            <button onClick={() => setShowLogin(true)} className="text-sm font-semibold text-gray-400 hover:text-cyan-400">Log In</button>
            <button onClick={() => setShowRegister(true)} className="relative group"><div className="absolute -inset-0.5 bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-xl blur opacity-60 group-hover:opacity-100"></div><div className="relative px-5 py-2.5 bg-black text-white text-sm font-bold rounded-xl">Sign Up Free</div></button>
          </div>
          {/* Mobile Hamburger */}
          <button className="md:hidden relative w-8 h-8 flex flex-col items-center justify-center gap-1.5" onClick={() => setMobileMenuOpen(!mobileMenuOpen)}>
            <span className={`w-6 h-0.5 bg-white transition-all duration-300 ${mobileMenuOpen ? 'rotate-45 translate-y-2' : ''}`}></span>
            <span className={`w-6 h-0.5 bg-white transition-all duration-300 ${mobileMenuOpen ? 'opacity-0' : ''}`}></span>
            <span className={`w-6 h-0.5 bg-white transition-all duration-300 ${mobileMenuOpen ? '-rotate-45 -translate-y-2' : ''}`}></span>
          </button>
        </div>
        {mobileMenuOpen && (
          <div className="md:hidden bg-gray-900/95 backdrop-blur-xl border-t border-gray-800 px-6 py-4 space-y-3">
            <button onClick={() => { setPage('how-it-works'); setMobileMenuOpen(false) }} className="block w-full text-left text-gray-300 hover:text-cyan-400 py-2">How It Works</button>
            <button onClick={() => { setPage('pricing'); setMobileMenuOpen(false) }} className="block w-full text-left text-gray-300 hover:text-cyan-400 py-2">Pricing</button>
            <button onClick={() => { setPage('faq'); setMobileMenuOpen(false) }} className="block w-full text-left text-gray-300 hover:text-cyan-400 py-2">FAQ</button>
            <button onClick={() => { setPage('about'); setMobileMenuOpen(false) }} className="block w-full text-left text-gray-300 hover:text-cyan-400 py-2">About</button>
            <button onClick={() => { setPage('contact'); setMobileMenuOpen(false) }} className="block w-full text-left text-gray-300 hover:text-cyan-400 py-2">Contact</button>
            <div className="border-t border-gray-800 pt-3 mt-3 flex gap-3">
              <button onClick={() => { setShowLogin(true); setMobileMenuOpen(false) }} className="flex-1 py-2.5 border border-gray-700 text-white font-semibold rounded-xl hover:bg-gray-800 text-sm">Log In</button>
              <button onClick={() => { setShowRegister(true); setMobileMenuOpen(false) }} className="flex-1 py-2.5 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl text-sm">Sign Up</button>
            </div>
          </div>
        )}
      </nav>

      {/* Main Content */}
      <div className="relative z-10 flex-grow flex items-center justify-center px-6 py-24">
        <div className="max-w-5xl mx-auto grid md:grid-cols-2 gap-12 items-center">
          
          {/* Left side - Hero */}
          <div className="text-center md:text-left">
            <div className="flex items-center justify-center md:justify-start gap-4 mb-6">
              <div className="w-16 h-16 rounded-2xl overflow-hidden">
                <img src="/adc_logo.png" alt="Flo Permit" className="w-full h-full object-contain" />
              </div>
              <h1 className="text-3xl font-black"><span className="text-cyan-400">Flo</span> <span className="text-white">Permit</span></h1>
            </div>
            
            <p className="text-xl text-gray-300 mb-4">Upload your permit package and get instant AI-powered analysis. Know what's missing before you submit.</p>
            <p className="text-gray-500 mb-8">Serving 30 cities across South Florida</p>
            
            <div className="grid grid-cols-3 gap-4">
              {[{icon:'⚡',title:'Instant'},{icon:'🎯',title:'Accurate'},{icon:'📋',title:'Complete'}].map((f,i) => (
                <div key={i} className="text-center p-3 bg-gray-900/50 rounded-xl border border-gray-800 backdrop-blur-sm">
                  <div className="text-2xl mb-1">{f.icon}</div>
                  <p className="text-sm text-gray-400">{f.title}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Right side - Auth Form */}
          <div className="relative">
            <div className="absolute -inset-1 bg-gradient-to-r from-cyan-500/50 via-emerald-500/50 to-purple-500/50 rounded-3xl blur-xl opacity-40 animate-pulse"></div>
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
                        <button type="submit" className="w-full py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl hover:scale-[1.02] transition-transform">Send Reset Link</button>
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
                    {error && (
                      <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-xl mb-4">
                        <p className="text-red-400 text-sm font-medium">{error}</p>
                        {error.toLowerCase().includes('already registered') && (
                          <button type="button" onClick={() => { setShowRegister(false); setError('') }} className="text-cyan-400 hover:text-cyan-300 text-sm mt-2 underline">Click here to log in instead</button>
                        )}
                      </div>
                    )}
                    <button type="submit" className="w-full py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl hover:scale-[1.02] transition-transform">Create Account</button>
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
                    <button type="submit" className="w-full py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl hover:scale-[1.02] transition-transform">Log In</button>
                  </form>
                  <div className="mt-4 text-center"><button onClick={() => { setShowForgotPassword(true); setError('') }} className="text-cyan-400 hover:text-cyan-300 text-sm">Forgot password?</button></div>
                  <div className="relative my-6"><div className="absolute inset-0 flex items-center"><div className="w-full border-t border-gray-700"></div></div><div className="relative flex justify-center text-sm"><span className="px-4 bg-gray-900 text-gray-500">or</span></div></div>
                  <button onClick={() => { setShowRegister(true); setError('') }} className="w-full py-3 border border-gray-700 text-white font-bold rounded-xl hover:bg-gray-800 transition-colors">Create New Account</button>
                </>
              )}
            </div>
          </div>
        </div>
      </div>
      
      {/* Single Purchase Modal */}
      {showSinglePurchase && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="relative">
            <div className="absolute -inset-1 bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-3xl blur-lg opacity-50"></div>
            <div className="relative bg-gray-900 rounded-2xl p-8 max-w-md w-full border border-cyan-500/20">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-2xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent">One-Time Analysis</h2>
                <button onClick={() => setShowSinglePurchase(false)} className="text-2xl text-gray-500 hover:text-white">&times;</button>
              </div>
              <div className="text-center mb-6">
                <div className="text-4xl font-black text-white mb-2">$15.99</div>
                <p className="text-gray-400 text-sm">No subscription needed</p>
                <p className="text-cyan-400 text-xs mt-2">Valid for 30 days after purchase</p>
              </div>
              <ul className="space-y-2 mb-6">
                <li className="flex items-center gap-2 text-gray-300"><svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"/></svg>Full AI-powered permit analysis</li>
                <li className="flex items-center gap-2 text-gray-300"><svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"/></svg>City-specific requirements checklist</li>
                <li className="flex items-center gap-2 text-gray-300"><svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"/></svg>Add more files & re-analyze</li>
                <li className="flex items-center gap-2 text-gray-300"><svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"/></svg>No account required</li>
              </ul>
              <input 
                type="email" 
                placeholder="Your email address" 
                value={singlePurchaseEmail}
                onChange={(e) => setSinglePurchaseEmail(e.target.value)}
                className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl mb-4 text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
              />
              <button 
                onClick={handleSinglePurchaseCheckout}
                disabled={!singlePurchaseEmail || checkoutLoading}
                className="w-full py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl disabled:opacity-50 hover:scale-[1.02] transition-transform"
              >
                {checkoutLoading ? 'Processing...' : 'Continue to Payment'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ============================================================ */}
      {/* SECTION: Featured Testimonial Rotator */}
      {/* ============================================================ */}
      <div className="relative z-10 py-12 px-6">
        <div className="max-w-2xl mx-auto">
          <div className="relative h-28 overflow-hidden">
            {featuredTestimonials.map((t, i) => (
              <div 
                key={i} 
                className={`absolute inset-0 flex items-center justify-center text-center transition-all duration-700 ease-in-out ${activeTestimonial % featuredTestimonials.length === i ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}`}
              >
                <div>
                  <p className="text-lg text-gray-300 italic mb-3">"{t.review_text || t.quote}"</p>
                  <div className="flex items-center justify-center gap-2 flex-wrap">
                    <div className="w-8 h-8 bg-gradient-to-br from-cyan-500 to-emerald-500 rounded-full flex items-center justify-center text-black font-bold text-xs">{t.name[0]}</div>
                    <span className="text-white font-semibold text-sm">{t.name}</span>
                    <span className="text-gray-500">•</span>
                    <span className="text-cyan-400 text-sm">{t.role}{t.city ? `, ${t.city}` : ''}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
          {/* Dots indicator */}
          <div className="flex justify-center gap-2 mt-4">
            {featuredTestimonials.map((_, i) => (
              <button 
                key={i} 
                onClick={() => setActiveTestimonial(i)}
                className={`w-2 h-2 rounded-full transition-colors ${activeTestimonial % featuredTestimonials.length === i ? 'bg-cyan-400' : 'bg-gray-600 hover:bg-gray-500'}`}
              />
            ))}
          </div>
        </div>
      </div>

      {/* ============================================================ */}
      {/* SECTION: How It Works */}
      {/* ============================================================ */}
      <div className="relative z-10 py-20 px-6">
        <div className="max-w-5xl mx-auto">
          <h2 className="text-3xl font-black text-center mb-4 bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent">How It Works</h2>
          <p className="text-gray-500 text-center mb-12">Three simple steps to permit confidence</p>
          <div className="grid md:grid-cols-3 gap-8">
            {[
              { step: '1', icon: '📄', title: 'Upload Documents', desc: 'Upload your permit package — plans, surveys, NOCs, energy calcs, and more. We accept PDFs and images.' },
              { step: '2', icon: '🤖', title: 'AI Analyzes Everything', desc: 'Our AI checks your documents against city-specific requirements for your permit type and jurisdiction.' },
              { step: '3', icon: '✅', title: 'Get Your Report', desc: 'Receive a compliance score, missing document checklist, and actionable recommendations in seconds.' }
            ].map((s, i) => (
              <div key={i} className="relative text-center p-6 bg-gray-900/60 rounded-2xl border border-gray-800 hover:border-cyan-500/30 transition-colors">
                <div className="absolute -top-4 left-1/2 -translate-x-1/2 w-8 h-8 bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-full flex items-center justify-center text-black font-black text-sm">{s.step}</div>
                <div className="text-4xl mb-4 mt-2">{s.icon}</div>
                <h3 className="text-lg font-bold text-white mb-2">{s.title}</h3>
                <p className="text-gray-400 text-sm">{s.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ============================================================ */}
      {/* SECTION: Sample Analysis Preview */}
      {/* ============================================================ */}
      <div className="relative z-10 py-20 px-6 border-t border-gray-800/50">
        <div className="max-w-5xl mx-auto">
          <h2 className="text-3xl font-black text-center mb-4 bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent">See What You Get</h2>
          <p className="text-gray-500 text-center mb-12">Here's a sample analysis for a residential building permit in Fort Lauderdale</p>
          
          <div className="bg-gray-900/80 rounded-2xl border border-gray-800 overflow-hidden max-w-3xl mx-auto">
            {/* Header */}
            <div className="p-6 bg-gradient-to-r from-cyan-500/10 to-emerald-500/10 border-b border-gray-800 flex items-center justify-between">
              <div>
                <h3 className="text-xl font-black text-white">Sample Analysis</h3>
                <p className="text-gray-400 text-sm">Fort Lauderdale • Residential Building Permit</p>
              </div>
              <div className="text-center">
                <div className="text-4xl font-black text-amber-400">72%</div>
                <div className="text-xs text-gray-500">Compliance</div>
              </div>
            </div>
            
            <div className="p-6 space-y-5">
              {/* Summary */}
              <div className="p-4 bg-gray-800/50 rounded-xl">
                <p className="text-gray-300 text-sm">Your permit package has most core documents but is missing key energy compliance forms and the signed/sealed survey. The architectural plans are present but the site plan needs the required flood zone designation for Fort Lauderdale.</p>
              </div>
              
              {/* Checklist Preview */}
              <div>
                <h4 className="font-bold text-white mb-3 flex items-center gap-2">
                  <svg className="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/></svg>
                  Document Checklist
                </h4>
                <div className="space-y-2">
                  {/* Missing */}
                  {['Energy Compliance Form (Manual J/D)', 'Signed & Sealed Survey', 'Product Approval (FL#) for Impact Windows'].map((doc, i) => (
                    <div key={i} className="flex items-center gap-3 p-3 bg-red-500/5 border border-red-500/20 rounded-lg">
                      <span className="text-red-400">✗</span>
                      <span className="text-white text-sm font-medium">{doc}</span>
                      <span className="ml-auto text-xs bg-red-500/20 text-red-400 px-2 py-0.5 rounded-full">Missing</span>
                    </div>
                  ))}
                  {/* Found */}
                  {['Architectural Plans (Floor Plan & Elevations)', 'Site Plan', 'Permit Application Form', 'Notice of Commencement (NOC)'].map((doc, i) => (
                    <div key={i} className="flex items-center gap-3 p-3 bg-gray-800/30 rounded-lg">
                      <span className="text-emerald-400">✓</span>
                      <span className="text-gray-400 text-sm">{doc}</span>
                      <span className="ml-auto text-xs bg-emerald-500/20 text-emerald-400 px-2 py-0.5 rounded-full">Found</span>
                    </div>
                  ))}
                </div>
              </div>
              
              {/* Blurred section to tease more */}
              <div className="relative">
                <div className="space-y-2 blur-sm select-none">
                  <div className="p-3 bg-gray-800/30 rounded-lg h-10"></div>
                  <div className="p-3 bg-gray-800/30 rounded-lg h-10"></div>
                  <div className="p-3 bg-gray-800/30 rounded-lg h-10"></div>
                </div>
                <div className="absolute inset-0 flex items-center justify-center">
                  <button onClick={() => setShowRegister(true)} className="px-6 py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl hover:scale-105 transition-transform shadow-lg shadow-cyan-500/25">
                    Sign Up Free to See Full Reports →
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ============================================================ */}
      {/* SECTION: Testimonials / Social Proof - ANIMATED */}
      {/* ============================================================ */}
      <div className="relative z-10 py-20 border-t border-gray-800/50 overflow-hidden">
        {/* Background glow effects */}
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          <div className="absolute top-1/2 left-1/4 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl animate-pulse"></div>
          <div className="absolute top-1/2 right-1/4 w-96 h-96 bg-emerald-500/10 rounded-full blur-3xl animate-pulse" style={{animationDelay: '1s'}}></div>
        </div>
        
        <div className="max-w-5xl mx-auto px-6 relative">
          <h2 className="text-3xl font-black text-center mb-4 bg-gradient-to-r from-cyan-400 via-emerald-400 to-cyan-400 bg-clip-text text-transparent animate-pulse">⭐ Trusted by Builders ⭐</h2>
          <p className="text-gray-500 text-center mb-12">See why contractors and homeowners love Flo Permit</p>
        </div>
        
        {/* Scrolling testimonials container */}
        <div className="relative">
          {/* Fade edges */}
          <div className="absolute left-0 top-0 bottom-0 w-32 bg-gradient-to-r from-black to-transparent z-10 pointer-events-none"></div>
          <div className="absolute right-0 top-0 bottom-0 w-32 bg-gradient-to-l from-black to-transparent z-10 pointer-events-none"></div>
          
          {/* Scrolling track */}
          <div className="flex animate-scroll-left">
            {/* First set of testimonials */}
            {allTestimonials.map((t, i) => (
              <div 
                key={i} 
                className="review-card flex-shrink-0 w-80 mx-3 p-6 rounded-2xl relative overflow-hidden transition-all duration-300 hover:scale-105 hover:-translate-y-2"
                style={{ 
                  animationDelay: `${i * 0.2}s`,
                  background: 'linear-gradient(135deg, rgba(6,182,212,0.15) 0%, rgba(16,185,129,0.15) 100%)',
                  border: '1px solid rgba(6,182,212,0.3)',
                  boxShadow: '0 0 20px rgba(6,182,212,0.2), 0 0 40px rgba(16,185,129,0.1)'
                }}
              >
                {/* Animated glow border */}
                <div className="absolute inset-0 rounded-2xl bg-gradient-to-r from-cyan-500 via-emerald-500 to-cyan-500 opacity-30 animate-border-glow"></div>
                <div className="absolute inset-[1px] rounded-2xl bg-gray-900/90"></div>
                
                <div className="relative z-10">
                  <div className="flex items-center gap-1 mb-3">
                    {[...Array(t.stars || 5)].map((_, s) => (
                      <span key={s} className="star-twinkle text-amber-400 text-lg" style={{ animationDelay: `${s * 0.15}s` }}>★</span>
                    ))}
                  </div>
                  <p className="text-gray-200 text-sm mb-4 italic leading-relaxed">"{t.review_text || t.quote}"</p>
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 bg-gradient-to-br from-cyan-400 to-emerald-400 rounded-full flex items-center justify-center text-black font-bold text-sm shadow-lg shadow-cyan-500/30 avatar-bounce" style={{ animationDelay: `${i * 0.3}s` }}>{t.name[0]}</div>
                    <div>
                      <p className="text-white font-semibold text-sm">{t.name}</p>
                      <p className="text-cyan-400/80 text-xs">{t.role}{t.city ? ` • ${t.city}` : ''}</p>
                    </div>
                  </div>
                </div>
              </div>
            ))}
            {/* Duplicate set for seamless loop */}
            {allTestimonials.map((t, i) => (
              <div 
                key={`dup-${i}`} 
                className="review-card flex-shrink-0 w-80 mx-3 p-6 rounded-2xl relative overflow-hidden transition-all duration-300 hover:scale-105 hover:-translate-y-2"
                style={{ 
                  animationDelay: `${(i + allTestimonials.length) * 0.2}s`,
                  background: 'linear-gradient(135deg, rgba(6,182,212,0.15) 0%, rgba(16,185,129,0.15) 100%)',
                  border: '1px solid rgba(6,182,212,0.3)',
                  boxShadow: '0 0 20px rgba(6,182,212,0.2), 0 0 40px rgba(16,185,129,0.1)'
                }}
              >
                {/* Animated glow border */}
                <div className="absolute inset-0 rounded-2xl bg-gradient-to-r from-cyan-500 via-emerald-500 to-cyan-500 opacity-30 animate-border-glow"></div>
                <div className="absolute inset-[1px] rounded-2xl bg-gray-900/90"></div>
                
                <div className="relative z-10">
                  <div className="flex items-center gap-1 mb-3">
                    {[...Array(t.stars || 5)].map((_, s) => (
                      <span key={s} className="star-twinkle text-amber-400 text-lg" style={{ animationDelay: `${s * 0.15}s` }}>★</span>
                    ))}
                  </div>
                  <p className="text-gray-200 text-sm mb-4 italic leading-relaxed">"{t.review_text || t.quote}"</p>
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 bg-gradient-to-br from-cyan-400 to-emerald-400 rounded-full flex items-center justify-center text-black font-bold text-sm shadow-lg shadow-cyan-500/30 avatar-bounce" style={{ animationDelay: `${(i + allTestimonials.length) * 0.3}s` }}>{t.name[0]}</div>
                    <div>
                      <p className="text-white font-semibold text-sm">{t.name}</p>
                      <p className="text-cyan-400/80 text-xs">{t.role}{t.city ? ` • ${t.city}` : ''}</p>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Stats bar */}
        <div className="max-w-5xl mx-auto px-6">
          <div className="mt-12 grid grid-cols-3 gap-4 max-w-2xl mx-auto">
            {[
              { num: '30', label: 'Cities Covered' },
              { num: '50+', label: 'Permit Types' },
              { num: '<30s', label: 'Analysis Time' }
            ].map((s, i) => (
              <div key={i} className="text-center p-4 bg-gray-900/40 rounded-xl border border-gray-800">
                <div className="text-2xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent">{s.num}</div>
                <p className="text-gray-500 text-xs mt-1">{s.label}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ============================================================ */}
      {/* SECTION: Supported Cities */}
      {/* ============================================================ */}
      <div className="relative z-10 py-20 px-6 border-t border-gray-800/50">
        <div className="max-w-5xl mx-auto">
          <h2 className="text-3xl font-black text-center mb-4 bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent">30 Cities Across South Florida</h2>
          <p className="text-gray-500 text-center mb-12">City-specific permit requirements for three major counties</p>
          
          <div className="grid md:grid-cols-3 gap-8">
            {/* Broward County */}
            <div className="bg-gray-900/60 rounded-2xl border border-gray-800 overflow-hidden">
              <div className="p-4 bg-cyan-500/10 border-b border-gray-800">
                <h3 className="text-lg font-bold text-cyan-400">Broward County</h3>
                <p className="text-gray-500 text-xs">17 cities</p>
              </div>
              <div className="p-4 space-y-2">
                {['Coconut Creek','Coral Springs','Davie','Deerfield Beach','Fort Lauderdale','Hollywood','Lauderdale-by-the-Sea','Lighthouse Point','Margate','Miramar','Oakland Park','Pembroke Pines','Plantation','Pompano Beach','Sunrise','Tamarac','Weston'].map((c, i) => (
                  <div key={i} className="flex items-center gap-2 text-sm">
                    <span className="text-emerald-400">✓</span>
                    <span className="text-gray-300">{c}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Palm Beach County */}
            <div className="bg-gray-900/60 rounded-2xl border border-gray-800 overflow-hidden">
              <div className="p-4 bg-emerald-500/10 border-b border-gray-800">
                <h3 className="text-lg font-bold text-emerald-400">Palm Beach County</h3>
                <p className="text-gray-500 text-xs">6 cities</p>
              </div>
              <div className="p-4 space-y-2">
                {['Boca Raton','Boynton Beach','Delray Beach','Lake Worth Beach','Wellington','West Palm Beach'].map((c, i) => (
                  <div key={i} className="flex items-center gap-2 text-sm">
                    <span className="text-emerald-400">✓</span>
                    <span className="text-gray-300">{c}</span>
                  </div>
                ))}
                <div className="pt-4 mt-4 border-t border-gray-800">
                  <p className="text-gray-600 text-xs italic">More cities coming soon</p>
                </div>
              </div>
            </div>

            {/* Miami-Dade County */}
            <div className="bg-gray-900/60 rounded-2xl border border-gray-800 overflow-hidden">
              <div className="p-4 bg-purple-500/10 border-b border-gray-800">
                <h3 className="text-lg font-bold text-purple-400">Miami-Dade County</h3>
                <p className="text-gray-500 text-xs">7 cities</p>
              </div>
              <div className="p-4 space-y-2">
                {['Hialeah','Homestead','Kendall (Unincorporated)','Miami','Miami Beach','Miami Gardens','North Miami'].map((c, i) => (
                  <div key={i} className="flex items-center gap-2 text-sm">
                    <span className="text-emerald-400">✓</span>
                    <span className="text-gray-300">{c}</span>
                  </div>
                ))}
                <div className="pt-4 mt-4 border-t border-gray-800">
                  <p className="text-gray-600 text-xs italic">More cities coming soon</p>
                </div>
              </div>
            </div>
          </div>

          <p className="text-center text-gray-600 text-sm mt-8">Don't see your city? <button onClick={() => setPage('contact')} className="text-cyan-400 hover:underline">Let us know</button> — we're adding new cities every month.</p>
        </div>
      </div>

      {/* ============================================================ */}
      {/* SECTION: Final CTA */}
      {/* ============================================================ */}
      <div className="relative z-10 py-20 px-6 border-t border-gray-800/50">
        <div className="max-w-2xl mx-auto text-center">
          <h2 className="text-3xl font-black mb-4 text-white">Ready to Submit with Confidence?</h2>
          <p className="text-gray-400 mb-8">Start with 3 free analyses. No credit card required.</p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <button onClick={() => { setShowRegister(true); window.scrollTo({top: 0, behavior: 'smooth'}) }} className="px-8 py-4 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl hover:scale-105 transition-transform text-lg shadow-lg shadow-cyan-500/25">
              Get Started Free →
            </button>
            <button onClick={() => setPage('pricing')} className="px-8 py-4 border border-gray-700 text-white font-semibold rounded-xl hover:bg-gray-800 transition-colors">
              View Pricing
            </button>
          </div>
        </div>
      </div>
      
      <Footer />
      
      {/* CSS for floating animations */}
      <style>{`
        @keyframes float-1 {
          0%, 100% { transform: translateY(0) translateX(0); opacity: 0.6; }
          25% { transform: translateY(-20px) translateX(10px); opacity: 0.3; }
          50% { transform: translateY(-10px) translateX(-5px); opacity: 0.6; }
          75% { transform: translateY(-30px) translateX(15px); opacity: 0.4; }
        }
        @keyframes float-2 {
          0%, 100% { transform: translateY(0) translateX(0); opacity: 0.4; }
          33% { transform: translateY(-15px) translateX(-10px); opacity: 0.6; }
          66% { transform: translateY(-25px) translateX(5px); opacity: 0.3; }
        }
        @keyframes float-3 {
          0%, 100% { transform: translateY(0) translateX(0); opacity: 0.5; }
          50% { transform: translateY(-20px) translateX(-15px); opacity: 0.3; }
        }
        .animate-float-1 { animation: float-1 8s ease-in-out infinite; }
        .animate-float-2 { animation: float-2 10s ease-in-out infinite; }
        .animate-float-3 { animation: float-3 12s ease-in-out infinite; }
        /* Global cursor fix */
        * { cursor: default !important; }
        a, button, label, select, [role="button"], [onclick], .cursor-pointer { cursor: pointer !important; }
        input, textarea { cursor: text !important; }
        
        /* Testimonial animations */
        @keyframes scroll-left {
          0% { transform: translateX(0); }
          100% { transform: translateX(-50%); }
        }
        .animate-scroll-left {
          animation: scroll-left 40s linear infinite;
        }
        .animate-scroll-left:hover {
          animation-play-state: paused;
        }
        
        @keyframes twinkle {
          0%, 100% { opacity: 1; transform: scale(1); }
          50% { opacity: 0.5; transform: scale(1.3); }
        }
        .star-twinkle {
          animation: twinkle 1.5s ease-in-out infinite;
        }
        
        @keyframes avatar-bounce {
          0%, 100% { transform: translateY(0); }
          50% { transform: translateY(-5px); }
        }
        .avatar-bounce {
          animation: avatar-bounce 2s ease-in-out infinite;
        }
        
        @keyframes border-glow {
          0%, 100% { opacity: 0.3; filter: blur(2px); }
          50% { opacity: 0.6; filter: blur(4px); }
        }
        .animate-border-glow {
          animation: border-glow 3s ease-in-out infinite;
        }
        
        @keyframes float {
          0%, 100% { transform: translateY(0) rotate(0deg); }
          25% { transform: translateY(-8px) rotate(0.5deg); }
          75% { transform: translateY(-4px) rotate(-0.5deg); }
        }
        .review-card {
          animation: float 4s ease-in-out infinite;
        }
        .review-card:nth-child(2n) {
          animation-delay: 0.5s;
        }
        .review-card:nth-child(3n) {
          animation-delay: 1s;
        }
      `}</style>
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
        
        {/* Floating glowing particles */}
        <div className="particle particle-1"></div>
        <div className="particle particle-2"></div>
        <div className="particle particle-3"></div>
        <div className="particle particle-4"></div>
        <div className="particle particle-5"></div>
        <div className="particle particle-6"></div>
        <div className="particle particle-7"></div>
        <div className="particle particle-8"></div>
        <div className="particle particle-9"></div>
        <div className="particle particle-10"></div>
        <div className="particle particle-11"></div>
        <div className="particle particle-12"></div>
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
                <label className="flex items-start gap-3 mb-4 cursor-pointer">
                  <input type="checkbox" required className="mt-1 w-4 h-4 accent-cyan-500" />
                  <span className="text-gray-400 text-sm">I agree to the <button type="button" onClick={() => { setShowRegister(false); setPage('terms') }} className="text-cyan-400 hover:underline">Terms & Conditions</button> and <button type="button" onClick={() => { setShowRegister(false); setPage('privacy') }} className="text-cyan-400 hover:underline">Privacy Policy</button></span>
                </label>
                {error && (
                  <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-xl mb-4">
                    <p className="text-red-400 text-sm font-medium">{error}</p>
                    {error.toLowerCase().includes('already registered') && (
                      <button type="button" onClick={() => { setShowRegister(false); setShowLogin(true); setError('') }} className="text-cyan-400 hover:text-cyan-300 text-sm mt-2 underline">
                        Click here to log in instead
                      </button>
                    )}
                  </div>
                )}
                <button type="submit" className="w-full py-3 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold rounded-xl">Create Account</button>
              </form>
              <p className="text-center mt-4 text-sm text-gray-500">Have an account? <button onClick={() => { setShowRegister(false); setShowLogin(true); setError('') }} className="text-cyan-400 hover:text-cyan-300">Log in</button></p>
            </div>
          </div>
        </div>
      )}

      {/* Review Form Modal */}
      {showReviewForm && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="relative"><div className="absolute -inset-1 bg-gradient-to-r from-amber-500 to-orange-500 rounded-3xl blur-lg opacity-50"></div>
            <div className="relative bg-gray-900 rounded-2xl p-8 max-w-md w-full border border-amber-500/20">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-2xl font-black bg-gradient-to-r from-amber-400 to-orange-400 bg-clip-text text-transparent">Leave a Review</h2>
                <button onClick={() => setShowReviewForm(false)} className="text-2xl text-gray-500 hover:text-white">&times;</button>
              </div>
              <form onSubmit={submitReview}>
                <input name="name" type="text" required placeholder="Your Name" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl mb-4 text-white placeholder-gray-500 focus:border-amber-500 focus:outline-none" />
                <input name="role" type="text" placeholder="Role (e.g. General Contractor, Homeowner)" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl mb-4 text-white placeholder-gray-500 focus:border-amber-500 focus:outline-none" />
                <input name="city" type="text" placeholder="City (optional)" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl mb-4 text-white placeholder-gray-500 focus:border-amber-500 focus:outline-none" />
                
                <div className="mb-4">
                  <label className="block text-gray-400 text-sm mb-2">Rating</label>
                  <div className="flex gap-2">
                    {[1,2,3,4,5].map(star => (
                      <label key={star} className="cursor-pointer">
                        <input type="radio" name="stars" value={star} defaultChecked={star === 5} className="hidden peer" />
                        <span className="text-3xl peer-checked:text-amber-400 text-gray-600 hover:text-amber-300 transition-colors">★</span>
                      </label>
                    ))}
                  </div>
                </div>
                
                <textarea name="review_text" required placeholder="Tell us about your experience with Flo Permit..." rows="4" className="w-full px-4 py-3 bg-black/50 border border-gray-700 rounded-xl mb-4 text-white placeholder-gray-500 focus:border-amber-500 focus:outline-none resize-none"></textarea>
                
                <button type="submit" disabled={reviewSubmitting} className="w-full py-3 bg-gradient-to-r from-amber-500 to-orange-500 text-black font-bold rounded-xl disabled:opacity-50 flex items-center justify-center gap-2">
                  {reviewSubmitting ? <><div className="w-5 h-5 border-2 border-black border-t-transparent rounded-full animate-spin"></div> Submitting...</> : '★ Submit Review'}
                </button>
              </form>
              <p className="text-center mt-4 text-xs text-gray-500">Reviews are moderated before appearing on the site.</p>
            </div>
          </div>
        </div>
      )}

      {loading && (
        <div className="fixed inset-0 z-50 bg-black/95 flex items-center justify-center">
          <div className="text-center">
            {/* Cool document scanning animation */}
            <div className="relative w-32 h-40 mx-auto mb-8">
              {/* Document stack */}
              <div className="absolute inset-0 bg-gray-800 rounded-lg transform rotate-3 translate-x-2 translate-y-2"></div>
              <div className="absolute inset-0 bg-gray-700 rounded-lg transform -rotate-2 translate-x-1 translate-y-1"></div>
              <div className="absolute inset-0 bg-gradient-to-br from-gray-600 to-gray-700 rounded-lg border border-gray-500 overflow-hidden">
                {/* Document lines */}
                <div className="p-3 space-y-2">
                  <div className="h-2 bg-gray-500 rounded w-3/4"></div>
                  <div className="h-2 bg-gray-500 rounded w-full"></div>
                  <div className="h-2 bg-gray-500 rounded w-5/6"></div>
                  <div className="h-2 bg-gray-500 rounded w-2/3"></div>
                  <div className="h-2 bg-gray-500 rounded w-full"></div>
                  <div className="h-2 bg-gray-500 rounded w-4/5"></div>
                  <div className="h-2 bg-gray-500 rounded w-1/2"></div>
                </div>
                {/* Scanning line */}
                <div className="absolute inset-x-0 h-1 bg-gradient-to-r from-transparent via-cyan-400 to-transparent animate-scan"></div>
                {/* Glow effect */}
                <div className="absolute inset-0 bg-gradient-to-b from-cyan-500/20 to-transparent animate-pulse"></div>
              </div>
              {/* Floating checkmarks appearing */}
              <div className="absolute -right-4 top-2 w-6 h-6 bg-emerald-500 rounded-full flex items-center justify-center animate-bounce" style={{animationDelay: '0.5s'}}>
                <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="3" d="M5 13l4 4L19 7"/></svg>
              </div>
              <div className="absolute -right-2 top-14 w-5 h-5 bg-emerald-500 rounded-full flex items-center justify-center animate-bounce" style={{animationDelay: '1s'}}>
                <svg className="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="3" d="M5 13l4 4L19 7"/></svg>
              </div>
              <div className="absolute -left-3 top-8 w-5 h-5 bg-cyan-500 rounded-full flex items-center justify-center animate-bounce" style={{animationDelay: '1.5s'}}>
                <svg className="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="3" d="M5 13l4 4L19 7"/></svg>
              </div>
            </div>
            <h3 className="text-2xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent mb-2">{loadingStatus}</h3>
            <p className="text-gray-500 text-sm">Scanning your documents...</p>
            <div className="mt-4 flex justify-center gap-1">
              <div className="w-2 h-2 bg-cyan-500 rounded-full animate-bounce" style={{animationDelay: '0s'}}></div>
              <div className="w-2 h-2 bg-cyan-500 rounded-full animate-bounce" style={{animationDelay: '0.2s'}}></div>
              <div className="w-2 h-2 bg-cyan-500 rounded-full animate-bounce" style={{animationDelay: '0.4s'}}></div>
            </div>
          </div>
        </div>
      )}
      
      <style>{`
        @keyframes scan {
          0%, 100% { top: 0; opacity: 1; }
          50% { top: 100%; opacity: 0.5; }
        }
        .animate-scan {
          animation: scan 2s ease-in-out infinite;
        }
      `}</style>

      <div className="relative z-10 pt-24 px-6 pb-12 flex-grow">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <span className="px-4 py-1.5 bg-cyan-500/10 border border-cyan-500/20 rounded-full text-cyan-400 text-sm font-semibold">AI-POWERED PERMIT ANALYSIS</span>
            <h1 className="text-5xl md:text-7xl font-black mt-4 mb-6"><span className="bg-gradient-to-r from-white via-gray-200 to-gray-400 bg-clip-text text-transparent">South Florida</span><br/><span className="bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent">Permit Checker</span></h1>
            <p className="text-xl text-gray-400 mb-6">Upload your permit package and get instant AI-powered analysis</p>
            
            <div className="flex items-center justify-center gap-4 text-sm">
              <span className="px-3 py-1 bg-emerald-500/10 border border-emerald-500/20 rounded-full text-emerald-400">3 Counties</span>
              <span className="px-3 py-1 bg-cyan-500/10 border border-cyan-500/20 rounded-full text-cyan-400">30 Cities</span>
              <span className="px-3 py-1 bg-purple-500/10 border border-purple-500/20 rounded-full text-purple-400">More Coming Soon</span>
            </div>
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
                          <option value="Oakland Park">Oakland Park</option>
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
                          <option value="Wellington">Wellington</option>
                          <option value="West Palm Beach">West Palm Beach</option>
                        </>
                      )}
                      {county === 'Miami-Dade' && (
                        <>
                          <option value="Hialeah">Hialeah</option>
                          <option value="Homestead">Homestead</option>
                          <option value="Kendall">Kendall (Unincorporated)</option>
                          <option value="Miami">Miami</option>
                          <option value="Miami Beach">Miami Beach</option>
                          <option value="Miami Gardens">Miami Gardens</option>
                          <option value="North Miami">North Miami</option>
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
                  <input type="file" accept="image/*" capture="environment" onChange={handleFiles} className="hidden" id="cameraInput" />
                  
                  <div className="w-16 h-16 mx-auto mb-4 bg-gradient-to-br from-cyan-500/20 to-emerald-500/20 rounded-2xl flex items-center justify-center border border-cyan-500/30">
                    <svg className="w-8 h-8 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/>
                    </svg>
                  </div>
                  
                  <p className="font-bold text-white mb-2">Drag & drop files here</p>
                  <p className="text-sm text-gray-500 mb-4">PDF, PNG, JPG • Max 50 files</p>
                  
                  <div className="flex flex-wrap items-center justify-center gap-3">
                    <label htmlFor="fileInput" className="cursor-pointer px-4 py-2 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/30 rounded-lg text-cyan-400 text-sm font-semibold transition-all">
                      <span className="flex items-center gap-2">
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                        Select Files
                      </span>
                    </label>
                    <label htmlFor="folderInput" className="cursor-pointer px-4 py-2 bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/30 rounded-lg text-emerald-400 text-sm font-semibold transition-all">
                      <span className="flex items-center gap-2">
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>
                        Select Folder
                      </span>
                    </label>
                    <label htmlFor="cameraInput" className="cursor-pointer px-4 py-2 bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/30 rounded-lg text-purple-400 text-sm font-semibold transition-all md:hidden">
                      <span className="flex items-center gap-2">
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 9a2 2 0 012-2h.93a2 2 0 001.664-.89l.812-1.22A2 2 0 0110.07 4h3.86a2 2 0 011.664.89l.812 1.22A2 2 0 0018.07 7H19a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2V9z"/><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 13a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
                        Take Photo
                      </span>
                    </label>
                  </div>
                  
                  {/* Quality tip */}
                  <p className="text-xs text-gray-600 mt-4">💡 For best results, use scanned PDFs. Phone photos work but may be harder to read.</p>
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
                
                {/* AI Reading Warning */}
                <div className="mt-4 p-3 bg-cyan-500/10 border border-cyan-500/20 rounded-xl flex items-start gap-3">
                  <svg className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                  </svg>
                  <div>
                    <p className="text-cyan-300 text-sm font-medium">Best Results Tip</p>
                    <p className="text-gray-400 text-xs mt-1">Our AI works best with typed text and clear documents. Handwritten notes, cursive, or hard-to-read scans may not be accurately detected. For best results, use digital/typed documents when possible.</p>
                  </div>
                </div>
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
        /* Global cursor fix */
        * { cursor: default !important; }
        a, button, label, select, [role="button"], [onclick], .cursor-pointer { cursor: pointer !important; }
        input, textarea { cursor: text !important; }
        
        /* Glowing particles */
        .particle {
          position: absolute;
          border-radius: 50%;
          pointer-events: none;
          animation: particleFade 6s ease-in-out infinite, particleFloat 8s ease-in-out infinite;
        }
        .particle-1  { width: 4px; height: 4px; background: rgba(6,182,212,0.6); top: 8%; left: 12%; animation-delay: 0s; }
        .particle-2  { width: 6px; height: 6px; background: rgba(16,185,129,0.5); top: 15%; left: 75%; animation-delay: 1s; }
        .particle-3  { width: 3px; height: 3px; background: rgba(6,182,212,0.7); top: 25%; left: 30%; animation-delay: 2s; }
        .particle-4  { width: 5px; height: 5px; background: rgba(139,92,246,0.4); top: 35%; left: 85%; animation-delay: 0.5s; }
        .particle-5  { width: 4px; height: 4px; background: rgba(16,185,129,0.6); top: 50%; left: 8%;  animation-delay: 3s; }
        .particle-6  { width: 7px; height: 7px; background: rgba(6,182,212,0.3); top: 60%; left: 65%; animation-delay: 1.5s; }
        .particle-7  { width: 3px; height: 3px; background: rgba(139,92,246,0.5); top: 70%; left: 20%; animation-delay: 4s; }
        .particle-8  { width: 5px; height: 5px; background: rgba(6,182,212,0.5); top: 80%; left: 50%; animation-delay: 2.5s; }
        .particle-9  { width: 4px; height: 4px; background: rgba(16,185,129,0.4); top: 12%; left: 45%; animation-delay: 3.5s; }
        .particle-10 { width: 6px; height: 6px; background: rgba(6,182,212,0.4); top: 45%; left: 92%; animation-delay: 0.8s; }
        .particle-11 { width: 3px; height: 3px; background: rgba(139,92,246,0.6); top: 88%; left: 35%; animation-delay: 2.2s; }
        .particle-12 { width: 5px; height: 5px; background: rgba(16,185,129,0.5); top: 5%;  left: 58%; animation-delay: 4.5s; }
        
        @keyframes particleFade {
          0%, 100% { opacity: 0; transform: scale(0.5); }
          20% { opacity: 1; transform: scale(1); }
          50% { opacity: 0.8; transform: scale(1.2); }
          80% { opacity: 1; transform: scale(1); }
        }
        @keyframes particleFloat {
          0%, 100% { transform: translateY(0) translateX(0); }
          25% { transform: translateY(-15px) translateX(8px); }
          50% { transform: translateY(-8px) translateX(-5px); }
          75% { transform: translateY(-20px) translateX(12px); }
        }
      `}</style>
    </div>
  )
}