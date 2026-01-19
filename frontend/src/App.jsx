/**
 * South Florida Permit Helper - Frontend
 * Matches backend API structure: /api/analyze-permit with city and permit_type
 */

import { useState, useEffect } from 'react'
import './App.css'

// ✅ UPDATE THIS to your Railway backend URL
const API_URL = 'https://south-florida-permit-helper-production-9d6f.up.railway.app'

function App() {
  const [cities, setCities] = useState({})
  const [selectedCity, setSelectedCity] = useState('')
  const [permitTypes, setPermitTypes] = useState([])
  const [selectedPermitType, setSelectedPermitType] = useState('')
  const [file, setFile] = useState(null)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [loadingCities, setLoadingCities] = useState(true)

  // Load cities on mount
  useEffect(() => {
    loadCities()
  }, [])

  // Load permit types when city changes
  useEffect(() => {
    if (selectedCity) {
      loadPermitTypes(selectedCity)
    }
  }, [selectedCity])

  const loadCities = async () => {
    try {
      console.log('📍 Loading cities...')
      const response = await fetch(`${API_URL}/api/cities`)
      if (!response.ok) throw new Error('Failed to load cities')
      const data = await response.json()
      setCities(data)
      console.log('✅ Cities loaded:', Object.keys(data).length)
    } catch (err) {
      console.error('❌ Error loading cities:', err)
      setError('Failed to load cities. Check if backend is running.')
    } finally {
      setLoadingCities(false)
    }
  }

  const loadPermitTypes = async (cityKey) => {
    try {
      console.log(`📋 Loading permit types for: ${cityKey}`)
      const response = await fetch(`${API_URL}/api/permits/${cityKey}`)
      if (!response.ok) throw new Error('Failed to load permit types')
      const data = await response.json()
      setPermitTypes(data.permit_types || [])
      console.log('✅ Permit types loaded:', data.permit_types?.length || 0)
    } catch (err) {
      console.error('❌ Error loading permit types:', err)
      setPermitTypes([])
    }
  }

  const handleCityChange = (e) => {
    const cityName = e.target.value
    setSelectedCity(cityName)
    setSelectedPermitType('')
    setPermitTypes([])
    
    // Find city key from cities object
    if (cityName && cities[cityName]) {
      const cityData = cities[cityName]
      console.log(`Selected city: ${cityName} (${cityData.key})`)
    }
  }

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0]
    
    if (!selectedFile) return

    // Validate file type
    const allowedTypes = ['application/pdf', 'image/png', 'image/jpeg']
    if (!allowedTypes.includes(selectedFile.type)) {
      setError('Please upload a PDF, PNG, or JPG file')
      setFile(null)
      return
    }

    // Validate file size (10MB max)
    const maxSize = 10 * 1024 * 1024
    if (selectedFile.size > maxSize) {
      setError('File size must be less than 10MB')
      setFile(null)
      return
    }

    setFile(selectedFile)
    setError(null)
    setResult(null)
    console.log('✅ File selected:', selectedFile.name)
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    
    // Validation
    if (!selectedCity) {
      setError('Please select a city')
      return
    }
    if (!selectedPermitType) {
      setError('Please select a permit type')
      return
    }
    if (!file) {
      setError('Please select a file')
      return
    }

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      console.log('📤 Uploading permit for analysis...')
      console.log(`  City: ${selectedCity}`)
      console.log(`  Permit Type: ${selectedPermitType}`)
      console.log(`  File: ${file.name}`)
      
      // Create FormData with city, permit_type, and file
      const formData = new FormData()
      formData.append('file', file)
      formData.append('city', selectedCity)
      formData.append('permit_type', selectedPermitType)

      // Send to backend
      const response = await fetch(`${API_URL}/api/analyze-permit`, {
        method: 'POST',
        body: formData,
      })

      console.log('📥 Response status:', response.status)

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ 
          detail: `Server error: ${response.statusText}` 
        }))
        throw new Error(errorData.detail || `Upload failed: ${response.status}`)
      }

      const data = await response.json()
      console.log('✅ Analysis complete:', data)
      
      setResult(data)
      setError(null)

    } catch (err) {
      console.error('❌ Upload error:', err)
      
      if (err.message.includes('Failed to fetch')) {
        setError(
          'Cannot connect to server. Please check:\n' +
          '1. Backend is running on Railway\n' +
          '2. CORS is configured correctly\n' +
          '3. Your internet connection'
        )
      } else {
        setError(err.message || 'An error occurred during analysis')
      }
      
      setResult(null)
    } finally {
      setLoading(false)
    }
  }

  const handleReset = () => {
    setSelectedCity('')
    setSelectedPermitType('')
    setPermitTypes([])
    setFile(null)
    setResult(null)
    setError(null)
  }

  if (loadingCities) {
    return (
      <div className="App">
        <div className="loading-screen">
          <div className="spinner"></div>
          <p>Loading cities...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="App">
      <header className="App-header">
        <h1>🏗️ South Florida Permit Helper</h1>
        <p>AI-powered permit analysis for South Florida municipalities</p>
      </header>

      <main className="main-content">
        <div className="upload-section">
          <form onSubmit={handleSubmit}>
            {/* City Selection */}
            <div className="form-group">
              <label htmlFor="city-select">
                📍 Select City
              </label>
              <select
                id="city-select"
                value={selectedCity}
                onChange={handleCityChange}
                disabled={loading}
                required
              >
                <option value="">-- Choose a city --</option>
                {Object.keys(cities).map((cityName) => (
                  <option key={cityName} value={cityName}>
                    {cityName} ({cities[cityName].county})
                  </option>
                ))}
              </select>
              
              {selectedCity && cities[selectedCity] && (
                <div className="city-info">
                  <small>
                    📞 {cities[selectedCity].phone}<br/>
                    📍 {cities[selectedCity].address}
                  </small>
                </div>
              )}
            </div>

            {/* Permit Type Selection */}
            <div className="form-group">
              <label htmlFor="permit-select">
                📋 Select Permit Type
              </label>
              <select
                id="permit-select"
                value={selectedPermitType}
                onChange={(e) => setSelectedPermitType(e.target.value)}
                disabled={!selectedCity || loading}
                required
              >
                <option value="">-- Choose permit type --</option>
                {permitTypes.map((permit) => (
                  <option key={permit} value={permit}>
                    {permit}
                  </option>
                ))}
              </select>
            </div>

            {/* File Upload */}
            <div className="form-group">
              <label htmlFor="file-upload" className="file-label">
                {file ? (
                  <span>📄 {file.name} ({(file.size / 1024).toFixed(2)} KB)</span>
                ) : (
                  <span>📎 Choose Permit Document (PDF, PNG, JPG)</span>
                )}
              </label>
              <input
                id="file-upload"
                type="file"
                accept=".pdf,.png,.jpg,.jpeg"
                onChange={handleFileChange}
                disabled={loading}
              />
            </div>

            {/* Buttons */}
            <div className="button-group">
              <button
                type="submit"
                disabled={!selectedCity || !selectedPermitType || !file || loading}
                className="btn btn-primary"
              >
                {loading ? '🔄 Analyzing...' : '🚀 Analyze Permit'}
              </button>

              {(selectedCity || file) && (
                <button
                  type="button"
                  onClick={handleReset}
                  disabled={loading}
                  className="btn btn-secondary"
                >
                  🔄 Reset
                </button>
              )}
            </div>
          </form>
        </div>

        {/* Error Display */}
        {error && (
          <div className="error-box">
            <h3>❌ Error</h3>
            <pre>{error}</pre>
          </div>
        )}

        {/* Results Display */}
        {result && (
          <div className="results-box">
            <h2>✅ Analysis Complete</h2>
            
            <div className="info-section">
              <h3>📄 Permit Information</h3>
              <p><strong>City:</strong> {result.city}</p>
              <p><strong>Permit Type:</strong> {result.permit_type}</p>
              <p><strong>Analysis ID:</strong> {result.analysis_id}</p>
            </div>

            {result.analysis && (
              <div className="analysis-section">
                <h3>🔍 Analysis Results</h3>
                <div className="analysis-content">
                  {typeof result.analysis === 'string' ? (
                    <pre className="analysis-text">{result.analysis}</pre>
                  ) : (
                    <pre className="analysis-text">
                      {JSON.stringify(result.analysis, null, 2)}
                    </pre>
                  )}
                </div>
              </div>
            )}

            <details className="debug-section">
              <summary>🔧 Debug: Full Response</summary>
              <pre>{JSON.stringify(result, null, 2)}</pre>
            </details>
          </div>
        )}

        {/* Loading State */}
        {loading && (
          <div className="loading-box">
            <div className="spinner"></div>
            <p>Analyzing your permit document...</p>
            <p className="small-text">This may take 30-60 seconds</p>
          </div>
        )}
      </main>

      <footer className="footer">
        <p>Powered by Claude AI • Covering 6 South Florida cities</p>
      </footer>
    </div>
  )
}

export default App