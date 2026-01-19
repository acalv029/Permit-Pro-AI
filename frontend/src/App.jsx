import React, { useState } from 'react';
import { Upload, FileText, CheckCircle, AlertCircle, Building2, MapPin, Palmtree } from 'lucide-react';

export default function App() {
  const [selectedCity, setSelectedCity] = useState('Fort Lauderdale');
  const [selectedPermit, setSelectedPermit] = useState('building');
  const [analyzing, setAnalyzing] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);

  const cities = {
    'Fort Lauderdale': { county: 'Broward County', phone: '(954) 828-6520' },
    'Pompano Beach': { county: 'Broward County', phone: '(954) 786-4600' },
    'Lauderdale-by-the-Sea': { county: 'Broward County', phone: '(954) 640-4215' },
    'Coral Springs': { county: 'Broward County', phone: '(954) 344-1111' },
    'Hollywood': { county: 'Broward County', phone: '(954) 921-3201' },
    'Boca Raton': { county: 'Palm Beach County', phone: '(561) 393-7930' },
  };

  const permitTypes = {
    building: 'Building Permit',
    electrical: 'Electrical Permit',
    plumbing: 'Plumbing Permit',
    mechanical: 'Mechanical/HVAC Permit',
    roofing: 'Roofing Permit',
    dock: 'Dock/Marine Structure',
    seawall: 'Seawall Permit',
    boat_lift: 'Boat Lift Permit',
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const allowedTypes = ['application/pdf', 'image/png', 'image/jpeg'];
    if (!allowedTypes.includes(file.type)) {
      setError('Please upload a PDF, PNG, or JPG file');
      return;
    }

    setAnalyzing(true);
    setError(null);
    setResults(null);

    const formData = new FormData();
    formData.append('file', file);
    formData.append('city', selectedCity);
    formData.append('permit_type', selectedPermit);

    try {
      const response = await fetch('https://south-florida-permit-checker-production.up.railway.app', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.detail || 'Analysis failed');
      }

      const data = await response.json();
      setResults(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-sky-50 via-blue-50 to-cyan-50">
      {/* Navigation */}
      <nav className="bg-white/80 backdrop-blur-xl border-b border-blue-100 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-20">
            <div className="flex items-center space-x-3">
              <div className="bg-gradient-to-br from-blue-600 to-cyan-600 p-2 rounded-xl">
                <Building2 className="w-7 h-7 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-gray-900" style={{fontFamily: 'Montserrat, sans-serif'}}>
                  South Florida Permits
                </h1>
                <p className="text-xs text-gray-500">AI-Powered Analysis</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <a href="#pricing" className="text-gray-600 hover:text-blue-600 transition font-medium">
                Pricing
              </a>
              <button className="px-5 py-2.5 bg-gradient-to-r from-blue-600 to-cyan-600 text-white rounded-xl hover:shadow-lg transition-all font-medium">
                Sign In
              </button>
            </div>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
        <div className="text-center mb-12">
          <div className="inline-flex items-center space-x-2 bg-blue-100 px-4 py-2 rounded-full mb-6">
            <Palmtree className="w-5 h-5 text-blue-600" />
            <span className="text-sm font-semibold text-blue-700">Trusted by 500+ Contractors</span>
          </div>
          <h2 className="text-6xl font-bold mb-4 bg-gradient-to-r from-blue-600 via-cyan-600 to-blue-600 bg-clip-text text-transparent" style={{fontFamily: 'Montserrat, sans-serif'}}>
            Check Your Permits
          </h2>
          <h3 className="text-6xl font-bold mb-6 text-gray-900" style={{fontFamily: 'Montserrat, sans-serif'}}>
            Before You Submit
          </h3>
          <p className="text-xl text-gray-600 max-w-2xl mx-auto">
            AI-powered analysis ensures your permit applications are complete and compliant
            across all South Florida municipalities.
          </p>
        </div>

        {/* Main Card */}
        <div className="max-w-5xl mx-auto">
          <div className="bg-white rounded-3xl shadow-2xl overflow-hidden border border-gray-100">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-0">
              
              {/* Left Panel - Configuration */}
              <div className="bg-gradient-to-br from-blue-50 to-cyan-50 p-8 border-r border-gray-100">
                <h3 className="text-2xl font-bold text-gray-900 mb-6" style={{fontFamily: 'Montserrat, sans-serif'}}>
                  Configure Check
                </h3>
                
                {/* City Selector */}
                <div className="mb-6">
                  <label className="flex items-center text-sm font-semibold text-gray-700 mb-3">
                    <MapPin className="w-4 h-4 mr-2 text-blue-600" />
                    Select Your City
                  </label>
                  <select
                    value={selectedCity}
                    onChange={(e) => setSelectedCity(e.target.value)}
                    className="w-full px-4 py-3 bg-white border-2 border-gray-200 rounded-xl focus:border-blue-500 focus:ring focus:ring-blue-200 transition appearance-none cursor-pointer font-medium"
                  >
                    {Object.keys(cities).map((city) => (
                      <option key={city} value={city}>{city}</option>
                    ))}
                  </select>
                  <div className="mt-2 text-sm text-gray-600">
                    📞 {cities[selectedCity].phone}
                  </div>
                  <div className="text-xs text-gray-500">
                    {cities[selectedCity].county}
                  </div>
                </div>

                {/* Permit Type Selector */}
                <div className="mb-6">
                  <label className="flex items-center text-sm font-semibold text-gray-700 mb-3">
                    <FileText className="w-4 h-4 mr-2 text-blue-600" />
                    Permit Type
                  </label>
                  <select
                    value={selectedPermit}
                    onChange={(e) => setSelectedPermit(e.target.value)}
                    className="w-full px-4 py-3 bg-white border-2 border-gray-200 rounded-xl focus:border-blue-500 focus:ring focus:ring-blue-200 transition appearance-none cursor-pointer font-medium"
                  >
                    {Object.entries(permitTypes).map(([key, name]) => (
                      <option key={key} value={key}>{name}</option>
                    ))}
                  </select>
                </div>

                {/* Upload Area */}
                <div className="mb-6">
                  <label className="flex items-center text-sm font-semibold text-gray-700 mb-3">
                    <Upload className="w-4 h-4 mr-2 text-blue-600" />
                    Upload Document
                  </label>
                  <div className="relative">
                    <input
                      type="file"
                      accept=".pdf,.png,.jpg,.jpeg"
                      onChange={handleFileUpload}
                      className="hidden"
                      id="file-upload"
                    />
                    <label
                      htmlFor="file-upload"
                      className="flex flex-col items-center justify-center w-full h-40 bg-white border-2 border-dashed border-blue-300 rounded-xl cursor-pointer hover:border-blue-500 hover:bg-blue-50 transition group"
                    >
                      <Upload className="w-10 h-10 text-blue-400 group-hover:text-blue-600 mb-3 transition" />
                      <span className="text-sm font-medium text-gray-700 group-hover:text-blue-600 transition">
                        {analyzing ? 'Analyzing...' : 'Click to upload or drag file'}
                      </span>
                      <span className="text-xs text-gray-500 mt-1">
                        PDF, PNG, JPG (Max 10MB)
                      </span>
                    </label>
                  </div>
                </div>

                {error && (
                  <div className="p-4 bg-red-50 border border-red-200 rounded-xl flex items-start space-x-3">
                    <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
                    <div className="flex-1">
                      <p className="text-sm font-medium text-red-800">Error</p>
                      <p className="text-sm text-red-700">{error}</p>
                    </div>
                  </div>
                )}
              </div>

              {/* Right Panel - Results */}
              <div className="p-8 bg-white">
                {!results && !analyzing && (
                  <div className="h-full flex flex-col items-center justify-center text-center">
                    <div className="w-20 h-20 bg-gradient-to-br from-blue-100 to-cyan-100 rounded-2xl flex items-center justify-center mb-4">
                      <CheckCircle className="w-10 h-10 text-blue-600" />
                    </div>
                    <h4 className="text-lg font-bold text-gray-900 mb-2" style={{fontFamily: 'Montserrat, sans-serif'}}>
                      Ready to Check
                    </h4>
                    <p className="text-sm text-gray-600 max-w-xs">
                      Upload your permit document to receive instant AI-powered analysis
                    </p>
                  </div>
                )}

                {analyzing && (
                  <div className="h-full flex flex-col items-center justify-center">
                    <div className="animate-spin rounded-full h-16 w-16 border-4 border-blue-200 border-t-blue-600 mb-4"></div>
                    <p className="text-lg font-semibold text-gray-900">Analyzing Document...</p>
                    <p className="text-sm text-gray-600 mt-2">This may take a few seconds</p>
                  </div>
                )}

                {results && (
                  <div className="h-full overflow-y-auto">
                    <div className="flex items-center justify-between mb-6 pb-4 border-b border-gray-200">
                      <div>
                        <h4 className="text-xl font-bold text-gray-900" style={{fontFamily: 'Montserrat, sans-serif'}}>
                          Analysis Complete
                        </h4>
                        <p className="text-sm text-gray-600 mt-1">
                          {results.permit_type} • {selectedCity}
                        </p>
                      </div>
                      <CheckCircle className="w-8 h-8 text-green-500" />
                    </div>
                    
                    <div className="prose prose-sm max-w-none">
                      <div 
                        className="text-sm text-gray-700 leading-relaxed"
                        dangerouslySetInnerHTML={{ 
                          __html: results.analysis
                            .replace(/## /g, '<h3 class="text-lg font-bold text-gray-900 mt-4 mb-2">')
                            .replace(/### /g, '<h4 class="text-base font-semibold text-gray-800 mt-3 mb-2">')
                            .replace(/• /g, '<li>')
                            .replace(/\n/g, '<br/>')
                        }}
                      />
                    </div>

                    <button className="w-full mt-6 px-6 py-3 bg-gradient-to-r from-blue-600 to-cyan-600 text-white rounded-xl font-semibold hover:shadow-lg transition-all">
                      Download Full Report
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mt-16 max-w-5xl mx-auto">
          {[
            { number: '6', label: 'Cities Covered' },
            { number: '8', label: 'Permit Types' },
            { number: '500+', label: 'Contractors' },
            { number: '24/7', label: 'Available' },
          ].map((stat, idx) => (
            <div key={idx} className="bg-white rounded-2xl p-6 text-center shadow-lg border border-gray-100">
              <div className="text-4xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-600 to-cyan-600 mb-2" style={{fontFamily: 'Montserrat, sans-serif'}}>
                {stat.number}
              </div>
              <div className="text-sm font-medium text-gray-600">{stat.label}</div>
            </div>
          ))}
        </div>

        {/* Pricing */}
        <div id="pricing" className="mt-24">
          <div className="text-center mb-12">
            <h3 className="text-4xl font-bold text-gray-900 mb-4" style={{fontFamily: 'Montserrat, sans-serif'}}>
              Simple Pricing
            </h3>
            <p className="text-lg text-gray-600">Choose the plan that fits your needs</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-6xl mx-auto">
            {[
              {
                name: 'Free',
                price: '$0',
                features: ['3 checks/month', 'Basic analysis', '6 cities', 'Community support'],
                cta: 'Get Started',
                highlighted: false,
              },
              {
                name: 'Contractor Pro',
                price: '$49',
                features: ['Unlimited checks', 'AI analysis', 'All cities', 'Priority support', 'PDF reports', 'Save history'],
                cta: 'Start Free Trial',
                highlighted: true,
              },
              {
                name: 'Business',
                price: '$149',
                features: ['Everything in Pro', 'Team (5 users)', 'API access', 'White-label', 'Dedicated support', 'Training'],
                cta: 'Contact Sales',
                highlighted: false,
              },
            ].map((plan, idx) => (
              <div
                key={idx}
                className={`rounded-3xl p-8 ${
                  plan.highlighted
                    ? 'bg-gradient-to-br from-blue-600 to-cyan-600 text-white shadow-2xl scale-105'
                    : 'bg-white border-2 border-gray-100 shadow-lg'
                }`}
              >
                {plan.highlighted && (
                  <div className="text-xs font-bold uppercase tracking-wider mb-2 text-blue-100">
                    Most Popular
                  </div>
                )}
                <h4 className="text-2xl font-bold mb-2" style={{fontFamily: 'Montserrat, sans-serif'}}>
                  {plan.name}
                </h4>
                <div className="text-4xl font-bold mb-1" style={{fontFamily: 'Montserrat, sans-serif'}}>
                  {plan.price}
                </div>
                <div className={`text-sm mb-6 ${plan.highlighted ? 'text-blue-100' : 'text-gray-600'}`}>
                  per month
                </div>
                <ul className="space-y-3 mb-8">
                  {plan.features.map((feature, i) => (
                    <li key={i} className="flex items-center text-sm">
                      <CheckCircle className={`w-5 h-5 mr-3 flex-shrink-0 ${plan.highlighted ? 'text-blue-200' : 'text-blue-600'}`} />
                      <span>{feature}</span>
                    </li>
                  ))}
                </ul>
                <button
                  className={`w-full py-3 rounded-xl font-semibold transition-all ${
                    plan.highlighted
                      ? 'bg-white text-blue-600 hover:shadow-xl'
                      : 'bg-gradient-to-r from-blue-600 to-cyan-600 text-white hover:shadow-lg'
                  }`}
                >
                  {plan.cta}
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="bg-gray-900 text-white mt-24 py-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <div className="flex items-center justify-center space-x-3 mb-4">
              <div className="bg-gradient-to-br from-blue-500 to-cyan-500 p-2 rounded-xl">
                <Building2 className="w-6 h-6" />
              </div>
              <span className="text-xl font-bold" style={{fontFamily: 'Montserrat, sans-serif'}}>
                South Florida Permits
              </span>
            </div>
            <p className="text-gray-400 mb-8">
              AI-Powered Permit Analysis for South Florida Contractors
            </p>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm text-gray-400 max-w-2xl mx-auto mb-8">
              {Object.keys(cities).map((city) => (
                <div key={city}>{city}</div>
              ))}
            </div>
            <div className="text-sm text-gray-500">
              © 2025 South Florida Permits. All rights reserved.
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
