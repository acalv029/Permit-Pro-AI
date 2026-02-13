// Run from your project root: node patch_admin.js
const fs = require('fs');
const path = require('path');

const file = path.join('frontend', 'src', 'App.jsx');
let content = fs.readFileSync(file, 'utf8');

// === CHANGE 1: Add adminPurchases state ===
content = content.replace(
  `const [adminReviews, setAdminReviews] = useState([])`,
  `const [adminReviews, setAdminReviews] = useState([])
  const [adminPurchases, setAdminPurchases] = useState([])`
);
console.log('✅ Change 1: Added adminPurchases state');

// === CHANGE 2: Add loadAdminPurchases + updateAdminPurchase functions ===
const oldLine = `const loadAdminReviews = async () => { if (!authToken) return; try { const res = await fetch(\`\${API_BASE_URL}/api/admin/reviews\`, { headers: { 'Authorization': \`Bearer \${authToken}\` } }); if (res.ok) { const data = await res.json(); setAdminReviews(data.reviews || []) } } catch (err) { console.error(err) } }`;

const newLine = `const loadAdminReviews = async () => { if (!authToken) return; try { const res = await fetch(\`\${API_BASE_URL}/api/admin/reviews\`, { headers: { 'Authorization': \`Bearer \${authToken}\` } }); if (res.ok) { const data = await res.json(); setAdminReviews(data.reviews || []) } } catch (err) { console.error(err) } }
  const loadAdminPurchases = async () => { if (!authToken) return; try { const res = await fetch(\`\${API_BASE_URL}/api/admin/single-purchases\`, { headers: { 'Authorization': \`Bearer \${authToken}\` } }); if (res.ok) { const data = await res.json(); setAdminPurchases(data.purchases || []) } } catch (err) { console.error(err) } }
  const updateAdminPurchase = async (purchaseUuid, updates) => { try { const res = await fetch(\`\${API_BASE_URL}/api/admin/single-purchase/\${purchaseUuid}\`, { method: 'PUT', headers: { 'Content-Type': 'application/json', 'Authorization': \`Bearer \${authToken}\` }, body: JSON.stringify(updates) }); if (res.ok) { alert('Purchase updated!'); loadAdminPurchases() } else { const data = await res.json(); alert(data.detail || 'Update failed') } } catch (err) { alert('Error updating purchase') } }`;

content = content.replace(oldLine, newLine);
console.log('✅ Change 2: Added loadAdminPurchases + updateAdminPurchase functions');

// === CHANGE 3: Add loadAdminPurchases to useEffect ===
content = content.replace(
  `loadAdminStats(); loadAdminReviews() }`,
  `loadAdminStats(); loadAdminReviews(); loadAdminPurchases() }`
);
console.log('✅ Change 3: Added loadAdminPurchases to useEffect');

// === CHANGE 4: Add Single Purchases UI section above Reviews Management ===
const reviewsSectionStart = `              {/* Reviews Management */}`;

const purchasesUI = `              {/* Single Purchases Management */}
              <div className="bg-gradient-to-r from-cyan-900/30 to-emerald-900/30 rounded-xl p-6 border border-cyan-500/30">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-bold text-white flex items-center gap-2"><span className="text-xl">🏠</span> Single Purchases</h3>
                  <button onClick={loadAdminPurchases} className="px-3 py-1 bg-cyan-500/20 text-cyan-400 rounded-lg text-sm hover:bg-cyan-500/30">↻ Refresh</button>
                </div>
                {adminPurchases.length === 0 ? (
                  <p className="text-gray-500">No single purchases yet</p>
                ) : (
                  <div className="space-y-4">
                    {adminPurchases.map(p => (
                      <div key={p.id} className={\`p-4 rounded-xl border \${p.analysis_used ? 'bg-gray-800/50 border-gray-700' : 'bg-emerald-900/20 border-emerald-500/30'}\`}>
                        <div className="flex items-start justify-between gap-4">
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-1 flex-wrap">
                              <span className="font-semibold text-white">{p.email}</span>
                              <span className={\`px-2 py-0.5 rounded-full text-xs font-bold \${p.payment_status === 'paid' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400'}\`}>{p.payment_status}</span>
                              <span className={\`px-2 py-0.5 rounded-full text-xs font-bold \${p.analysis_used ? 'bg-red-500/20 text-red-400' : 'bg-cyan-500/20 text-cyan-400'}\`}>{p.analysis_used ? 'Used' : 'Available'}</span>
                            </div>
                            <div className="text-sm text-gray-400 mb-1">{p.city} • {p.permit_type}</div>
                            <div className="text-xs text-gray-500">
                              Purchased: {new Date(p.created_at).toLocaleDateString()} • 
                              Expires: {p.expires_at ? new Date(p.expires_at).toLocaleDateString() : 'N/A'} • 
                              UUID: <span className="font-mono text-gray-600">{p.purchase_uuid?.slice(0, 8)}...</span>
                            </div>
                          </div>
                          <div className="flex flex-col gap-2">
                            {p.analysis_used && (
                              <button 
                                onClick={() => { if (confirm(\`Reset analysis for \${p.email}? They can analyze again.\`)) updateAdminPurchase(p.purchase_uuid, { reset_analysis: true }) }}
                                className="px-3 py-1 bg-cyan-500/20 text-cyan-400 rounded-lg text-xs font-bold hover:bg-cyan-500/30"
                              >
                                ↻ Reset Analysis
                              </button>
                            )}
                            <button 
                              onClick={() => updateAdminPurchase(p.purchase_uuid, { extend_days: 30 })}
                              className="px-3 py-1 bg-emerald-500/20 text-emerald-400 rounded-lg text-xs font-bold hover:bg-emerald-500/30"
                            >
                              +30 Days
                            </button>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Reviews Management */}`;

content = content.replace(reviewsSectionStart, purchasesUI);
console.log('✅ Change 4: Added Single Purchases UI to admin page');

// Save
fs.writeFileSync(file, content, 'utf8');
console.log('\n🎉 All changes applied! File saved.');
console.log('Now run:');
console.log('  git add frontend/src/App.jsx');
console.log('  git commit -m "Add single purchases management to admin"');
console.log('  git push');
