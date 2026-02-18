// Run from Permit-Pro-AI folder: node fixall.js
const fs = require('fs');
const path = require('path');

const file = path.join('frontend', 'src', 'App.jsx');
let content = fs.readFileSync(file, 'utf8');

let changes = 0;

// 1. Add adminPurchases state
if (!content.includes('adminPurchases')) {
  content = content.replace(
    'const [adminReviews, setAdminReviews] = useState([])',
    'const [adminReviews, setAdminReviews] = useState([])\n  const [adminPurchases, setAdminPurchases] = useState([])'
  );
  changes++;
  console.log('1. Added adminPurchases state');
}

// 2. Add functions
if (!content.includes('loadAdminPurchases')) {
  const oldFunc = `const loadAdminReviews = async () => { if (!authToken) return; try { const res = await fetch(\`\${API_BASE_URL}/api/admin/reviews\`, { headers: { 'Authorization': \`Bearer \${authToken}\` } }); if (res.ok) { const data = await res.json(); setAdminReviews(data.reviews || []) } } catch (err) { console.error(err) } }`;
  const newFunc = oldFunc + `
  const loadAdminPurchases = async () => { if (!authToken) return; try { const res = await fetch(\`\${API_BASE_URL}/api/admin/single-purchases\`, { headers: { 'Authorization': \`Bearer \${authToken}\` } }); if (res.ok) { const data = await res.json(); setAdminPurchases(data.purchases || []) } } catch (err) { console.error(err) } }
  const updateAdminPurchase = async (purchaseUuid, updates) => { try { const res = await fetch(\`\${API_BASE_URL}/api/admin/single-purchase/\${purchaseUuid}\`, { method: 'PUT', headers: { 'Content-Type': 'application/json', 'Authorization': \`Bearer \${authToken}\` }, body: JSON.stringify(updates) }); if (res.ok) { alert('Purchase updated!'); loadAdminPurchases() } else { const data = await res.json(); alert(data.detail || 'Update failed') } } catch (err) { alert('Error updating purchase') } }`;
  if (content.includes(oldFunc)) {
    content = content.replace(oldFunc, newFunc);
    changes++;
    console.log('2. Added functions');
  } else { console.log('2. WARN: Could not find insert point'); }
}

// 3. Add to useEffect
if (!content.includes('loadAdminPurchases()')) {
  content = content.replace(
    'loadAdminStats(); loadAdminReviews() }',
    'loadAdminStats(); loadAdminReviews(); loadAdminPurchases() }'
  );
  changes++;
  console.log('3. Updated useEffect');
}

// 4. Add Single Purchases UI
if (!content.includes('Single Purchases Management')) {
  const old = '              {/* Reviews Management */}';
  const ui = `              {/* Single Purchases Management */}
              <div className="bg-gradient-to-r from-cyan-900/30 to-emerald-900/30 rounded-xl p-6 border border-cyan-500/30">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-bold text-white flex items-center gap-2"><span className="text-xl">\u{1F3E0}</span> Single Purchases</h3>
                  <button onClick={loadAdminPurchases} className="px-3 py-1 bg-cyan-500/20 text-cyan-400 rounded-lg text-sm hover:bg-cyan-500/30">\u{21BB} Refresh</button>
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
                            <div className="text-sm text-gray-400 mb-1">{p.city} \u{2022} {p.permit_type}</div>
                            <div className="text-xs text-gray-500">Purchased: {new Date(p.created_at).toLocaleDateString()} \u{2022} Expires: {p.expires_at ? new Date(p.expires_at).toLocaleDateString() : 'N/A'}</div>
                          </div>
                          <div className="flex flex-col gap-2">
                            {p.analysis_used && (
                              <button onClick={() => { if (confirm(\`Reset analysis for \${p.email}?\`)) updateAdminPurchase(p.purchase_uuid, { reset_analysis: true }) }} className="px-3 py-1 bg-cyan-500/20 text-cyan-400 rounded-lg text-xs font-bold hover:bg-cyan-500/30">\u{21BB} Reset</button>
                            )}
                            <button onClick={() => updateAdminPurchase(p.purchase_uuid, { extend_days: 30 })} className="px-3 py-1 bg-emerald-500/20 text-emerald-400 rounded-lg text-xs font-bold hover:bg-emerald-500/30">+30 Days</button>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Reviews Management */}`;
  if (content.includes(old)) {
    content = content.replace(old, ui);
    changes++;
    console.log('4. Added Single Purchases UI');
  } else { console.log('4. WARN: Could not find insert point'); }
}

// 5. Free tier text
const subs = [
  ['3 analyses/month', '1 analysis/month'],
  ['3 free analyses', '1 free analysis'],
  ['3 analyses per month', '1 analysis per month'],
  ['3 permit checks per month', '1 permit check per month'],
  ['3 permit checks', '1 permit check'],
  ['Start with 3', 'Start with 1'],
  ['3 free', '1 free'],
];
let t = 0;
for (const [o, n] of subs) {
  if (content.includes(o)) { content = content.replaceAll(o, n); t++; }
}
if (t > 0) { changes++; console.log('5. Updated free tier text'); }

fs.writeFileSync(file, content, 'utf8');
console.log('\nDone! ' + changes + ' changes. Now test: cd frontend && npm run build');
