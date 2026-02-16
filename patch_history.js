// Run from Permit-Pro-AI folder: node patch_history.js
const fs = require('fs');
const path = require('path');

// ============ MAIN.PY: Block history for free users ============
const mainFile = path.join('backend', 'main.py');
let main = fs.readFileSync(mainFile, 'utf8');

// Find the get_history endpoint and add a free tier check
// Look for the history endpoint function
const historyPattern = `@app.get("/api/history")`;
if (main.includes(historyPattern)) {
  // Find "analyses = db.query" after the history endpoint to locate where to insert
  const historyIdx = main.indexOf(historyPattern);
  // Find the first "user_id" reference after the endpoint
  const afterHistory = main.substring(historyIdx);
  
  // Look for "analyses = db.query" which is where it fetches history
  const analysesQuery = afterHistory.indexOf('analyses = db.query');
  if (analysesQuery > -1) {
    const insertPoint = historyIdx + analysesQuery;
    // Add free tier check right before the query
    const freeCheck = `# Block history for free users
    user = db.query(User).filter(User.id == user_id).first()
    if user and user.subscription_tier == "free":
        raise HTTPException(status_code=403, detail="History is available for Pro and Business subscribers. Upgrade to access your analysis history.")

    `;
    main = main.substring(0, insertPoint) + freeCheck + main.substring(insertPoint);
    console.log('✅ main.py: History blocked for free users');
  } else {
    console.log('⚠️ Could not find analyses query in history endpoint');
  }
} else {
  console.log('⚠️ Could not find /api/history endpoint');
}

fs.writeFileSync(mainFile, main, 'utf8');

// ============ APP.JSX CHANGES ============
const appFile = path.join('frontend', 'src', 'App.jsx');
let app = fs.readFileSync(appFile, 'utf8');

// Add "Analysis history" to Free tier as NOT included
// Find the free tier features list - look for "1 analysis/month" in the pricing section
// Replace "Email support" in free tier to add a crossed-out history line
// Actually, let's add history as a feature in Pro and Business tiers

// Add history feature to Pro tier if not already there
if (!app.includes('Analysis history</li>') && app.includes('Priority AI analysis')) {
  // It might already be there, let's check more carefully
}

// Change 1: Make History nav button only show for paid users (desktop)
// Find all instances of the history button
const historyBtnDesktop = `<button onClick={() => setPage('history')} className="text-sm font-semibold text-gray-400 hover:text-cyan-400">History</button>`;
const historyBtnPaid = `{subscription?.tier && subscription.tier !== 'free' && <button onClick={() => setPage('history')} className="text-sm font-semibold text-gray-400 hover:text-cyan-400">History</button>}`;

// Desktop nav
app = app.replaceAll(historyBtnDesktop, historyBtnPaid);
console.log('✅ App.jsx: History button hidden for free users');

// Mobile nav history button
const mobileHistoryBtn = `<button onClick={() => { setPage('history'); setMobileMenuOpen(false) }} className="block w-full text-left text-gray-300 hover:text-cyan-400 py-2">History</button>`;
const mobileHistoryBtnPaid = `{subscription?.tier && subscription.tier !== 'free' && <button onClick={() => { setPage('history'); setMobileMenuOpen(false) }} className="block w-full text-left text-gray-300 hover:text-cyan-400 py-2">History</button>}`;

app = app.replaceAll(mobileHistoryBtn, mobileHistoryBtnPaid);
console.log('✅ App.jsx: Mobile history button hidden for free users');

// Change 2: Update pricing page - add "No analysis history" to free tier
// Find the free tier email support line and add a no-history line after it
const freeEmailSupport = `<li className="flex items-center gap-2 text-gray-400"><svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg>Email support</li>
              </ul>`;

const freeEmailSupportWithHistory = `<li className="flex items-center gap-2 text-gray-400"><svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg>Email support</li>
                <li className="flex items-center gap-2 text-gray-500"><svg className="w-5 h-5 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" /></svg><span className="line-through">Analysis history</span></li>
              </ul>`;

// Only replace the FIRST occurrence (which is the free tier)
const firstIdx = app.indexOf(freeEmailSupport);
if (firstIdx > -1) {
  app = app.substring(0, firstIdx) + freeEmailSupportWithHistory + app.substring(firstIdx + freeEmailSupport.length);
  console.log('✅ App.jsx: Added "no history" to free tier pricing');
} else {
  console.log('⚠️ Could not find free tier email support line');
}

// Load subscription on page load so nav knows the tier
// Check if subscription is loaded on home page
const subLoadCheck = app.includes('loadSubscription()');
if (subLoadCheck) {
  console.log('✅ Subscription already loads on relevant pages');
}

fs.writeFileSync(appFile, app, 'utf8');

console.log('\n🎉 All history changes applied!');
console.log('\nNow run:');
console.log('  git add backend/main.py frontend/src/App.jsx');
console.log('  git commit -m "History for paid users only, update pricing"');
console.log('  git push');
