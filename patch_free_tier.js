// Run from Permit-Pro-AI folder: node patch_free_tier.js
const fs = require('fs');
const path = require('path');

// ============ APP.JSX CHANGES ============
const appFile = path.join('frontend', 'src', 'App.jsx');
let app = fs.readFileSync(appFile, 'utf8');
const appOriginal = app;

// Replace free tier mentions
app = app.replaceAll('3 analyses/month', '1 analysis/month');
app = app.replaceAll('3 free analyses', '1 free analysis');
app = app.replaceAll('3 analyses per month', '1 analysis per month');
app = app.replaceAll('3 permit checks per month', '1 permit check per month');
app = app.replaceAll('3 permit checks', '1 permit check');

// Count App.jsx changes
const appChanges = (appOriginal.length - app.length !== 0) ? 'YES' : 'NO';
fs.writeFileSync(appFile, app, 'utf8');
console.log('✅ App.jsx free tier text updated');

// ============ MAIN.PY CHANGES ============
const mainFile = path.join('backend', 'main.py');
let main = fs.readFileSync(mainFile, 'utf8');

// Fix free tier limit
main = main.replaceAll('"free": 3', '"free": 1');

// Fix is_admin error
main = main.replaceAll(
  'not user.is_admin',
  'user.email not in ["toshygluestick@gmail.com"]'
);

fs.writeFileSync(mainFile, main, 'utf8');
console.log('✅ main.py free tier limit updated');
console.log('✅ main.py is_admin fix applied');

// ============ VERIFY ============
// Re-read and check
const appCheck = fs.readFileSync(appFile, 'utf8');
const mainCheck = fs.readFileSync(mainFile, 'utf8');

const issues = [];
if (appCheck.includes('3 analyses/month')) issues.push('App.jsx still has "3 analyses/month"');
if (appCheck.includes('3 free analyses')) issues.push('App.jsx still has "3 free analyses"');
if (mainCheck.includes('"free": 3')) issues.push('main.py still has "free": 3');
if (mainCheck.includes('not user.is_admin')) issues.push('main.py still has is_admin');

if (issues.length === 0) {
  console.log('\n🎉 All changes verified! No issues found.');
} else {
  console.log('\n⚠️ Some issues remain:');
  issues.forEach(i => console.log('  -', i));
}

console.log('\nNow run:');
console.log('  git add backend/main.py frontend/src/App.jsx');
console.log('  git commit -m "Free tier: 1 analysis, fix admin reviews"');
console.log('  git push');
