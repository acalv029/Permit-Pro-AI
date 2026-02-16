// Run from Permit-Pro-AI folder: node patch_landing.js
const fs = require('fs');
const path = require('path');

const file = path.join('frontend', 'public', 'landing.html');
let html = fs.readFileSync(file, 'utf8');

// Replace all variations of "3 free" messaging
html = html.replaceAll('3 free analyses', 'a free analysis');
html = html.replaceAll('3 Free Analyses', 'a Free Analysis');
html = html.replaceAll('3 free permits', 'a free analysis');
html = html.replaceAll('3 Free Permits', 'a Free Analysis');
html = html.replaceAll('3 free checks', 'a free check');
html = html.replaceAll('3 Free Checks', 'a Free Check');
html = html.replaceAll('3 permit checks', '1 permit check');
html = html.replaceAll('3 analyses', '1 analysis');

// Also update any CTA text
html = html.replaceAll('Start Free - 3 Analyses', 'Try It Free');
html = html.replaceAll('Get 3 Free', 'Try It Free');
html = html.replaceAll('3 free', '1 free');
html = html.replaceAll('3 Free', '1 Free');

fs.writeFileSync(file, html, 'utf8');

// Verify
const check = fs.readFileSync(file, 'utf8');
if (check.includes('3 free') || check.includes('3 Free')) {
  console.log('⚠️ Some "3 free" text may remain - check manually');
} else {
  console.log('✅ Landing page updated!');
}

console.log('\nNow run:');
console.log('  git add frontend/public/landing.html');
console.log('  git commit -m "Update landing page: 1 free analysis"');
console.log('  git push');
