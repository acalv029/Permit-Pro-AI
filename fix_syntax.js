// Run from Permit-Pro-AI folder: node fix_syntax.js
const fs = require('fs');
const path = require('path');

const file = path.join('frontend', 'src', 'App.jsx');
let content = fs.readFileSync(file, 'utf8');

// Fix: className=`...`}> should be className={`...`}>
const bad = "className=`p-4 rounded-xl border ${r.is_approved ? 'bg-emerald-900/20 border-emerald-500/30' : 'bg-gray-800/50 border-gray-700'}`>";
const good = "className={`p-4 rounded-xl border ${r.is_approved ? 'bg-emerald-900/20 border-emerald-500/30' : 'bg-gray-800/50 border-gray-700'}`}>";

if (content.includes(bad)) {
  content = content.replace(bad, good);
  fs.writeFileSync(file, content, 'utf8');
  console.log('✅ Fixed className syntax error');
} else {
  console.log('⚠️ Could not find the exact bad string. Checking...');
  // Try to find any className= followed by backtick without {
  const lines = content.split('\n');
  lines.forEach((line, i) => {
    if (line.includes('className=`') && !line.includes('className={`')) {
      console.log(`  Line ${i+1}: ${line.trim().substring(0, 80)}...`);
    }
  });
}

console.log('\nNow run:');
console.log('  git add frontend/src/App.jsx');
console.log('  git commit -m "Fix JSX syntax error"');
console.log('  git push');
