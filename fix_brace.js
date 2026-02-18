// Run: node fix_brace.js
const fs = require('fs');
const path = require('path');

const file = path.join('frontend', 'src', 'App.jsx');
let lines = fs.readFileSync(file, 'utf8').split('\n');

// Line 2113 (index 2112) is a standalone "}" that closes the function too early
// It comes right after a ")" on line 2112 (index 2111)
// Check context
console.log('Line 2110:', lines[2109]?.trim());
console.log('Line 2111:', lines[2110]?.trim());
console.log('Line 2112:', lines[2111]?.trim());
console.log('Line 2113:', lines[2112]?.trim());
console.log('Line 2114:', lines[2113]?.trim());

// Remove the extra } on line 2113 (index 2112)
if (lines[2112]?.trim() === '}') {
  lines.splice(2112, 1);
  fs.writeFileSync(file, lines.join('\n'), 'utf8');
  console.log('\n✅ Removed extra } on line 2113');
} else {
  console.log('\n⚠️ Line 2113 is not just "}" - check manually');
}
