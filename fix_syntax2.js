// Run from Permit-Pro-AI folder: node fix_syntax2.js
const fs = require('fs');
const path = require('path');

const file = path.join('frontend', 'src', 'App.jsx');
let lines = fs.readFileSync(file, 'utf8').split('\n');

// Fix line 1707 (index 1706)
const badLine = lines[1706];
console.log('Before:', badLine.trim().substring(0, 80));

// Replace className=` with className={` and `}> with `}>
lines[1706] = lines[1706].replace('className=`', 'className={`').replace('`}>', '`}>');

console.log('After:', lines[1706].trim().substring(0, 80));

fs.writeFileSync(file, lines.join('\n'), 'utf8');
console.log('\n✅ Fixed!');
