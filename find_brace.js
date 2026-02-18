// Run: node find_brace.js
const fs = require('fs');
const path = require('path');

const file = path.join('frontend', 'src', 'App.jsx');
const content = fs.readFileSync(file, 'utf8');
const lines = content.split('\n');

let depth = 0;
let inString = false;
let inTemplate = false;
let inComment = false;
let inLineComment = false;

for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  const prevDepth = depth;
  
  for (let j = 0; j < line.length; j++) {
    const ch = line[j];
    const next = line[j+1];
    const prev = line[j-1];
    
    // Skip string contents
    if (inLineComment) continue;
    if (ch === '/' && next === '/' && !inString && !inTemplate && !inComment) { inLineComment = true; continue; }
    if (ch === '/' && next === '*' && !inString && !inTemplate) { inComment = true; continue; }
    if (ch === '*' && next === '/' && inComment) { inComment = false; j++; continue; }
    if (inComment) continue;
    
    // Count braces outside of strings/templates/JSX string attributes
    if (ch === '{' && !inString) depth++;
    if (ch === '}' && !inString) depth--;
  }
  
  inLineComment = false;
  
  // Report when depth hits 0 (function closed)
  if (depth === 0 && prevDepth > 0) {
    console.log(`Depth reaches 0 at line ${i+1}: ${line.trim().substring(0, 60)}`);
  }
  
  // Report negative depth (extra closing brace)
  if (depth < 0) {
    console.log(`❌ NEGATIVE depth at line ${i+1}: ${line.trim().substring(0, 60)}`);
  }
}

console.log(`\nFinal depth: ${depth}`);
console.log(`Total lines: ${lines.length}`);

if (depth !== 0) {
  console.log(`\n⚠️ Brace mismatch: depth should be 0 but is ${depth}`);
}
