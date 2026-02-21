// Run from Permit-Pro-AI: node debuglogin.js
const fs = require('fs');
const file = 'backend/main.py';
let content = fs.readFileSync(file, 'utf8');

const old = `        user = db.query(User).filter(User.email == user_data.email).first()
        if not user:`;

const rep = `        user = db.query(User).filter(User.email == user_data.email).first()
        print(f"DEBUG: Found user: {user.id if user else 'None'}, email={user_data.email}")
        if not user:`;

if (content.includes(old)) {
  content = content.replace(old, rep);
  fs.writeFileSync(file, content, 'utf8');
  console.log('Done! Debug line added. Now push.');
} else {
  console.log('Could not find the target line');
}
