// Run from Permit-Pro-AI folder: node fixmain.js
const fs = require('fs');
const path = require('path');

const file = path.join('backend', 'main.py');
let content = fs.readFileSync(file, 'utf8');

// 1. Remove the misplaced history block that broke admin stats
const bad = `        total_# Block history for free users
    user = db.query(User).filter(User.id == user_id).first()
    if user and user.subscription_tier == "free":
        raise HTTPException(status_code=403, detail="History is available for Pro and Business subscribers. Upgrade to access your analysis history.")

    analyses = db.query(AnalysisHistory).count()`;

const good = `        total_analyses = db.query(AnalysisHistory).count()`;

if (content.includes(bad)) {
  content = content.replace(bad, good);
  console.log('1. Fixed broken admin stats function');
} else {
  console.log('1. WARN: Could not find broken block');
}

// 2. Fix is_admin error
if (content.includes('not user.is_admin')) {
  content = content.replaceAll('not user.is_admin', 'user.email not in ["toshygluestick@gmail.com"]');
  console.log('2. Fixed is_admin check');
} else {
  console.log('2. is_admin already fixed or not found');
}

// 3. Fix free tier limit
if (content.includes('"free": 3')) {
  content = content.replaceAll('"free": 3', '"free": 1');
  console.log('3. Fixed free tier to 1');
} else {
  console.log('3. Free tier already 1');
}

// 4. Add signup notification (check if already there)
if (!content.includes('Notify admin of new signup')) {
  const returnToken = `        return TokenResponse(`;
  const notifyBlock = `        # Notify admin of new signup
        try:
            import resend
            resend.api_key = os.getenv("RESEND_API_KEY")
            resend.Emails.send({
                "from": "Flo Permit <noreply@flopermit.com>",
                "to": ["toshygluestick@gmail.com"],
                "subject": f"New Signup: {user_data.email}",
                "html": f"<h3>New user signed up!</h3><p><b>Email:</b> {user_data.email}</p><p><b>Name:</b> {user_data.full_name or 'Not provided'}</p><p><b>Company:</b> {user_data.company_name or 'Not provided'}</p><p><b>Time:</b> {datetime.utcnow().isoformat()}</p>"
            })
        except Exception as e:
            print(f"Admin notification email failed: {e}")

        return TokenResponse(`;
  
  // Only replace the first occurrence (in register function)
  const idx = content.indexOf(returnToken);
  if (idx > -1) {
    content = content.substring(0, idx) + notifyBlock + content.substring(idx + returnToken.length);
    console.log('4. Added signup notification');
  } else {
    console.log('4. WARN: Could not find return TokenResponse');
  }
} else {
  console.log('4. Signup notification already exists');
}

// 5. Add history block in the RIGHT place
if (!content.includes('Block history for free users')) {
  // Find the get_history endpoint
  const historyEndpoint = content.indexOf('@app.get("/api/history")');
  if (historyEndpoint > -1) {
    // Find "analyses = db.query(AnalysisHistory)" after the history endpoint
    const afterHistory = content.substring(historyEndpoint);
    const analysesLine = afterHistory.indexOf('analyses = db.query(AnalysisHistory)');
    if (analysesLine > -1) {
      const insertPoint = historyEndpoint + analysesLine;
      const historyCheck = `# Block history for free users
    user = db.query(User).filter(User.id == user_id).first()
    if user and user.subscription_tier == "free":
        raise HTTPException(status_code=403, detail="History is available for Pro and Business subscribers. Upgrade to access your analysis history.")

    `;
      content = content.substring(0, insertPoint) + historyCheck + content.substring(insertPoint);
      console.log('5. Added history paywall in correct location');
    } else {
      console.log('5. WARN: Could not find analyses query in history endpoint');
    }
  } else {
    console.log('5. WARN: Could not find /api/history endpoint');
  }
} else {
  console.log('5. History paywall already exists');
}

fs.writeFileSync(file, content, 'utf8');
console.log('\nDone! Now push both files.');
