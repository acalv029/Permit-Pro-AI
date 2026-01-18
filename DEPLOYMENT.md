# 🚀 Deployment Guide - Go Live Step by Step

## Your Goal
Get your permit checker live on your own domain with subscription billing.

---

## Phase 1: Local Setup (30 minutes)

### 1. Get Your Files Ready

Download the permit-checker-saas folder and:

```bash
# Copy your FULL permit_data.py file
# (The one with all the city requirements)
# Put it in: permit-checker-saas/backend/permit_data.py

# Replace the stub file that's there now
```

### 2. Get API Key

1. Go to https://console.anthropic.com
2. Create account / Sign in
3. Go to API Keys
4. Create new key
5. Copy it (starts with `sk-ant-...`)

### 3. Start Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Create .env file
echo "ANTHROPIC_API_KEY=sk-ant-your-key-here" > .env

python main.py
```

✅ Open http://localhost:8000/docs - should see API documentation

### 4. Start Frontend

```bash
cd frontend
npm install
npm run dev
```

✅ Open http://localhost:3000 - should see your beautiful site!

### 5. Test It

1. Upload a permit PDF
2. Should analyze and show results
3. ✅ Everything works? Move to Phase 2!

---

## Phase 2: Deploy Backend (20 minutes)

### Using Railway.app (Recommended - Easiest)

**Step 1: Push to GitHub**

```bash
cd permit-checker-saas
git init
git add .
git commit -m "Initial commit"

# Create repo on GitHub, then:
git remote add origin https://github.com/yourusername/permit-checker.git
git push -u origin main
```

**Step 2: Deploy to Railway**

1. Go to https://railway.app
2. Sign in with GitHub
3. Click "New Project"
4. Select "Deploy from GitHub repo"
5. Choose your `permit-checker` repo
6. Railway auto-detects Python ✅

**Step 3: Configure Railway**

1. In Railway dashboard, click on your service
2. Go to "Settings"
3. **Root Directory**: `backend`
4. **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`

**Step 4: Add Environment Variables**

In Railway → Variables, add:

```
ANTHROPIC_API_KEY=sk-ant-your-actual-key
STRIPE_SECRET_KEY=sk_test_your_stripe_key
```

**Step 5: Get Your URL**

Railway gives you a URL like:
```
https://permit-checker-production.up.railway.app
```

Copy this! You'll need it for the frontend.

✅ Test: Open `https://your-url.railway.app/docs`

---

## Phase 3: Deploy Frontend (15 minutes)

### Using Vercel (Free!)

**Step 1: Update API URL**

Edit `frontend/src/App.jsx` around line 66:

```javascript
// Find this:
const response = await fetch('http://localhost:8000/api/analyze-permit', {

// Replace with your Railway URL:
const response = await fetch('https://your-app.railway.app/api/analyze-permit', {
```

Save the file, commit to GitHub:

```bash
git add .
git commit -m "Update API URL for production"
git push
```

**Step 2: Deploy to Vercel**

```bash
cd frontend
npm i -g vercel
vercel login
vercel
```

Answer the questions:
- Link to existing project? **N**
- Project name? **permit-checker**
- Directory? **`./` (press Enter)**
- Want to override settings? **N**

Vercel deploys and gives you:
```
https://permit-checker.vercel.app
```

**Step 3: Update Backend CORS**

Edit `backend/main.py` around line 21:

```python
allow_origins=[
    "http://localhost:3000",
    "https://permit-checker.vercel.app",  # Add your Vercel URL
],
```

Commit and push (Railway auto-deploys):

```bash
git add .
git commit -m "Add Vercel URL to CORS"
git push
```

✅ **Test**: Visit `https://your-app.vercel.app` and try uploading a permit!

---

## Phase 4: Custom Domain (10 minutes)

### Buy a Domain

**Namecheap** (Recommended - Cheap & Easy):

1. Go to https://namecheap.com
2. Search for domain (e.g., "flpermitcheck.com")
3. Add to cart, checkout (~$12/year for .com)

**Good domain ideas:**
- permitcheck.io
- flpermits.com
- southfloridapermits.com
- permitai.co

### Connect to Vercel

**Step 1: In Vercel Dashboard**

1. Go to your project
2. Settings → Domains
3. Click "Add"
4. Enter your domain: `yourdomain.com`
5. Also add: `www.yourdomain.com`

**Step 2: Vercel Gives You DNS Records**

Example:
```
Type: A
Name: @
Value: 76.76.21.21

Type: CNAME
Name: www
Value: cname.vercel-dns.com
```

**Step 3: In Namecheap**

1. Go to Domain List → Manage
2. Advanced DNS tab
3. Add the A record (delete existing ones first)
4. Add the CNAME record
5. Save

**Step 4: Wait**

- DNS takes 5-60 minutes to propagate
- Check status in Vercel dashboard
- When ready, Vercel auto-enables HTTPS ✅

**Step 5: Update Backend CORS Again**

Edit `backend/main.py`:

```python
allow_origins=[
    "http://localhost:3000",
    "https://permit-checker.vercel.app",
    "https://yourdomain.com",        # Add this
    "https://www.yourdomain.com",    # And this
],
```

Commit and push.

✅ **Visit `https://yourdomain.com` - You're LIVE!** 🎉

---

## Phase 5: Set Up Stripe Billing (20 minutes)

### Create Stripe Account

1. Go to https://stripe.com
2. Sign up
3. Complete business info

### Create Products

**In Stripe Dashboard → Products:**

**Product 1: Contractor Pro**
- Name: Contractor Pro
- Price: $49/month
- Recurring: Monthly
- Copy the **Price ID** (looks like `price_abc123`)

**Product 2: Business**
- Name: Business Plan
- Price: $149/month
- Recurring: Monthly
- Copy the **Price ID**

### Add to Your App

**Step 1: Get Stripe Keys**

Stripe Dashboard → Developers → API Keys:
- Publishable key: `pk_test_...`
- Secret key: `sk_test_...`

**Step 2: Add to Railway**

In Railway → Variables:
```
STRIPE_SECRET_KEY=sk_test_your_key_here
STRIPE_PUBLISHABLE_KEY=pk_test_your_key_here
```

**Step 3: Update Pricing Endpoint**

Edit `backend/main.py` → `/api/pricing` endpoint:

```python
{
    "name": "Contractor Pro",
    "price": 49,
    "stripe_price_id": "price_abc123"  # Your real Price ID
},
{
    "name": "Business",
    "price": 149,
    "stripe_price_id": "price_xyz789"  # Your real Price ID
}
```

Commit and push.

### Add Stripe Checkout to Frontend (Next Phase)

This requires adding Stripe.js library and creating checkout flow.
Ready for this? Let me know and I'll build it!

---

## Phase 6: Go Live Checklist

Before marketing your site:

- [ ] Test full payment flow (use Stripe test mode)
- [ ] Add Terms of Service page
- [ ] Add Privacy Policy page
- [ ] Set up Google Analytics
- [ ] Test on mobile devices
- [ ] Get 3 friends to test and give feedback
- [ ] Add FAQ section
- [ ] Create demo video
- [ ] Switch Stripe to LIVE mode

---

## 🎯 You're Live!

Your permit checker is now:

✅ Live on your own domain
✅ Processing payments via Stripe
✅ Analyzing permits with AI
✅ Looking professional

---

## 📊 Monthly Costs

| Service | Cost |
|---------|------|
| Railway (Backend) | $5-10/month |
| Vercel (Frontend) | $0 (free forever) |
| Domain | ~$1/month |
| Stripe fees | 2.9% + 30¢ per transaction |
| Anthropic API | ~$20-50/month (usage-based) |

**Total: ~$30-60/month to run**

**First 10 customers at $49/mo = $490/month revenue!**

**Profit = $430+/month** 💰

---

## 🆘 Common Issues

**Backend won't start on Railway:**
- Check logs in Railway dashboard
- Verify environment variables are set
- Make sure requirements.txt has all dependencies

**Frontend can't connect to API:**
- Check CORS settings in main.py
- Verify Railway URL is correct in App.jsx
- Check Railway service is running

**Domain not working:**
- Wait 30-60 minutes for DNS propagation
- Verify DNS records match Vercel's exactly
- Try clearing browser cache

**Stripe not working:**
- Make sure you're using the right keys (test vs live)
- Check webhook configuration
- Verify Price IDs are correct

---

## Next: Marketing & Growth

Once you're live:

1. **Soft launch** - share with 10 contractors you know
2. **Get feedback** - fix any issues
3. **Create case study** - "Saved 5 hours on permit"
4. **Launch publicly** - social media, forums
5. **Run ads** - Google Ads for "South Florida permits"

Ready to market? Check the BUSINESS_GUIDE.md!

---

**Need help? Review the README.md or ask me!**

You've got this! 🚀
