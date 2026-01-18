# South Florida Permit Checker SaaS

Turn your Streamlit permit checker into a **real subscription business** with your own domain!

## 🎯 What You Have

- ✅ **Backend API** (FastAPI) - Your permit checking code as a REST API
- ✅ **Beautiful Frontend** (React) - Professional UI with South Florida aesthetic
- ✅ **Stripe Ready** - Just add your payment keys
- ✅ **Your Existing Logic** - Uses your analyzer.py, reader.py code
- ✅ **Deployment Ready** - Instructions to go live

---

## 📁 Project Structure

```
permit-checker-saas/
├── backend/
│   ├── main.py              # FastAPI server
│   ├── analyzer.py          # Your AI analysis code
│   ├── reader.py            # PDF/image text extraction
│   ├── permit_data.py       # City requirements (REPLACE THIS)
│   ├── requirements.txt     # Python dependencies
│   └── .env.example         # Environment variables template
└── frontend/
    ├── src/
    │   ├── App.jsx          # Main React app
    │   ├── main.jsx         # Entry point
    │   └── index.css        # Styles
    ├── package.json         # Node dependencies
    └── index.html           # HTML template
```

---

## 🚀 Quick Start (Local Testing)

### Step 1: Setup Backend

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# IMPORTANT: Copy your full permit_data.py file here
# Replace the stub permit_data.py with your complete requirements.py content

# Create .env file with your API key
cp .env.example .env
# Edit .env and add: ANTHROPIC_API_KEY=sk-ant-your-key-here

# Run the server
python main.py
```

✅ Backend runs on **http://localhost:8000**
Test it: http://localhost:8000/docs (API documentation)

### Step 2: Setup Frontend

```bash
cd frontend

# Install dependencies
npm install

# Run development server
npm run dev
```

✅ Frontend runs on **http://localhost:3000**

### Step 3: Test It!

1. Open http://localhost:3000
2. Select a city and permit type
3. Upload a PDF permit document
4. See AI analysis instantly!

---

## 🔑 Important Setup Notes

### Replace permit_data.py

The `backend/permit_data.py` file is currently a stub. You need to:

1. Take your full `requirements.py` file (the one with all city data)
2. Rename it to `permit_data.py`
3. Replace the stub file in `backend/` folder
4. Make sure it has these functions:
   - `get_city_key(city_name)`
   - `get_permit_types(city_key)`
   - `get_permit_requirements(city_key, permit_type)`

Your existing file already has all of these! Just copy it over.

---

## 💳 Setting Up Stripe (Subscriptions)

### 1. Create Stripe Account
- Go to https://stripe.com
- Sign up and get your API keys

### 2. Add Keys to Backend

Edit `backend/.env`:
```env
STRIPE_SECRET_KEY=sk_test_your_key_here
STRIPE_PUBLISHABLE_KEY=pk_test_your_key_here
```

### 3. Create Products in Stripe

In Stripe Dashboard → Products:
- **Free**: $0 (3 checks/month)
- **Contractor Pro**: $49/month (unlimited)
- **Business**: $149/month (teams)

Copy the Price IDs and update in `backend/main.py` → `/api/pricing`

### 4. Add Stripe Checkout (When Ready)

I can help you add the Stripe Checkout flow to the React frontend when you're ready!

---

## 🌐 Deploying to Production

### Option 1: Railway (Backend) + Vercel (Frontend)

**Deploy Backend to Railway:**

1. Push your code to GitHub
2. Go to https://railway.app
3. New Project → Deploy from GitHub
4. Select `backend` folder
5. Add environment variables:
   ```
   ANTHROPIC_API_KEY=sk-ant-your-key
   STRIPE_SECRET_KEY=sk_test_your_key
   ```
6. Railway gives you a URL: `https://your-app.railway.app`

**Deploy Frontend to Vercel:**

1. Update `frontend/src/App.jsx` line ~66:
   ```javascript
   // Change from:
   const response = await fetch('http://localhost:8000/api/analyze-permit'
   
   // To your Railway URL:
   const response = await fetch('https://your-app.railway.app/api/analyze-permit'
   ```

2. Deploy to Vercel:
   ```bash
   cd frontend
   npm i -g vercel
   vercel
   ```

3. Vercel gives you: `https://your-app.vercel.app`

### Option 2: Get Your Custom Domain

1. **Buy domain** from Namecheap ($12/year)
   - Example: permitcheck.io, floridapermits.com

2. **In Vercel:** Settings → Domains → Add your domain

3. **Update DNS** (Vercel shows you exactly what to do)

4. **Update backend CORS** in `backend/main.py`:
   ```python
   allow_origins=[
       "http://localhost:3000",
       "https://yourdomain.com",  # Add this
       "https://www.yourdomain.com"
   ]
   ```

5. Done! Your app is live at `https://yourdomain.com` 🎉

---

## 💰 Pricing Strategy

### Recommended Pricing:

**Free Tier:**
- 3 permit checks per month
- Basic analysis
- Perfect for occasional users

**Contractor Pro - $49/month:**
- Unlimited checks
- AI-powered analysis
- Save history
- Priority support

**Business - $149/month:**
- Everything in Pro
- Team collaboration (5 users)
- API access
- White-label reports

### Why These Prices?

- Contractors charge $500-2000+ per permit
- One rejected permit = hours of rework
- Your tool saves time & money = easy ROI
- Similar tools charge $99-299/month

**You're priced competitively!**

---

## 📈 Marketing Your SaaS

### Week 1: Launch
- [ ] Post on construction forums
- [ ] Share in contractor Facebook groups
- [ ] Email local contractors you know
- [ ] List on Product Hunt

### Month 1: Growth
- [ ] SEO: "South Florida permit checker"
- [ ] Google Ads: Target permit keywords
- [ ] Partner with building supply stores
- [ ] Sponsor contractor meetups

### Month 2: Scale
- [ ] Case studies from happy customers
- [ ] Referral program (20% commission)
- [ ] Content: "How to avoid permit rejections"
- [ ] YouTube tutorials

---

## 🎯 Revenue Goals

**Conservative Estimates:**

- **Month 1:** 5 paid customers = $245/month
- **Month 3:** 20 customers = $980/month
- **Month 6:** 50 customers = $2,450/month
- **Year 1:** 100 customers = $4,900/month

**Costs:**
- Railway: $5/month
- Vercel: Free
- Domain: $1/month
- Anthropic API: ~$20-50/month

**Profit:** $4,800/month by year 1! 💰

---

## 🔥 Next Steps

1. **Test locally** - Make sure everything works
2. **Replace permit_data.py** with your full file
3. **Get Anthropic API key** (claude.ai/settings)
4. **Deploy backend** to Railway
5. **Deploy frontend** to Vercel
6. **Buy domain** and connect it
7. **Set up Stripe** and start charging!

---

## 🆘 Troubleshooting

**"Module not found" errors:**
```bash
# Backend:
cd backend && pip install -r requirements.txt

# Frontend:
cd frontend && npm install
```

**"CORS Error":**
- Make sure backend is running (http://localhost:8000)
- Check `main.py` allows your frontend URL

**"API not responding":**
- Check backend logs
- Verify your ANTHROPIC_API_KEY in .env

**"Can't upload files":**
- Check file size (must be < 10MB)
- Verify file type (PDF, PNG, JPG only)

---

## 📞 Support

Need help? Common issues:

1. **permit_data.py errors** → Copy your full requirements.py file
2. **API key issues** → Get key from claude.ai/settings
3. **Deployment questions** → Check Railway/Vercel docs
4. **Stripe setup** → Visit stripe.com/docs

---

## 🎉 You're Ready!

You have everything you need to launch a real SaaS business:

✅ Professional UI
✅ Working backend
✅ Subscription pricing
✅ Deployment guide
✅ Marketing strategy

**Now go build your business! 🚀**

---

Made with ❤️ for South Florida contractors
