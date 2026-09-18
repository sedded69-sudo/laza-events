# Deploy (free)

**1. MongoDB Atlas (free)**
- atlas.mongodb.com → create free cluster → Database Access: add a user → Network Access: allow 0.0.0.0/0
- Get connection string (Connect → Drivers → copy URI), put your user/password into it

**2. Backend on Render (free)**
- render.com → New → Web Service → connect this `backend` folder (or upload as a repo)
- Build command: `npm install`  Start command: `npm start`
- Add environment variables:
  - `MONGODB_URI` = your Atlas connection string
  - `JWT_SECRET` = any long random string
- Deploy. Copy the URL Render gives you (e.g. `https://gatekeep-api.onrender.com`)

**3. Frontend**
- Open `frontend/index.html`, set `API_BASE` near the top of the `<script>` to your Render URL
- Drag the file onto app.netlify.com/drop → get your public link

**4. First login**
- Open the link, it'll say "no admin yet" — enter a username + password to create the admin account
- Go to Setup → Staff accounts to create staff logins with specific permissions (scan / generate / passes)
