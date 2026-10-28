# LEMS — Lab Equipment Management System

## Deployment architecture

- **Frontend:** Netlify (static HTML/CSS/JavaScript in `front end/`)
- **Backend:** Node.js + Express on Railway or another Node host
- **Database:** MySQL, reachable from the backend host
- **Hardware:** ESP32 connects to the deployed backend API

Netlify hosts the frontend; it does not run the existing Express server or host MySQL.

## Deploy the backend first

1. Create a Node service from this repository in Railway.
2. Set the service root directory to `backend`.
3. Build command: `npm install`
4. Start command: `npm start`
5. Add the environment variables below. Use a strong, unique `JWT_SECRET` (at least 32 random bytes) and do not commit secrets.
6. Ensure the hosted MySQL database has the existing LEMS schema and the backend can connect to it.
7. Deploy and verify `https://YOUR-BACKEND-DOMAIN/` returns `LEMS Backend API is running`.

### Backend environment variables

Required:
- `JWT_SECRET` — long random secret used to sign login tokens.
- `ALLOWED_ORIGINS` — exact Netlify site origin, e.g. `https://your-site.netlify.app` (comma-separated if using multiple origins).
- `MYSQLHOST`, `MYSQLUSER`, `MYSQLPASSWORD`, `MYSQLDATABASE`, `MYSQLPORT` (or the corresponding `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, `DB_PORT` values).

Optional:
- `FRONTEND_URL` — public Netlify URL used in password-reset emails.
- `EMAIL_USER`, `EMAIL_PASS` — SMTP/Gmail credentials for password-reset email.
- `KIOSK_API_KEY` — shared secret for ESP32 kiosk API requests. Send it as `X-Device-Api-Key`.
- `BOOTSTRAP_ADMIN_ID`, `BOOTSTRAP_ADMIN_EMAIL`, `BOOTSTRAP_ADMIN_PASSWORD`, optional `BOOTSTRAP_ADMIN_NAME` — creates one admin if no admin exists. Set these securely for the first deployment, then remove the bootstrap password variable after the admin is created.

Never use the old demo credentials `A101 / admin123` in production.

## Deploy the frontend to Netlify

1. Push the branch containing these changes to GitHub.
2. In Netlify, choose **Add new site → Import an existing project** and select this repository.
3. Set the branch to `security-netlify-deployment` for testing (or merge it to `main` after review).
4. The included `netlify.toml` configures the site base directory as `front end`, publishes that directory, and runs the API configuration generator.
5. In **Site configuration → Environment variables**, add:
   - `LEMS_API_BASE_URL` = the full HTTPS URL of your deployed backend, with no trailing slash, e.g. `https://your-api.up.railway.app`.
6. Trigger a fresh deploy after setting the variable.
7. Add your Netlify site origin to backend `ALLOWED_ORIGINS` and set `FRONTEND_URL` to that origin.

## Authentication and existing data

- Public signup creates student accounts only.
- Passwords are hashed with bcrypt for new signups and password resets. Existing plaintext passwords are upgraded to bcrypt hashes after a successful login.
- Login returns a short-lived JWT; the frontend stores it in session storage and attaches it to API calls.
- Admin API routes require an admin JWT. The browser's role display alone is not authorization.
- Reset tokens must have an unexpired expiry time and are not returned in the forgot-password API response.
- Keep your existing MySQL data and take a backup before deployment. Test against a staging database first.
- After deploying, test student signup/login, admin login, equipment list, checkout, return, complaints, password reset email, and access denial for a student calling an admin endpoint.

## Important scope note

These changes improve deployment configuration and authentication, but they do not by themselves implement every feature in the full LEMS development specification (for example, the complete multi-quantity/partial-return workflows, all RFID registration workflows, and end-to-end ESP32/OLED integration). Validate each workflow against the acceptance checklist before describing the whole system as complete.
