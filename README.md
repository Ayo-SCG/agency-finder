# Agency Finder

A market research tool from Ayo Strategic Consulting Group, LLC. Enter a NAICS code and work through four steps: find the agencies that buy in that code, see the opportunities open now, find contracts that are ending soon at your target agencies (with a link to the last solicitation on SAM.gov), and build a target list.

Data comes from USAspending.gov and the public SAM.gov Contract Opportunities file, which a nightly job in this repository sorts by NAICS code.

## Two ways it runs

1. Open, on a plain file host. `index.html` works by itself with no sign in, and the target list is saved in the visitor's browser.
2. Signed in, on a server (`server.js`). People create an account with an access code, their target list is saved to their account, and the owner page at `/admin` shows who is using the tool and how often.

## Running the signed in version (Railway)

1. Create a new Railway project from this repository.
2. Add a PostgreSQL database to the project. Railway sets `DATABASE_URL` for you. In the service variables, reference it from the database.
3. Add these variables to the service: `ADMIN_EMAIL` (your email), `ADMIN_PASSWORD` (12 characters or more), and `NODE_ENV` set to `production`.
4. Deploy. The start command is `npm start`. The tables are created the first time it starts.
5. Sign in with the owner email and password, open the owner page, and create an access code for each session you sell.

Optional variables: `OPPS_BASE` and `OPPS_TOKEN` (only needed if this repository is made private), and `PGSSL=1` if the database requires SSL.

© 2026 Ayo Strategic Consulting Group, LLC. All rights reserved.
