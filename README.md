# RentGear – Equipment Rental Platform (Server)

**Server live URL:** https://YOUR-SERVER-LIVE-URL
**Client repo:** https://github.com/YOUR-USERNAME/YOUR-CLIENT-REPO
**Client live URL:** https://YOUR-CLIENT-LIVE-URL

## Purpose
REST API for the RentGear equipment rental marketplace: users & roles, equipment listings, favorites, bookings, Stripe payments and dashboard analytics.

## Key Features
- JWT verification with role middlewares: `verifyToken`, `verifyRenter`, `verifyOwner`, `verifyAdmin`
- Server-side search, filter, sort and pagination for equipment
- Stripe Checkout session + payment confirmation (stored in `payments`)
- Atomic (MongoDB transaction) stock + payment + booking save, so quantity never goes below zero and payment/booking never go out of sync
- Stripe webhook (`/webhook/stripe`) as a safety net, plus automatic refund when stock runs out or a booking is cancelled
- helmet, rate limiting, input validation and DB indexes
- Admin and Owner analytics (totals, revenue/earnings, monthly stats)
- Daily cron job (`node-cron` + Vercel Cron) that completes finished rentals and emails renter & owner (nodemailer)

## npm Packages
`express`, `helmet`, `express-rate-limit`, `cors`, `dotenv`, `mongodb`, `jsonwebtoken`, `stripe`, `node-cron`, `nodemailer`, `express-async-errors`

## Run Locally
```bash
npm install
cp .env.example .env   # then fill in your own values
npm run dev
```

## Environment Variables
See `.env.example`. `INTERNAL_KEY` must be identical in the client and the server.

## Stripe webhook
Create a webhook endpoint pointing to `/webhook/stripe` for the `checkout.session.completed` event and put its signing secret in `STRIPE_WEBHOOK_SECRET`. Locally: `stripe listen --forward-to localhost:5000/webhook/stripe`.
MongoDB must support transactions (Atlas does; a standalone local mongod does not).
