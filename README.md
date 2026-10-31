# Arihant Medicos — phone app

Installable web app (PWA) for Arihant Medicos. It shows the business data that the **Arihant ERP** (repository
`chinmaydaklia/am`) emails to the Arihant Gmail account after each FAWin sync (10 AM, 2 PM, 8 PM).

* Signs in to that Gmail account **read-only** (Google sign-in, scope `gmail.readonly`), opens the newest
  `[ARIHANT-ERP]` email and unlocks its attached data file with the **phone data password**
  (AES-256-GCM, key from the password with PBKDF2-SHA256 — the same as the ERP).
* Home, parties (profile, due bills, ledger, bills, payments, purchases), due list with WhatsApp messages, tracks,
  sales, collections, purchases & payable, stock / expiry / low stock, changes in FAWin with user names, reports,
  older reports from Gmail.
* Keeps the last (still locked) data on the phone, so it works offline; ⟳ gets the latest.

**This repository holds no business data** — only the app. The data comes from your Gmail and can only be opened
with your password.

## Address
GitHub Pages: **https://chinmaydaklia.github.io/am.mob/** — open it in Chrome on the phone → Settings → paste the
Google Client ID → *Get the latest from Gmail*. Chrome menu → *Add to Home screen*.

Turn Pages on once: this repository → **Settings → Pages** → *Deploy from a branch* → `main` / `(root)` → Save.

Full setup (Gmail App Password, ERP settings, Google Cloud sign-in key): see `erp/docs/PHONE_APP.md` in the
`chinmaydaklia/am` repository.

## Files
`index.html` (screen layout and styles) · `app.js` (the app) · `sw.js` (offline) · `manifest.webmanifest`, `icon.svg`
(home-screen icon).
