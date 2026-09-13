# 📓 Vaultbook

**Your private notebook vault.**

Vaultbook is a private, offline-first encrypted notebook that runs entirely in your browser. Write, sketch, and attach images — everything is locked with **AES‑256‑GCM** and lives only on your device. No servers. No accounts. No tracking.

[![Live Demo](https://img.shields.io/badge/Live-Demo-2f7a68?style=for-the-badge)](https://rakibulislamnayan.github.io/restrictednotebook-js)
[![GitHub](https://img.shields.io/badge/GitHub-Repo-181717?style=for-the-badge&logo=github)](https://github.com/rakibulislamnayan/restrictednotebook-js)

---

## Why Vaultbook

Most note-taking apps expect you to sign in, sync your data to their cloud, and trust them with your writing. Vaultbook flips that around. Your notebook is a single `.vbk` file. You choose where it lives — a USB stick, your Downloads folder, an encrypted disk, or nowhere at all. The password you set never leaves your browser tab.

If you close the tab or lose the password, the notebook is unrecoverable — and that is the point.

---

## Features

- **AES‑256‑GCM encryption** with a fresh salt and IV on every save
- **PBKDF2** key derivation with 250 000 iterations of SHA‑256
- **Password set before you start writing** — with a confirm field, because there's no reset link
- **Write mode** — clean, distraction‑free typography (Fraunces serif on paper)
- **Draw mode** — full sketch canvas with brush, eraser, colors, size, undo/redo
- **Image attachments** — insert any image, view it fullscreen, remove it
- **Panic Lock** — hide the notebook instantly; restore it in the same session with your password
- **Export as PDF** — bundled offline, includes title, body, drawing, and images
- **Export as TXT** — for plain‑text portability
- **Light and dark themes** — remembers your choice
- **100% offline** — open `index.html` directly, no server, no build step
- **Backward compatible** — opens legacy `.rna` files from the old *R. Note*; saving converts them to `.vbk`

---

## Quick start

1. Download or clone this repo.
2. Open `index.html` in any modern browser (Chrome, Firefox, Safari, Edge).
3. Click **New Vaultbook** → set a password → start writing.
4. Click **Save** to download an encrypted `.vbk` file to your device.

That's it. There is no install step, no dependency to fetch, no server to run.

---

## How it works

### Creating a new notebook

Click **New Vaultbook**, choose a strong password, confirm it, and you're dropped straight into the editor. The password is held in memory only as long as the tab is open and the notebook is unlocked.

### Saving

Pressing **Save** (or <kbd>Ctrl</kbd>+<kbd>S</kbd>) does this:

1. Snapshots the current title, body, drawing, and images into a JSON payload.
2. Prepends a signature marker (`VAULTBOOK_V2::`) — used later to verify the password was correct.
3. Generates a fresh 16‑byte salt and 12‑byte IV.
4. Derives an AES‑256 key using PBKDF2‑SHA256 with 250 000 iterations of your password + salt.
5. Encrypts the payload with AES‑256‑GCM (which also authenticates it against tampering).
6. Wraps everything in a small JSON envelope and downloads it as `<Your Title>.vbk`.

### Opening

Drop a `.vbk` file onto the **Open** screen, enter your password, and the file is decrypted in place. The signature marker inside the payload is checked — if it isn't there, the password was wrong and the app refuses to load anything.

### Panic Lock (redesigned in v2)

The Panic button (or <kbd>Ctrl</kbd>+<kbd>L</kbd>) is meant for the moment someone walks up behind you.

- The current notebook is **re‑encrypted with the same password**, in memory.
- The plaintext is **wiped from the editor and from memory**.
- The password is **wiped from memory**.
- Only the encrypted bytes remain — behind a full‑screen lock overlay.

Enter your password again and the notebook is restored, exactly as you left it. If you close the tab, the encrypted buffer is gone; the notebook lives on only in whatever `.vbk` file you previously saved.

This is a deliberate change from v1, where "Panic Lock" wiped everything permanently. Now it protects your privacy without punishing your muscle memory.

---

## File format: `.vbk` v2

A Vaultbook file is a small JSON envelope containing base64‑encoded cryptographic material:

```json
{
  "format":     "VAULTBOOK",
  "version":    2,
  "salt":       "<base64 · 16 bytes>",
  "iv":         "<base64 · 12 bytes>",
  "ciphertext": "<base64 · AES-256-GCM output>"
}
```

Once decrypted with the correct password, the plaintext starts with the signature `VAULTBOOK_V2::` followed by a JSON document:

```json
{
  "title": "…",
  "body":  "…",
  "drawing": "data:image/png;base64,…" | null,
  "images": [
    { "id": "…", "name": "…", "dataURL": "data:image/…;base64,…" }
  ],
  "createdAt": "ISO 8601 timestamp",
  "updatedAt": "ISO 8601 timestamp"
}
```

The format is stable — future versions of Vaultbook will always be able to read v2 files.

### Legacy `.rna` files (from R. Note)

Vaultbook detects old `.rna` files automatically (format identifier `RNA`, version `1`, signature `RNA_NOTEBOOK_V1::`). It decrypts them with your original password, converts them into the new notebook shape (empty drawing, empty images, text preserved verbatim), and shows a small notice offering to save them as `.vbk`. Once you save, the file is fully upgraded and the notice goes away.

Your old files still work. You don't need to migrate anything up front.

---

## Security model

**What Vaultbook protects:** the confidentiality and integrity of your notebook file. Someone who obtains your `.vbk` cannot read it without your password, and cannot alter a single byte without the app refusing to open it.

**What Vaultbook does not protect:** you. If someone else uses your computer while your notebook is unlocked, or your device is compromised by malware, or someone shoulder‑surfs your password, no client‑side encryption will save you. Use Vaultbook on a device you trust.

Everything about the crypto is standard and easily auditable:

- **Cipher:** AES‑256‑GCM (authenticated encryption — detects tampering)
- **Key derivation:** PBKDF2 with SHA‑256, 250 000 iterations
- **Randomness:** `crypto.getRandomValues()` from the Web Crypto API
- **Salt:** 16 bytes, fresh per save
- **IV:** 12 bytes, fresh per save (never reused with the same key)
- **Storage:** the only thing ever written to `localStorage` is your **theme preference**. Notebook data, drawings, images, and passwords are never persisted by the browser.

The app is a single static site — you can read every line of `script.js` and see for yourself.

---

## Keyboard shortcuts

| Shortcut                                | Action                                    |
| --------------------------------------- | ----------------------------------------- |
| <kbd>Ctrl</kbd>+<kbd>S</kbd>            | Save (encrypt & download)                 |
| <kbd>Ctrl</kbd>+<kbd>L</kbd>            | Panic Lock                                |
| <kbd>Ctrl</kbd>+<kbd>D</kbd>            | Toggle light/dark theme                   |
| <kbd>Ctrl</kbd>+<kbd>Z</kbd>            | Undo (in Draw mode)                       |
| <kbd>Ctrl</kbd>+<kbd>Y</kbd>            | Redo (in Draw mode)                       |
| <kbd>Esc</kbd>                          | Exit Draw mode, close image preview       |

On macOS, <kbd>Cmd</kbd> works in place of <kbd>Ctrl</kbd>.

---

## Project structure

```
vaultbook/
├── index.html              — page structure and all four screens
├── style.css               — theme tokens, layout, responsive rules
├── script.js               — encryption, editor, drawing, panic lock, exports
├── lib/
│   ├── jspdf.umd.min.js    — bundled locally for offline PDF export
│   └── html2canvas.min.js  — bundled locally
└── README.md
```

No build step. No package manager. No dependencies to install. Open `index.html` and it runs.

---

## Deploying

**GitHub Pages:** push the folder to a repo, enable Pages in the repo settings, and pick the branch. That's it.

**Any static host:** upload the folder as‑is to Netlify, Vercel, Cloudflare Pages, S3, or your own web server. Vaultbook has no runtime dependencies — a plain file server works.

**Fully offline:** double‑click `index.html` and it runs from your filesystem. The `lib/` folder means PDF export works offline too.

---

## Limitations

- **Password recovery is impossible by design.** If you forget it, the file is cryptographically inaccessible.
- **Image size matters.** Every image is stored inside the encrypted file, so a notebook with dozens of large photos will produce a large `.vbk`. Vaultbook warns you before adding images over 5 MB.
- **The drawing canvas is a single sketch per notebook**, saved as a PNG. It isn't a multi‑layer illustration tool.
- **Client‑side encryption doesn't protect a compromised device.** If your machine is running keyloggers or the operating system is compromised, no browser app can help.

---

## Version history

- **v2.0** — Rebranded from *R. Note* to **Vaultbook** with new `.vbk` format. New editor UI, Draw mode, image support, PDF/TXT export, redesigned Panic Lock, dark‑mode persistence, backward compatibility with legacy `.rna` files.
- **v1.0** — Original *R. Note* release (text‑only, `.rna` format).

---

## Author

Made by **Md. Rakibul Islam Nayan**.

Vaultbook is free software — use it, fork it, break it apart, adapt it to your workflow. No warranty of any kind.
