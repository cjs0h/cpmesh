# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

People who move text, images and files between their own computers and phones many times a day — developers, IT staff and privacy-conscious professionals — and who prefer, or are required, to keep that data off third-party clouds. On the desktop they install cpmesh once, sign in, approve the device from another one they own, and then mostly leave it running in the tray; they open the window to find something they copied earlier, check that sync is live, approve a new device, or change a setting.

## Product Purpose

cpmesh is a self-hosted clipboard sync tool with end-to-end encryption: copy on one device, paste on any other within a second. Success is that sync is invisible when it works and unmistakable when it doesn't — the user always knows whether this device is connected, trusted and up to date.

## Positioning

End-to-end encrypted clipboard sync on a relay the user runs themselves. The relay only stores ciphertext; devices join only after a full 64-character fingerprint is compared on both ends, so trust decisions belong to the user, never to the server.

## Operating Context

- Desktop app (Tauri + SvelteKit) for macOS, Windows and Linux. Closing the window hides it to the tray/menu bar; `Cmd/Ctrl+Shift+Space` brings it back from anywhere.
- A web dashboard (`web/`) served by the same server handles account management, passkeys and two-factor setup; the desktop app hands browser sign-ins back through the `cpmesh://` deep link.
- Every sign-in is confirmed with a second factor (authenticator code, recovery code, or passkey in the browser).
- New devices wait in a pending state until an approved device verifies the fingerprint and approves them.

## Capabilities and Constraints

- Desktop features: sign in or register against any cpmesh server, SSO and browser sign-in, two-factor codes, connection control, clipboard history (search, copy back, delete, clear, sync from server), device list with approve/reject/remove, fingerprint verification of existing peers, settings (auto-connect, launch at login, notifications), password change (signs the device out), update checks and installs.
- Minimum window 700×500; default 900×650.
- Content Security Policy forbids remote scripts, fonts and images; all assets must ship with the app.
- Fingerprint comparison must always show and compare the full fingerprint; never shorten or summarise it.

## Brand Commitments

- The desktop app shares the web dashboard's identity (confirmed by the user): the cpmesh mesh logo (three nodes, one in orange), Geist and Geist Mono, neutral surfaces with hairline borders, and a single orange accent (`#ff5c38`) reserved for live state and emphasis.
- The desktop app must support both light and dark appearance.

## Evidence on Hand

- Logo mark: `web/src/components/Logo.svelte`; app icons in `assets/` and `desktop-tauri/src-tauri/icons/`.
- No testimonials, customer names, benchmarks or usage statistics exist; do not invent them.

## Product Principles

1. Show trust state plainly: connected, pending, verified and rejected must never be ambiguous.
2. Security steps stay complete; make them easier to perform, never shorter.
3. Stay out of the way: the app lives in the tray, so every visit should be quick to scan and act on.
4. One product across surfaces: desktop and web should feel like the same cpmesh.

## Accessibility & Inclusion

Keyboard operable throughout, visible focus, respects reduced motion and the system light/dark preference.
