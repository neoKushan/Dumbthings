# Dumbthings

<img src="branding/logo.svg" alt="DumbThings logo" width="120" align="right">

**Making Samsung SmartThings devices dumb again — local control without the cloud.**

Dumbthings documents how Samsung's OCF (Open Connectivity Foundation) appliances are
onboarded and authenticated, and demonstrates a **no-root way to obtain the `OwnerPSK`**
that local integrations such as [Home Assistant LocalThings](https://github.com/mbillow/localthings)
need to talk to these devices directly over your LAN.

It is a **research record**: wire-protocol notes, diagrams, a reference Android implementation,
and small tools. Everything here was reverse-engineered from a single soundbar on a test
account; all personal, account, device and network identifiers have been replaced with
placeholders (see [Sanitization](#sanitization)).

> **Status:** validated end-to-end on a Samsung HW-Q950A soundbar here, and independently reported
> working on a **HW-Q850A** by another user — both 2021 "A"-series soundbars. The key authenticates
> a real local DTLS-PSK session (`GET /oic/d → 2.05`, `networkaudio` resources served) and the
> device registers in SmartThings. Treat these as a couple of early data points, not a guarantee
> for every model or firmware.

## Why this exists

Samsung appliances (soundbars, TVs, washers, fridges…) speak **OCF over CoAP/DTLS** on your
LAN. To control one locally you need its **`OwnerPSK`** — a symmetric key established when the
device is *owned* (OCF Ownership Transfer, "OTM"). The key is **never transmitted**; each side
derives it independently from the ownership handshake. That leaves three ways to get it:

| Route | Needs | Who documented it |
|---|---|---|
| Extract the stored key from the SmartThings app | **rooted phone** + Frida, or an **iOS backup** | the LocalThings community |
| Derive it from a manufacturer-DTLS handshake you drive | the ability to run the OTM | laundry only, not public |
| **This repo: a standalone app does the OTM itself and derives the key** | **no root**, a Samsung account | here |

Because the key can't be sniffed, the only way to *know* it without reading it out of
SmartThings' memory is to **be the party that performs the ownership handshake**. That is what
the reference app does — see [`docs/02-ocf-ownership-model.md`](docs/02-ocf-ownership-model.md).

## What's inside

| Path | What |
|---|---|
| [`docs/01-overview.md`](docs/01-overview.md) | The end-to-end result and the pipeline at a glance |
| [`docs/02-ocf-ownership-model.md`](docs/02-ocf-ownership-model.md) | OCF ownership, the `OwnerPSK`, and why "no-root" forces you to become the owner |
| [`docs/03-otm-sequence.md`](docs/03-otm-sequence.md) | The manufacturer-certificate OTM, step by step, on the wire |
| [`docs/04-ownerpsk-derivation.md`](docs/04-ownerpsk-derivation.md) | Deriving the key, the BouncyCastle master-secret trap, and the OXM-label gotcha |
| [`docs/05-easysetup-and-cloud.md`](docs/05-easysetup-and-cloud.md) | EasySetup, the device JWT, and reaching `ES_COMPLETE` |
| [`docs/06-ble-ocf-transport.md`](docs/06-ble-ocf-transport.md) | OCF-over-BLE framing and CoAP/DTLS on the GATT channel |
| [`docs/07-acquisition-landscape.md`](docs/07-acquisition-landscape.md) | How this compares to the community's extraction routes |
| [`docs/08-reproduction.md`](docs/08-reproduction.md) | Reproducing it, and the test rig |
| [`android/`](android/) | Reference standalone OTM app (no root) |
| [`tools/`](tools/) | Capture/decode helpers and a local mock cloud |
| [`traces/`](traces/) | **Sanitized** protocol excerpts (no raw dumps) |

## Scope — what works, what doesn't

These are a couple of early data points (HW-Q950A, HW-Q850A soundbars). The path the tool
automates is specific, and "my device advertises the right bit" is **not** enough to know it
will work. What the tool actually does:

- A **manufacturer-certificate OTM with an anonymous client** — it presents *no* client
  certificate (so the AC14K_M chain LocalThings uses on import is irrelevant here); only the
  device's own factory certificate is used, and the OwnerPSK is derived from that handshake.
- A **physical-presence confirm** — a button on the device (Volume-Down on the soundbar)
  approves the ownership transfer.
- A **full OTM from RFOTM** — the device must be factory-reset into setup mode first. It is
  **not** the no-reset "authorized transition".

A device is only a plausible candidate if **all** of these hold: its plaintext `/oic/sec/doxm`
`oxms` includes a **manufacturer-certificate OTM** method — method `2` (`oic.sec.doxm.mfgcert`)
or the `0xFF02` (`65282`) `conmfgcert` variant, both of which the tool tries; it completes that
mfg-cert DTLS handshake with no client cert; its ownership confirm is a simple physical button;
and you're willing to factory-reset it.

**Known *not* in scope**, as the tool stands:

- **Laundry and other appliances that gate the transfer behind account-bound proofs.** The key
  difference isn't the OTM method number (`0xFF02` is itself a manufacturer-cert variant, not a
  non-cert path): it's the **confirm/authorization step**. The tested soundbars complete the
  transfer with a single physical button; the laundry path in SmartThings-Local's
  [`ocf-pki-laundry.md`](https://github.com/QuiteYellow/SmartThings-Local/blob/main/docs/ocf-pki-laundry.md)
  needs fresh serial/account hashed-proof confirmations *before* the manufacturer DTLS, which
  this tool does not implement. So advertising a mfg-cert method is necessary but not sufficient.
  That is a separate track (see @Jason-Morcos's work in #435).
- **Devices that require a client certificate** for the OTM handshake.
- **Pairwise-peer (additive) setups** where Samsung stays the OCF owner — this tool takes full
  ownership instead.
- **Any model beyond the two confirmed 2021 "A"-series soundbars** (HW-Q950A, HW-Q850A). Other
  soundbars/TVs may well work — check the four conditions above — but nothing else is verified here.

The cheap, non-destructive first check on anything new is a plaintext `GET /oic/sec/doxm`:
`oxms` and `oxmsel` tell you a lot before anything is reset.

## Using the app

> **Proof of concept.** Built and tested against **one** Samsung HW-Q950A soundbar on one
> account. It may not work with any other model, firmware, or account, and it is provided as-is
> with no support. **This repository is not accepting pull requests at this time.**

Download the APK from [**Releases**](../../releases) and sideload it on an Android phone (you'll
need to allow "install unknown apps" for your browser or file manager). Then:

- **Factory-reset the device** so it is back in setup mode (unowned) and advertising for
  onboarding. On the soundbar this is its normal factory-reset procedure.
- Make sure your **phone is on the same Wi-Fi network** you want the device to join — the one
  Home Assistant is on.
- Open **Dumb things** and tap **1. SmartThings login**. Sign in to your Samsung/SmartThings
  account in the web view; it closes by itself once it has the token and the button shows
  **✓ Cloud bearer set**.
- Tap **2. Scan & pair OCF device**. **Wait ~8 seconds** while it scans, then pick your device
  from the list (e.g. "Samsung Soundbar Q950A").
- Enter your **Wi-Fi SSID and password** and tap **Pair + register**.
- When the screen says **"Confirm on the device"**, press the device's physical confirm button
  within a few seconds — on the soundbar that's **Volume-Down**.
- **Now wait and leave it alone.** It runs the secure handshake, joins Wi-Fi, and registers with
  the cloud — **up to ~60 seconds**, during which it shows **"Confirming in SmartThings…"** for
  up to 45s.
- The dialog **title tells you the real outcome:**
  - **✓ Added to SmartThings** — cloud registration completed and ownership is durable. The Owner
    PSK is valid and will work in LocalThings. The values are listed, each with its own copy button.
  - **⚠ Provisioned, but not yet visible in SmartThings** / **Local-only** — the ownership transfer
    happened but **cloud registration (`ES_COMPLETE`) did not complete**.

> **Important — a "Local-only" / "not yet visible" result is not usable.** Without `ES_COMPLETE` the
> device **reverts to unowned on disconnect**, so the Owner PSK it shows is **dead**: it won't
> auto-populate an identity in LocalThings and won't pass the handshake. Don't try to import it.
> Factory-reset and retry, checking that the **SmartThings login succeeded** (its button shows ✓)
> and that the **device actually joined Wi-Fi**. Only a **✓ Added to SmartThings** result yields a
> key that works.

### Add it to Home Assistant LocalThings

- In the result dialog (or later via **SAVED DEVICES → your device**), tap **FIND** on the `ip`
  row. **Wait a few seconds** while it locates the device on your LAN; it then fills in the IP.
- Copy the **ip** and the **Owner PSK** (both highlighted). LocalThings distinguishes *OwnerPSK*
  from *Peer Shared PSK* — use the **Owner PSK** value here.
- In Home Assistant, add the device in **LocalThings** with that **IP** and **Owner PSK**.

## Ethics & scope

This is interoperability research on **hardware you own**, to use it locally without a
mandatory cloud dependency. The ownership transfer makes *you* the device's OCF owner; on the
one unit tested, SmartThings cloud control continued to work (the device appears as an
"External" device). It is **not** a way to take over someone else's device, and nothing here
depends on a Samsung vulnerability — it uses the device's own documented OCF onboarding.

## Credits

Built on the shoulders of the LocalThings community — especially
[`mbillow/localthings`](https://github.com/mbillow/localthings) (the Home Assistant
integration and the credential-acquisition research) and the
[`smartthings-local`](https://github.com/QuiteYellow/SmartThings-Local) protocol library,
whose `derive_mfg_certificate_owner_psk` and DTLS work this builds on.

## Sanitization

No real identifiers are committed. Emails, names, account UUIDs, device UUIDs, MACs, Wi-Fi
SSID/password, location/room IDs, bearer tokens, JWTs and pre-shared keys are all replaced
with obvious placeholders (`192.0.2.x` IPs, `aa:bb:cc:…` MACs, `REDACTED_*`, `<PLACEHOLDER>`,
`example.com`). Raw packet traces and raw screenshots are **excluded by design** — only
curated, placeholder-substituted excerpts and clean recreations are included. A sweep script
(kept out of the repo) checks every file before any push.
