# Ethics & responsible use

Dumbthings is **interoperability research** and a tool to use hardware **you own** locally,
without a mandatory cloud dependency. Please use it in that spirit.

## What this is

- A documented way to onboard your own Samsung OCF device and obtain its `OwnerPSK`, so a
  local integration (e.g. Home Assistant LocalThings) can talk to it on your LAN.
- It uses the device's **own, documented OCF onboarding** (manufacturer-certificate OTM). It
  does **not** rely on any Samsung vulnerability, and it extracts nothing from anyone else's
  account or device.

## What it is not

- **Not** a way to access, take over, or interfere with a device you do not own or administer.
- **Not** a way to read another person's credentials. The only account credential involved is
  **your own**, obtained by **you** signing into **your** Samsung/SmartThings account in the
  app's own WebView.

## Know before you run it

- **Ownership transfer changes the device's OCF owner to you.** On the one unit tested, the
  SmartThings cloud integration continued to work (the device showed as "External"), but this
  is **not guaranteed** across models or firmware. Only run it on a device you're willing to
  re-onboard if something misbehaves, and keep a factory reset as your recovery path.
- **Keep secrets secret.** The account bearer and the `OwnerPSK` are sensitive. Don't commit
  them, paste them into issues, or share captures that contain them.
- **This is one data point.** Everything here was proven on a single soundbar; treat it as a
  starting point, not a guarantee.

## Legal

You are responsible for complying with your local laws and with the terms of service of any
account or device you use this with. The authors make no claim that this method is endorsed by
Samsung or permitted under any particular agreement. See `LICENSE` — the software is provided
"as is", without warranty, and the authors accept no liability.
