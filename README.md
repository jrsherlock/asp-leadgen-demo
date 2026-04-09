# ASP Lead-Gen Demo

A vision demo for **ProCircular's Attack Surface Profiler** lead generation concept. This single-page app simulates scanning a domain's external attack surface, displays teaser results from real scan data, and captures visitor contact information.

## Purpose

Internal demo for ProCircular stakeholders and designers — not production code. Demonstrates the concept of giving website visitors a free "peek" at their attack surface to drive lead capture.

## Features

- **8-phase scan simulation** with randomized timing (3–8s per phase) for realism
- **Live terminal console** streaming color-coded scan output during each phase
- **Animated risk gauge** with severity-colored SVG ring and pulse effect
- **6 KPI stat cards** with count-up animations and click-to-navigate
- **7 data sections**: Endpoints, Breach Findings, Subdomains, Open Ports, Technologies, SSL Certificates, Typosquats
- **Posture summary** with plain-language security assessment
- **Lead capture CTA** with name/email/company form
- **Dark glassmorphism UI** with ProCircular branding

## Tech Stack

- Vanilla JavaScript + CSS — no frameworks, no build step, no dependencies
- Google Fonts: DM Sans + JetBrains Mono
- Opens directly in any browser

## Usage

```
open index.html
```

Type a domain (pre-filled with `andrews.edu`) and click **Scan Now** to see the full experience.

## Files

```
index.html            — HTML shell with all section structure
style.css             — Dark theme, glassmorphism, animations, responsive
app.js                — Demo data, scan simulation, rendering, event handlers
procircular-logo.png  — ProCircular logo asset
```

## License

Internal use only — ProCircular, Inc.
