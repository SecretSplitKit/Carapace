# Carapace GUI

This Svelte application is the loopback control interface for the Carapace daemon. The
production build is embedded in `crates/carapace-api/static`. It is not a separate remote
web service.

## Requirements

- Use the Node and npm versions in the repository configuration.
- Run the daemon on the same computer as the browser.
- Keep the API token private. The daemon creates it with restricted access in its state
  directory.

## Development

Install the locked dependencies and run the type checks:

```sh
npm ci
npm run check
npm test
npx playwright install chromium
npm run test:browser
```

The source and rendered-component tests check API authentication, accessible alerts,
clipboard success and failure, and deliberate WebSocket retry and shutdown. The Playwright
suite runs desktop and mobile Chromium. It checks keyboard focus, axe accessibility rules,
destructive confirmations, claimant activation, clipboard feedback, and viewport overflow.
CI installs the Chromium build that the exact Playwright dependency selects.

Start the development server only for local interface work:

```sh
npm run dev
```

The GUI expects the authenticated Carapace API. Do not expose the development server or
the daemon API to another computer.

## Production build

Build the embedded files:

```sh
npm run build
```

The build writes to `../crates/carapace-api/static`. Commit the source and generated files
together. CI rebuilds the GUI and fails if the generated output differs.

## Security model

The daemon is authoritative for vault, friendship, storage-grant, replica, and recovery
state. Browser storage holds presentation preferences only. Recovery scope, threshold,
issued-share count, trustee delivery, warnings, alarms, and storage grants come from the
authenticated status response.

Never put shares, root keys, passphrases, decrypted grants, or API tokens in logs, error
reports, browser storage, or screenshots.
