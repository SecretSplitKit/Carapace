// The daemon injects `window.__CARAPACE_TOKEN__` into the served index.html.
// In `npm run dev` there is no daemon in front of Vite, so fall back to a
// Vite env var (`VITE_CARAPACE_TOKEN`, see gui/.env.example) for local work
// against a daemon started separately.

declare global {
	interface Window {
		__CARAPACE_TOKEN__?: string;
	}
}

export function apiToken(): string {
	if (typeof window !== 'undefined' && window.__CARAPACE_TOKEN__) {
		return window.__CARAPACE_TOKEN__;
	}
	return import.meta.env.VITE_CARAPACE_TOKEN ?? '';
}
