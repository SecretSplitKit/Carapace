import { writable } from 'svelte/store';

/** The most recent API/network error, surfaced by a banner - never console-only. */
export const lastError = writable<string | null>(null);

export function reportError(message: string): void {
	lastError.set(message);
}

export function clearError(): void {
	lastError.set(null);
}
