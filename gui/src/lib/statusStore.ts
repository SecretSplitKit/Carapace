import { writable } from 'svelte/store';
import { apiToken } from './token';
import { api } from './api';
import type { StatusSnapshot } from './types';

export const status = writable<StatusSnapshot | null>(null);
/** True once a live WS connection is up (vs. the one-shot initial fetch). */
export const live = writable(false);

let socket: WebSocket | null = null;
let retryMs = 1000;
let stopped = true;
let generation = 0;
let retry: ReturnType<typeof setTimeout> | undefined;
export const sessionExpired = writable(false);

function connect(): void {
	if (stopped || typeof window === 'undefined') return;
	const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
	const url = `${proto}//${location.host}/api/events`;
	const current = new WebSocket(url);
	socket = current;
	const active = () => !stopped && socket === current;

	current.onopen = () => {
		if (!active()) return;
		sessionExpired.set(false);
		retryMs = 1000;
	};
	current.onmessage = (ev) => {
		if (!active()) return;
		try {
			status.set(JSON.parse(ev.data) as StatusSnapshot);
			live.set(true);
		} catch {
			// ignore a malformed frame; the next tick will correct it
		}
	};
	current.onclose = async () => {
		if (!active()) return;
		live.set(false);
		try {
			const response = await fetch('/api/status', { headers: { Authorization: `Bearer ${apiToken()}` } });
			if (!active()) return;
			if (response.status === 401) {
				sessionExpired.set(true);
				return;
			}
		} catch { /* retry while the daemon is unavailable */ }
		if (!active()) return;
		retry = setTimeout(connect, retryMs);
		retryMs = Math.min(retryMs * 2, 15000);
	};

	current.onerror = () => {
		current.close();
	};
}

/** Kick off the live feed, seeded by one REST fetch so the first paint isn't blank. */
export function startStatusFeed(): void {
	if (!stopped) return;
	stopped = false;
	const currentGeneration = ++generation;
	retryMs = 1000;
	api
		.status()
		.then((s) => { if (!stopped && generation === currentGeneration) status.set(s); })
		.catch(() => {
			/* reportError already fired inside api.status() */
		});
	connect();
}

export function stopStatusFeed(): void {
	stopped = true;
	generation++;
	clearTimeout(retry);
	live.set(false);
	socket?.close();
	socket = null;
}
