import { writable } from 'svelte/store';
import { apiToken } from './token';
import { api } from './api';
import type { StatusSnapshot } from './types';

export const status = writable<StatusSnapshot | null>(null);
/** True once a live WS connection is up (vs. the one-shot initial fetch). */
export const live = writable(false);

let socket: WebSocket | null = null;
let retryMs = 1000;

function connect(): void {
	if (typeof window === 'undefined') return;
	const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
	const url = `${proto}//${location.host}/api/events?token=${encodeURIComponent(apiToken())}`;
	socket = new WebSocket(url);

	socket.onopen = () => {
		live.set(true);
		retryMs = 1000;
	};
	socket.onmessage = (ev) => {
		try {
			status.set(JSON.parse(ev.data) as StatusSnapshot);
		} catch {
			// ignore a malformed frame; the next tick will correct it
		}
	};
	socket.onclose = () => {
		live.set(false);
		// ponytail: fixed backoff ladder, not a full jittered retry policy -
		// fine for a single loopback daemon that's either up or restarting.
		setTimeout(connect, retryMs);
		retryMs = Math.min(retryMs * 2, 15000);
	};
	socket.onerror = () => {
		socket?.close();
	};
}

/** Kick off the live feed, seeded by one REST fetch so the first paint isn't blank. */
export function startStatusFeed(): void {
	api
		.status()
		.then((s) => status.set(s))
		.catch(() => {
			/* reportError already fired inside api.status() */
		});
	connect();
}

export function stopStatusFeed(): void {
	socket?.close();
	socket = null;
}
