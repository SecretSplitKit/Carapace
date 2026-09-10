import { get } from 'svelte/store';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { lastError } from '$lib/errors';
import { copyToClipboard } from '$lib/format';

describe('clipboard feedback', () => {
	beforeEach(() => lastError.set(null));

	it('reports success only after the clipboard accepts the value', async () => {
		const writeText = vi.fn().mockResolvedValue(undefined);
		Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
		expect(await copyToClipboard('public-value')).toBe(true);
		expect(writeText).toHaveBeenCalledWith('public-value');
		expect(get(lastError)).toBeNull();
	});

	it('shows safe manual-copy guidance after clipboard rejection', async () => {
		Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: vi.fn().mockRejectedValue(new Error('denied')) } });
		expect(await copyToClipboard('public-value')).toBe(false);
		expect(get(lastError)).toMatch(/Select and copy the value manually/);
	});
});

describe('status WebSocket lifecycle', () => {
	beforeEach(() => { vi.useFakeTimers(); vi.resetModules(); });
	afterEach(() => vi.useRealTimers());

	it('retries an unexpected close and does not retry a deliberate stop', async () => {
		const sockets: FakeSocket[] = [];
		class FakeSocket {
			onopen: (() => void) | null = null;
			onmessage: ((event: MessageEvent) => void) | null = null;
			onclose: (() => void) | null = null;
			onerror: (() => void) | null = null;
			constructor(public url: string) { sockets.push(this); }
			close() { this.onclose?.(); }
		}
		vi.stubGlobal('WebSocket', FakeSocket);
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) }));
		const feed = await import('$lib/statusStore');
		feed.startStatusFeed();
		expect(sockets).toHaveLength(1);
		sockets[0].onclose?.();
		await vi.advanceTimersByTimeAsync(1_000);
		expect(sockets).toHaveLength(2);
		feed.stopStatusFeed();
		await vi.advanceTimersByTimeAsync(30_000);
		expect(sockets).toHaveLength(2);
	});
});
