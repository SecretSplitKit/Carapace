// ponytail: the loopback API doesn't report a friend's agreed storage grant, a
// friend's roles, or a recovery set's M/N/scope back to us (it only tracks live
// counts + lets you act). Cache what this GUI itself set, keyed by id, in
// localStorage so those numbers still show up on reload. Ceiling: another
// client (CLI, another GUI instance) setting the same thing won't be reflected
// here. Upgrade when the daemon starts returning this in /api/status or a
// dedicated endpoint.

import { writable } from 'svelte/store';

export interface RecoverySetNote {
	rsid: number;
	scope: { kind: 'root' } | { kind: 'vault'; vid: string };
	m: number;
	n: number;
	createdAt: number;
}

interface NotesShape {
	friendStorageGrants: Record<string, number>;
	recoverySets: Record<string, RecoverySetNote>;
}

const KEY = 'carapace-gui-notes-v1';

function load(): NotesShape {
	if (typeof localStorage === 'undefined') return { friendStorageGrants: {}, recoverySets: {} };
	try {
		const raw = localStorage.getItem(KEY);
		if (!raw) return { friendStorageGrants: {}, recoverySets: {} };
		return JSON.parse(raw) as NotesShape;
	} catch {
		return { friendStorageGrants: {}, recoverySets: {} };
	}
}

export const notes = writable<NotesShape>(load());

notes.subscribe((n) => {
	if (typeof localStorage === 'undefined') return;
	localStorage.setItem(KEY, JSON.stringify(n));
});

export function noteFriendGrant(friendHex: string, bytes: number): void {
	notes.update((n) => ({ ...n, friendStorageGrants: { ...n.friendStorageGrants, [friendHex]: bytes } }));
}

export function noteRecoverySet(note: RecoverySetNote): void {
	notes.update((n) => ({
		...n,
		recoverySets: { ...n.recoverySets, [String(note.rsid)]: note }
	}));
}
