<script lang="ts">
	import { api } from '$lib/api';
	import { status } from '$lib/statusStore';
	import { notes, noteFriendGrant } from '$lib/notes';
	import { formatBytes, copyToClipboard } from '$lib/format';
	import CopyHex from './CopyHex.svelte';

	let friends = $state<string[]>([]);
	let loading = $state(true);

	let ticket = $state<{ uri: string; ticket_hex: string } | null>(null);
	let issuing = $state(false);

	let ticketHex = $state('');
	let addrsInput = $state('');
	let grantGiB = $state(1);
	let adding = $state(false);
	let addResult = $state<string | null>(null);
	let uriCopied = $state(false);

	// Per-friend unfriend (§9.3): two-step confirm, then POST the unfriend endpoint.
	let confirming = $state<string | null>(null);
	let removing = $state<string | null>(null);
	let unfriendNote = $state<{ friend: string; resplit: boolean; rsids: number[] } | null>(null);

	async function refresh() {
		loading = true;
		const res = await api.listFriends().catch(() => ({ count: 0, list: [] }));
		friends = res.list;
		loading = false;
	}

	refresh();
	$effect(() => {
		$status?.friends.count;
		refresh();
	});

	async function issueTicket() {
		issuing = true;
		try {
			const res = await api.issueTicket();
			ticket = res;
		} finally {
			issuing = false;
		}
	}

	async function copyUri() {
		if (ticket && (await copyToClipboard(ticket.uri))) {
			uriCopied = true;
			setTimeout(() => (uriCopied = false), 1200);
		}
	}

	async function addFriend() {
		if (!ticketHex.trim()) return;
		adding = true;
		addResult = null;
		try {
			const addrs = addrsInput
				.split(',')
				.map((a) => a.trim())
				.filter(Boolean);
			const bytes = Math.round(grantGiB * 1024 ** 3);
			const res = await api.addFriend(ticketHex.trim(), addrs.length ? addrs : undefined, bytes);
			noteFriendGrant(res.friend, bytes);
			addResult = `Friend added (${res.friend.slice(0, 12)}…).`;
			ticketHex = '';
			addrsInput = '';
			await refresh();
		} finally {
			adding = false;
		}
	}

	async function unfriend(f: string) {
		removing = f;
		try {
			const res = await api.unfriend(f);
			confirming = null;
			if (res.was_friend) {
				unfriendNote = { friend: f, resplit: res.resplit_triggered, rsids: res.recovery_set_ids };
			}
			await refresh();
		} finally {
			removing = null;
		}
	}
</script>

<section>
	<h1>Friends</h1>
	<p class="muted">
		Friends hold encrypted replicas of your vaults and, if you make them trustees, pieces of your
		recovery key.
	</p>

	<div class="grid">
		<div class="card">
			<h3>Invite a friend</h3>
			<button class="primary" type="button" onclick={issueTicket} disabled={issuing}>
				{issuing ? 'Issuing…' : 'Create invite ticket'}
			</button>
			{#if ticket}
				<div class="ticket">
					<label for="ticket-uri" class="muted">Send this to your friend</label>
					<div class="row">
						<input id="ticket-uri" readonly value={ticket.uri} />
						<button type="button" onclick={copyUri}>{uriCopied ? 'Copied' : 'Copy'}</button>
					</div>
				</div>
			{/if}
		</div>

		<div class="card">
			<h3>Add a friend from a ticket</h3>
			<form onsubmit={(e) => (e.preventDefault(), addFriend())}>
				<label for="ticket-hex" class="muted">Ticket they sent you</label>
				<input id="ticket-hex" bind:value={ticketHex} placeholder="carapace: ticket or its hex" />
				<label for="addrs" class="muted">Their address (optional - uses the ticket's if blank)</label>
				<input id="addrs" bind:value={addrsInput} placeholder="host:port, host2:port2" />
				<label for="grant" class="muted">Storage you'll hold for them (GiB)</label>
				<input id="grant" type="number" min="0" step="0.25" bind:value={grantGiB} style="width: 6rem" />
				<button class="primary" type="submit" disabled={adding || !ticketHex.trim()}>
					{adding ? 'Adding…' : 'Add friend'}
				</button>
			</form>
			{#if addResult}
				<p class="healthy">{addResult}</p>
			{/if}
		</div>
	</div>

	{#if unfriendNote}
		<div class="card {unfriendNote.resplit ? 'at-risk' : 'healthy'}" style="margin-top: 1.5rem">
			{#if unfriendNote.resplit}
				<h3>Re-split required</h3>
				<p>
					{unfriendNote.friend.slice(0, 12)}… was a trustee. A trustee re-split is now running for
					recovery set{unfriendNote.rsids.length > 1 ? 's' : ''}
					{unfriendNote.rsids.join(', ')}. Both the old and new sets stay usable until the new set is
					live and the old shares are destroyed - track it under
					<strong>Recovery &amp; trustees</strong>.
				</p>
			{:else}
				<p>{unfriendNote.friend.slice(0, 12)}… removed. They held no recovery shares, so no re-split
					was needed.</p>
			{/if}
			<button type="button" onclick={() => (unfriendNote = null)}>Dismiss</button>
		</div>
	{/if}

	<h2 style="margin-top: 2rem">Your friends</h2>
	{#if loading}
		<p class="muted">Loading…</p>
	{:else if friends.length === 0}
		<p class="muted">No friends yet. Issue an invite ticket to add your first one.</p>
	{:else}
		<div class="list">
			{#each friends as f (f)}
				<div class="card friend-row">
					<CopyHex value={f} />
					<span class="muted">
						{#if $notes.friendStorageGrants[f] !== undefined}
							≈{formatBytes($notes.friendStorageGrants[f])} agreed (recorded in this browser)
						{:else}
							storage limit not recorded here
						{/if}
					</span>
					{#if confirming === f}
						<span class="confirm">
							<span class="muted">Remove this friend?</span>
							<button
								class="danger"
								type="button"
								disabled={removing === f}
								onclick={() => unfriend(f)}
							>
								{removing === f ? 'Removing…' : 'Confirm unfriend'}
							</button>
							<button type="button" disabled={removing === f} onclick={() => (confirming = null)}>
								Cancel
							</button>
						</span>
					{:else}
						<button type="button" onclick={() => (confirming = f)}>Unfriend</button>
					{/if}
				</div>
			{/each}
		</div>
	{/if}
	<p class="muted" style="font-size: var(--step--1); margin-top: 0.5rem">
		The daemon doesn't yet report a friend's storage/trustee/relay role or agreed limit back to the
		GUI - the figures above are only what this browser set when adding the friend.
	</p>
</section>

<style>
	.grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
		gap: 1rem;
		margin: 1rem 0;
	}

	form label,
	.ticket label {
		display: block;
		margin: 0.6rem 0 0.3rem;
		font-size: var(--step--1);
	}

	form input {
		width: 100%;
	}

	form button {
		margin-top: 1rem;
	}

	.row {
		display: flex;
		gap: 0.5rem;
	}

	.row input {
		flex: 1;
	}

	.list {
		display: flex;
		flex-direction: column;
		gap: 0.6rem;
	}

	.friend-row {
		display: flex;
		justify-content: space-between;
		align-items: center;
		flex-wrap: wrap;
		gap: 0.5rem;
	}

	.confirm {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		flex-wrap: wrap;
	}

	button.danger {
		border-color: var(--coral);
		color: var(--coral);
	}

	button.danger:hover {
		background: var(--coral);
		color: var(--ink);
	}
</style>
