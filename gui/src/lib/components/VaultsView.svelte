<script lang="ts">
	import { api } from '$lib/api';
	import { status } from '$lib/statusStore';
	import CopyHex from './CopyHex.svelte';
	import type { PublishedVault } from '$lib/types';

	let vaults = $state<PublishedVault[]>([]);
	let replicas = $state<Record<string, string[]>>({});
	let loading = $state(true);

	let dir = $state('');
	let publishing = $state(false);

	let placeVid = $state<string | null>(null);
	let placeR = $state(3);
	let peerRows = $state<{ node: string; addrs: string }[]>([{ node: '', addrs: '' }]);
	let placing = $state(false);
	let placedResult = $state<string[] | null>(null);

	async function refresh() {
		loading = true;
		const res = await api.listVaults().catch(() => ({ published: [] }));
		vaults = res.published;
		const entries = await Promise.all(
			vaults.map(async (v) => [v.vid, (await api.listReplicas(v.vid).catch(() => ({ members: [] }))).members] as const)
		);
		replicas = Object.fromEntries(entries);
		loading = false;
	}

	refresh();
	// Any live status change (a new vault published elsewhere, a replica landing)
	// is worth a re-check; cheap given the small vault counts expected here.
	$effect(() => {
		$status?.vaults.published.length;
		refresh();
	});

	async function publish() {
		if (!dir.trim()) return;
		publishing = true;
		try {
			await api.publishVault(dir.trim());
			dir = '';
			await refresh();
		} finally {
			publishing = false;
		}
	}

	function openPlacement(vid: string) {
		placeVid = vid;
		placedResult = null;
		peerRows = [{ node: '', addrs: '' }];
	}

	function addPeerRow() {
		peerRows = [...peerRows, { node: '', addrs: '' }];
	}

	function removePeerRow(i: number) {
		peerRows = peerRows.filter((_, idx) => idx !== i);
	}

	async function placeReplicas() {
		if (!placeVid) return;
		placing = true;
		try {
			const peers = peerRows
				.filter((p) => p.node.trim())
				.map((p) => ({
					node: p.node.trim(),
					addrs: p.addrs
						.split(',')
						.map((a) => a.trim())
						.filter(Boolean)
				}));
			const res = await api.placeReplicas(placeVid, peers, placeR);
			placedResult = res.placed;
			await refresh();
		} finally {
			placing = false;
		}
	}
</script>

<section>
	<h1>Vaults</h1>
	<p class="muted">
		A vault is a directory you've published for friends to hold replicas of. Publishing ingests
		and encrypts it locally; placing replicas is what actually copies it out.
	</p>

	<form class="card publish-form" onsubmit={(e) => (e.preventDefault(), publish())}>
		<label for="vault-dir">Directory to publish</label>
		<div class="row">
			<input id="vault-dir" bind:value={dir} placeholder="/path/to/directory" />
			<button class="primary" type="submit" disabled={publishing || !dir.trim()}>
				{publishing ? 'Publishing…' : 'Publish vault'}
			</button>
		</div>
	</form>

	{#if loading}
		<p class="muted">Loading vaults…</p>
	{:else if vaults.length === 0}
		<p class="muted">No vaults published yet. Publish a directory above to start protecting it.</p>
	{:else}
		<div class="list">
			{#each vaults as v (v.vid)}
				<div class="card vault-row">
					<div>
						<CopyHex value={v.vid} />
						<div class="muted" style="font-size: var(--step--1)">epoch {v.epoch}</div>
					</div>
					<div>
						<div class="label muted">Replica members</div>
						{#if replicas[v.vid]?.length}
							<ul class="member-list">
								{#each replicas[v.vid] as m (m)}
									<li><CopyHex value={m} /></li>
								{/each}
							</ul>
						{:else}
							<span class="at-risk">no replicas placed - vault exists only here</span>
						{/if}
					</div>
					<button type="button" onclick={() => openPlacement(v.vid)}>Place replicas</button>
				</div>
			{/each}
		</div>
	{/if}

	{#if placeVid}
		<div class="card" style="margin-top: 1.5rem">
			<h3>Place replicas for <span class="mono">{placeVid.slice(0, 12)}…</span></h3>
			<p class="muted" style="font-size: var(--step--1)">
				The daemon doesn't remember a friend's network address for you - list each peer's node
				id and dialable address(es) again here.
			</p>
			{#each peerRows as row, i (i)}
				<div class="row peer-row">
					<input placeholder="friend node id (hex)" bind:value={row.node} />
					<input placeholder="addrs, comma-separated (host:port)" bind:value={row.addrs} />
					{#if peerRows.length > 1}
						<button type="button" onclick={() => removePeerRow(i)} aria-label="Remove peer">✕</button>
					{/if}
				</div>
			{/each}
			<button type="button" onclick={addPeerRow}>Add another peer</button>
			<div class="row" style="margin-top: 0.75rem">
				<label for="place-r">Replicas to place (r)</label>
				<input id="place-r" type="number" min="1" style="width: 5rem" bind:value={placeR} />
				<button class="primary" type="button" disabled={placing} onclick={placeReplicas}>
					{placing ? 'Placing…' : 'Place'}
				</button>
				<button type="button" onclick={() => (placeVid = null)}>Cancel</button>
			</div>
			{#if placedResult}
				<p class="healthy">Placed on {placedResult.length} peer{placedResult.length === 1 ? '' : 's'}.</p>
			{/if}
		</div>
	{/if}
</section>

<style>
	.publish-form label {
		display: block;
		margin-bottom: 0.4rem;
		font-size: var(--step--1);
		color: var(--muted);
	}

	.row {
		display: flex;
		gap: 0.6rem;
		align-items: center;
		flex-wrap: wrap;
	}

	.row input {
		flex: 1;
		min-width: 180px;
	}

	.list {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
		margin-top: 1.5rem;
	}

	.vault-row {
		display: grid;
		grid-template-columns: 1fr 2fr auto;
		gap: 1.5rem;
		align-items: start;
	}

	.member-list {
		margin: 0.3rem 0 0;
		padding: 0;
		list-style: none;
		display: flex;
		flex-direction: column;
		gap: 0.2rem;
	}

	.label {
		font-size: var(--step--1);
		text-transform: uppercase;
		letter-spacing: 0.06em;
	}

	.peer-row {
		margin-bottom: 0.5rem;
	}
</style>
