<script lang="ts">
	import { api } from '$lib/api';
	import { status } from '$lib/statusStore';
	import FolderPicker from './FolderPicker.svelte';
	import CopyHex from './CopyHex.svelte';
	import type { PublishedVault } from '$lib/types';

	let vaults = $state<PublishedVault[]>([]);
	let replicas = $state<Record<string, string[]>>({});
	let loading = $state(true);

	let dir = $state('');
	let publishing = $state(false);
	let syncNode = $state('');
	let syncAddrs = $state('');
	let syncPeer = $state('');
	let syncOutDir = $state('');
	let syncing = $state(false);
	let syncResult = $state<{ vid: string; epoch: number; out_dir: string }[] | null>(null);
	let operationError = $state('');

	let placeVid = $state<string | null>(null);
	let placeR = $state(3);
	let peerRows = $state<{ node: string; addrs: string }[]>([{ node: '', addrs: '' }]);
	let placing = $state(false);
	let placedResult = $state<string[] | null>(null);
	let selectedReplicaNodes = $state<string[]>([]);

	async function refresh() {
		loading = true;
		try {
			vaults = (await api.listVaults()).published;
			const entries = await Promise.all(vaults.map(async (v) => {
				try { return [v.vid, (await api.listReplicas(v.vid)).members] as const; }
				catch { return [v.vid, replicas[v.vid] ?? []] as const; }
			}));
			replicas = Object.fromEntries(entries);
		} catch { /* Preserve the last known folders while the daemon is unavailable. */ }
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
		operationError = '';
		try {
			await api.publishVault(dir.trim());
			dir = '';
			await refresh();
		} catch (error) {
			operationError = (error as Error).message;
		} finally {
			publishing = false;
		}
	}

	async function syncOwned() {
		const selected = $status?.peers.find((peer) => peer.node === syncPeer);
		if (selected) {
			syncNode = selected.node;
			syncAddrs = selected.addrs.join(',');
		}
		if (!syncNode.trim() || !syncOutDir.trim()) return;
		syncing = true;
		syncResult = null;
		operationError = '';
		try {
			const addrs = syncAddrs.split(',').map((a) => a.trim()).filter(Boolean);
			const res = await api.syncOwned({ node: syncNode.trim(), addrs }, syncOutDir.trim());
			syncResult = res.restored;
			await refresh();
		} catch (error) {
			operationError = (error as Error).message;
		} finally {
			syncing = false;
		}
	}

	function openPlacement(vid: string) {
		placeVid = vid;
		placedResult = null;
		peerRows = [{ node: '', addrs: '' }];
		selectedReplicaNodes = [];
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
			const selected = ($status?.peers ?? []).filter((peer) => selectedReplicaNodes.includes(peer.node));
			const manualPeers = peerRows.filter((p) => p.node.trim()).map((p) => ({
					node: p.node.trim(),
					addrs: p.addrs
						.split(',')
						.map((a) => a.trim())
						.filter(Boolean)
				}));
			const peers = [...selected.map((peer) => ({ node: peer.node, addrs: peer.addrs })), ...manualPeers];
			const res = await api.placeReplicas(placeVid, peers, placeR);
			placedResult = res.placed;
			await refresh();
		} catch (error) {
			operationError = (error as Error).message;
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
	{#if operationError}<p class="alarm-text" role="alert">{operationError}</p>{/if}

	<form class="card publish-form" onsubmit={(e) => (e.preventDefault(), publish())}>
		<p class="dependency">Local operation</p>
		<label for="vault-dir">Directory to publish</label>
		<div class="row">
			<FolderPicker id="vault-dir" bind:value={dir} />
			<button class="primary" type="submit" disabled={publishing || !dir.trim()}>
				{publishing ? 'Publishing…' : 'Publish vault'}
			</button>
		</div>
	</form>

	<form class="card publish-form" aria-busy={syncing} onsubmit={(e) => (e.preventDefault(), syncOwned())}>
		<h3>Sync from your other device</h3>
		<p class="muted" style="font-size: var(--step--1)">
			This peer-dependent action pulls authorized vault updates and restores them below the selected directory.
		</p>
		<label for="sync-peer">Other device or friend</label>
		<select id="sync-peer" bind:value={syncPeer}>
			<option value="">Select a verified peer</option>
			{#each $status?.peers ?? [] as peer (peer.node)}
				<option value={peer.node}>{peer.display || 'Friend'} · {peer.node.slice(0, 10)}…</option>
			{/each}
		</select>
		<details><summary>Advanced manual peer</summary>
			<label for="sync-node">Node id</label><input id="sync-node" bind:value={syncNode} />
			<label for="sync-addrs">Address hints</label><input id="sync-addrs" bind:value={syncAddrs} />
		</details>
		<label for="sync-out">Restore into</label>
		<input id="sync-out" bind:value={syncOutDir} placeholder="/path/to/restore-root" />
		<button class="primary" type="submit" disabled={syncing || (!syncPeer && !syncNode.trim()) || !syncOutDir.trim()}>Sync and restore</button>
		<div aria-live="polite">{#if syncing}<p>Sync is in progress.</p>{:else if syncResult}
			{#if syncResult.length === 0}
				<p class="muted">The sync completed. There were no new vault versions to restore.</p>
			{:else}
				<p class="healthy">Restored {syncResult.length} vault(s).</p>
				<ul>
					{#each syncResult as item (item.vid)}
						<li><span class="mono">{item.vid.slice(0, 12)}…</span>, epoch {item.epoch}, in <span class="mono">{item.out_dir}</span></li>
					{/each}
				</ul>
			{/if}
		{/if}</div>
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
						<strong>{v.name}</strong><br />
						{#if v.dir}<p>{v.dir}</p>{/if}
						<p>{v.syncing ? 'Syncing…' : v.watching ? 'Watching for changes' : 'Not currently watching'}</p>
						{#if v.last_error}<p role="alert">{v.last_error}</p>{/if}
						{#if v.recovery_backup}<p>Files saved before retrying an interrupted restore: <span class="mono">{v.recovery_backup}</span>. Check this folder for edits to keep.</p>{/if}
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
			<p class="dependency">Peer-dependent operation · safe to retry if a peer is offline</p>
			<fieldset><legend>Select verified friends</legend>
				{#each $status?.peers ?? [] as peer (peer.node)}
					<label><input type="checkbox" bind:group={selectedReplicaNodes} value={peer.node} /> {peer.display || 'Friend'} · {peer.node.slice(0, 10)}…</label>
				{/each}
			</fieldset>
			<details><summary>Advanced manual peers</summary>{#each peerRows as row, i (i)}
				<div class="row peer-row">
					<input placeholder="friend node id (hex)" bind:value={row.node} />
					<input placeholder="addrs, comma-separated (host:port)" bind:value={row.addrs} />
					{#if peerRows.length > 1}
						<button type="button" onclick={() => removePeerRow(i)} aria-label="Remove peer">✕</button>
					{/if}
				</div>
			{/each}<button type="button" onclick={addPeerRow}>Add another peer</button></details>
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

	.publish-form + .publish-form {
		margin-top: 1rem;
	}

	.publish-form > input {
		width: 100%;
		margin-bottom: 0.6rem;
	}

	.publish-form > button {
		margin-top: 0.4rem;
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

	@media (max-width: 640px) {
		.vault-row {
			grid-template-columns: 1fr;
			gap: 0.9rem;
		}

		.row > input,
		.peer-row > input {
			min-width: 0;
			width: 100%;
		}
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
