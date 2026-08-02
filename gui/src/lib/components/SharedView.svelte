<script lang="ts">
	import { api } from '$lib/api';
	import { copyToClipboard } from '$lib/format';
	import { status } from '$lib/statusStore';
	import type { PublishedVault } from '$lib/types';

	let vaults = $state<PublishedVault[]>([]);
	api
		.listVaults()
		.then((r) => (vaults = r.published))
		.catch(() => {});

	let vid = $state('');
	let pathsText = $state('');
	let audienceText = $state('');
	let selectedAudience = $state<string[]>([]);
	let creating = $state(false);
	let grantHex = $state<string | null>(null);
	let grantCopied = $state(false);
	let grantConfirmed = $state(false);

	async function createGrant() {
		if (!vid || !pathsText.trim() || (selectedAudience.length === 0 && !audienceText.trim())) return;
		creating = true;
		grantHex = null;
		try {
			const paths = pathsText
				.split('\n')
				.map((p) => p.trim())
				.filter(Boolean);
			const manualAudience = audienceText
				.split(',')
				.map((a) => a.trim())
				.filter(Boolean);
			const audience = [...new Set([...selectedAudience, ...manualAudience])];
			const res = await api.discloseFiles(vid, paths, audience);
			grantHex = res.grant_hex;
		} finally {
			creating = false;
		}
	}

	async function copyGrant() {
		if (grantHex && (await copyToClipboard(grantHex))) {
			grantCopied = true;
			setTimeout(() => (grantCopied = false), 1200);
		}
	}

	let fetchGrantHex = $state('');
	let ownerNode = $state('');
	let ownerAddrs = $state('');
	let ownerPeer = $state('');
	let outDir = $state('');
	let fetching = $state(false);
	let written = $state<string[] | null>(null);

	async function runFetch() {
		const selected = $status?.peers.find((peer) => peer.node === ownerPeer);
		if (selected) { ownerNode = selected.node; ownerAddrs = selected.addrs.join(','); }
		if (!fetchGrantHex.trim() || !ownerNode.trim() || !outDir.trim()) return;
		fetching = true;
		written = null;
		try {
			const addrs = ownerAddrs
				.split(',')
				.map((a) => a.trim())
				.filter(Boolean);
			const res = await api.fetchGrant(fetchGrantHex.trim(), { node: ownerNode.trim(), addrs }, outDir.trim());
			written = res.written;
		} finally {
			fetching = false;
		}
	}
</script>

<section>
	<h1>Shared files</h1>

	<div class="card">
		<h3>Share files from a vault</h3>
		<p class="dependency">Local operation · creates a non-recallable encrypted snapshot</p>
		<p class="muted" style="font-size: var(--step--1)">
			A share is a <strong>snapshot</strong> of these files at the vault's current epoch. It cannot
			be recalled once handed over - editing the files afterward only affects future shares, not
			this one.
		</p>
		<form onsubmit={(e) => (e.preventDefault(), createGrant())}>
			<label for="share-vid" class="muted">Vault</label>
			<select id="share-vid" bind:value={vid}>
				<option value="" disabled>choose a vault</option>
				{#each vaults as v (v.vid)}
					<option value={v.vid}>{v.name} (epoch {v.epoch})</option>
				{/each}
			</select>
			<label for="share-paths" class="muted">Files to share (one path per line)</label>
			<textarea id="share-paths" rows="4" bind:value={pathsText}></textarea>
			<fieldset><legend>Recipients</legend>{#each $status?.peers ?? [] as peer (peer.node)}<label><input type="checkbox" bind:group={selectedAudience} value={peer.user} /> {peer.display || `Friend ${peer.user.slice(0, 10)}…`}</label>{/each}</fieldset>
			<details><summary>Advanced manual recipient identities</summary><label for="share-audience" class="muted">User ids, comma-separated</label><input id="share-audience" bind:value={audienceText} /></details>
				<label class="confirm-action">
					<input type="checkbox" bind:checked={grantConfirmed} />
					I understand that recipients can keep this snapshot and that I cannot recall it.
				</label>
				<button class="primary" type="submit" disabled={creating || !vid || !pathsText.trim() || (selectedAudience.length === 0 && !audienceText.trim()) || !grantConfirmed}>
				{creating ? 'Sharing…' : 'Share files'}
			</button>
		</form>
		{#if grantHex}
			<div class="row" style="margin-top: 0.75rem">
				<code class="mono share-text">{grantHex}</code>
				<button type="button" onclick={copyGrant}>{grantCopied ? 'Copied' : 'Copy'}</button>
			</div>
			<p class="muted" style="font-size: var(--step--1)">Send this to each person in the audience.</p>
		{/if}
	</div>

	<div class="card" style="margin-top: 1.5rem">
		<h3>Fetch a file someone shared with you</h3>
		<p class="dependency">Peer-dependent operation · no partial output is activated, so a failed fetch is safe to retry</p>
		<form onsubmit={(e) => (e.preventDefault(), runFetch())}>
			<label for="fetch-grant" class="muted">Grant they sent you (hex)</label>
			<input id="fetch-grant" bind:value={fetchGrantHex} />
			<label for="fetch-peer" class="muted">Sender</label><select id="fetch-peer" bind:value={ownerPeer}><option value="">Select a verified peer</option>{#each $status?.peers ?? [] as peer (peer.node)}<option value={peer.node}>{peer.display || 'Friend'}</option>{/each}</select>
			<details><summary>Advanced manual peer</summary><label for="fetch-owner" class="muted">Node id</label><input id="fetch-owner" bind:value={ownerNode} /><label for="fetch-addrs" class="muted">Address hints</label><input id="fetch-addrs" bind:value={ownerAddrs} /></details>
			<label for="fetch-out" class="muted">Save into</label>
			<input id="fetch-out" bind:value={outDir} placeholder="/path/to/out-dir" />
			<button class="primary" type="submit" disabled={fetching}>
				{fetching ? 'Fetching…' : 'Fetch files'}
			</button>
		</form>
		{#if written}
			<p class="healthy">Wrote {written.length} file(s):</p>
			<ul>
				{#each written as p (p)}<li class="mono">{p}</li>{/each}
			</ul>
		{/if}
	</div>
</section>

<style>
	form label {
		display: block;
		margin: 0.6rem 0 0.3rem;
		font-size: var(--step--1);
	}

	form input,
	form select,
	form textarea {
		width: 100%;
	}

	form button {
		margin-top: 1rem;
	}

	.row {
		display: flex;
		gap: 0.5rem;
		align-items: center;
	}

	.share-text {
		flex: 1;
		word-break: break-all;
		background: var(--plate-raised);
		padding: 0.4em 0.6em;
		border-radius: 6px;
	}

	.confirm-action {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.confirm-action input {
		width: auto;
	}

	@media (max-width: 640px) {
		.row {
			align-items: stretch;
			flex-direction: column;
		}
	}
</style>
