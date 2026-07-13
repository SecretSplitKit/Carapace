<script lang="ts">
	import { api } from '$lib/api';
	import { copyToClipboard } from '$lib/format';
	import type { PublishedVault } from '$lib/types';

	let vaults = $state<PublishedVault[]>([]);
	api
		.listVaults()
		.then((r) => (vaults = r.published))
		.catch(() => {});

	let vid = $state('');
	let pathsText = $state('');
	let audienceText = $state('');
	let creating = $state(false);
	let grantHex = $state<string | null>(null);
	let grantCopied = $state(false);

	async function createGrant() {
		if (!vid || !pathsText.trim() || !audienceText.trim()) return;
		creating = true;
		grantHex = null;
		try {
			const paths = pathsText
				.split('\n')
				.map((p) => p.trim())
				.filter(Boolean);
			const audience = audienceText
				.split(',')
				.map((a) => a.trim())
				.filter(Boolean);
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
	let outDir = $state('');
	let fetching = $state(false);
	let written = $state<string[] | null>(null);

	async function runFetch() {
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
					<option value={v.vid}>{v.vid.slice(0, 16)}… (epoch {v.epoch})</option>
				{/each}
			</select>
			<label for="share-paths" class="muted">Files to share (one path per line)</label>
			<textarea id="share-paths" rows="4" bind:value={pathsText}></textarea>
			<label for="share-audience" class="muted">Audience (friend node ids, comma-separated)</label>
			<input id="share-audience" bind:value={audienceText} />
			<button class="primary" type="submit" disabled={creating}>
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
		<form onsubmit={(e) => (e.preventDefault(), runFetch())}>
			<label for="fetch-grant" class="muted">Grant they sent you (hex)</label>
			<input id="fetch-grant" bind:value={fetchGrantHex} />
			<label for="fetch-owner" class="muted">Their node id (hex)</label>
			<input id="fetch-owner" bind:value={ownerNode} />
			<label for="fetch-addrs" class="muted">Their address(es), comma-separated</label>
			<input id="fetch-addrs" bind:value={ownerAddrs} />
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
</style>
