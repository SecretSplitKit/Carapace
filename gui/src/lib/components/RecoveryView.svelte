<script lang="ts">
	import { api } from '$lib/api';
	import { status } from '$lib/statusStore';
	import { notes, noteRecoverySet } from '$lib/notes';
	import { copyToClipboard } from '$lib/format';
	import CopyHex from './CopyHex.svelte';

	let mode = $state<'split' | 'resplit'>('split');
	let rsid = $state(1);
	let scopeKind = $state<'root' | 'vault'>('root');
	let scopeVid = $state('');
	let m = $state(2);
	let n = $state(3);
	let allowOverCap = $state(false);
	let splitting = $state(false);
	let splitShares = $state<string[] | null>(null);
	let splitWarnings = $state<string[]>([]);

	let extendRsid = $state(1);
	let extendCount = $state(1);
	let extendOverCap = $state(false);
	let extending = $state(false);
	let extendShares = $state<string[] | null>(null);

	let openHex = $state('');
	let grantHex = $state('');
	let opening = $state(false);
	let openResult = $state<{ ceremony_id: string; phase: string } | null>(null);

	let approveHex = $state('');
	let approving = $state(false);
	let approveResult = $state<number | null>(null);

	let abortId = $state('');
	let aborting = $state(false);
	let abortHex = $state<string | null>(null);

	async function copy(text: string, mark: (v: boolean) => void) {
		if (await copyToClipboard(text)) {
			mark(true);
			setTimeout(() => mark(false), 1200);
		}
	}

	async function runSplit() {
		splitting = true;
		splitShares = null;
		splitWarnings = [];
		try {
			const scope = scopeKind === 'root' ? ({ kind: 'root' } as const) : ({ kind: 'vault', vid: scopeVid.trim() } as const);
			const fn = mode === 'split' ? api.recoverySplit : api.recoveryResplit;
			const res = await fn(rsid, scope, m, n, allowOverCap);
			splitShares = res.shares;
			splitWarnings = res.warnings;
			noteRecoverySet({ rsid, scope, m, n, createdAt: Date.now() });
		} finally {
			splitting = false;
		}
	}

	async function runExtend() {
		extending = true;
		extendShares = null;
		try {
			const res = await api.recoveryExtend(extendRsid, extendCount, extendOverCap);
			extendShares = res.shares;
			const existing = $notes.recoverySets[String(extendRsid)];
			if (existing) noteRecoverySet({ ...existing, n: existing.n + extendCount });
		} finally {
			extending = false;
		}
	}

	async function runOpen() {
		opening = true;
		openResult = null;
		try {
			openResult = await api.ceremonyOpen(openHex.trim(), grantHex.trim());
		} finally {
			opening = false;
		}
	}

	async function runApprove() {
		approving = true;
		approveResult = null;
		try {
			approveResult = (await api.ceremonyApprove(approveHex.trim())).approvals;
		} finally {
			approving = false;
		}
	}

	async function runAbort() {
		aborting = true;
		abortHex = null;
		try {
			abortHex = (await api.ceremonyAbort(abortId.trim())).abort_hex;
		} finally {
			aborting = false;
		}
	}

	let sharesCopied = $state<Record<number, boolean>>({});
</script>

<section>
	<h1>Recovery &amp; trustees</h1>
	<p class="muted">
		Split your key into pieces so a group of trustees can rebuild it if you lose access.
		Each share below is a bearer secret: send one to each trustee yourself - the daemon
		doesn't track who you gave it to.
	</p>

	{#if $status}
		<div class="card">
			<div class="label muted">Live on this node</div>
			<p class="mono">
				{$status.share_health.recovery_sets_owned} recovery set(s) split ·
				{$status.share_health.shares_held} share(s) held here in trust for others
			</p>
		</div>
	{/if}

	{#if Object.keys($notes.recoverySets).length > 0}
		<h2 style="margin-top: 1.5rem">Recovery sets split from this browser</h2>
		<div class="list">
			{#each Object.values($notes.recoverySets) as rs (rs.rsid)}
				<div class="card set-row">
					<span class="mono">rsid {rs.rsid}</span>
					<span>{rs.scope.kind === 'root' ? 'your root key' : `vault ${rs.scope.vid.slice(0, 10)}…`}</span>
					<span class="mono">{rs.m}-of-{rs.n}</span>
				</div>
			{/each}
		</div>
	{/if}

	<h2 style="margin-top: 2rem">Split or re-split</h2>
	<form class="card" onsubmit={(e) => (e.preventDefault(), runSplit())}>
		<div class="row">
			<label>
				<input type="radio" bind:group={mode} value="split" /> Split (new)
			</label>
			<label>
				<input type="radio" bind:group={mode} value="resplit" /> Re-split (raise M or replace trustees)
			</label>
		</div>
		<div class="row">
			<label for="rsid">Recovery set id</label>
			<input id="rsid" type="number" min="0" bind:value={rsid} style="width: 8rem" />
		</div>
		<div class="row">
			<label>
				<input type="radio" bind:group={scopeKind} value="root" /> Your whole identity (root key)
			</label>
			<label>
				<input type="radio" bind:group={scopeKind} value="vault" /> One vault
			</label>
			{#if scopeKind === 'vault'}
				<input placeholder="vault id (hex)" bind:value={scopeVid} />
			{/if}
		</div>
		<div class="row">
			<label for="m">Trustees needed (M)</label>
			<input id="m" type="number" min="1" bind:value={m} style="width: 5rem" />
			<label for="n">Trustees total (N)</label>
			<input id="n" type="number" min="1" bind:value={n} style="width: 5rem" />
		</div>
		<div class="row">
			<label><input type="checkbox" bind:checked={allowOverCap} /> allow exceeding the recommended trustee cap</label>
		</div>
		<button class="primary" type="submit" disabled={splitting}>
			{splitting ? 'Splitting…' : mode === 'split' ? 'Split key' : 'Re-split key'}
		</button>
	</form>

	{#if splitWarnings.length}
		<div class="card at-risk" style="margin-top: 1rem">
			{#each splitWarnings as w (w)}<p>{w}</p>{/each}
		</div>
	{/if}

	{#if splitShares}
		<div class="card" style="margin-top: 1rem">
			<h3>Shares - send one to each trustee</h3>
			{#each splitShares as share, i (i)}
				<div class="share-row">
					<code class="mono share-text">{share}</code>
					<button type="button" onclick={() => copy(share, (v) => (sharesCopied = { ...sharesCopied, [i]: v }))}>
						{sharesCopied[i] ? 'Copied' : 'Copy'}
					</button>
				</div>
			{/each}
		</div>
	{/if}

	<h2 style="margin-top: 2rem">Add a trustee (extend)</h2>
	<form class="card" onsubmit={(e) => (e.preventDefault(), runExtend())}>
		<div class="row">
			<label for="ext-rsid">Recovery set id</label>
			<input id="ext-rsid" type="number" min="0" bind:value={extendRsid} style="width: 8rem" />
			<label for="ext-count">New trustees to add</label>
			<input id="ext-count" type="number" min="1" bind:value={extendCount} style="width: 6rem" />
			<label><input type="checkbox" bind:checked={extendOverCap} /> allow exceeding cap</label>
		</div>
		<button class="primary" type="submit" disabled={extending}>
			{extending ? 'Issuing…' : 'Issue new share(s)'}
		</button>
	</form>
	{#if extendShares}
		<div class="card" style="margin-top: 1rem">
			{#each extendShares as share, i (i)}
				<div class="share-row">
					<code class="mono share-text">{share}</code>
				</div>
			{/each}
		</div>
	{/if}

	<h2 style="margin-top: 2rem">Recovery ceremony</h2>
	<p class="muted" style="font-size: var(--step--1)">
		A ceremony is opened by a signed request a trustee receives out of band (from the person
		recovering, or the daemon that observed them). The recovery delay and required approvals are
		enforced by the daemon per the grant that authorized the ceremony; paste the pieces below as
		they arrive.
	</p>
	<div class="grid">
		<form class="card" onsubmit={(e) => (e.preventDefault(), runOpen())}>
			<h3>Open</h3>
			<label for="open-hex" class="muted">Recovery open (hex)</label>
			<input id="open-hex" bind:value={openHex} />
			<label for="grant-hex" class="muted">Share grant (hex)</label>
			<input id="grant-hex" bind:value={grantHex} />
			<button class="primary" type="submit" disabled={opening}>{opening ? 'Opening…' : 'Track ceremony'}</button>
			{#if openResult}
				<p class="mono">id {openResult.ceremony_id.slice(0, 12)}… · phase <strong>{openResult.phase}</strong></p>
			{/if}
		</form>

		<form class="card" onsubmit={(e) => (e.preventDefault(), runApprove())}>
			<h3>Approve</h3>
			<label for="approve-hex" class="muted">Ceremony approve (hex)</label>
			<input id="approve-hex" bind:value={approveHex} />
			<button class="primary" type="submit" disabled={approving}>{approving ? 'Recording…' : 'Record approval'}</button>
			{#if approveResult !== null}
				<p class="healthy">{approveResult} approval(s) recorded so far.</p>
			{/if}
		</form>

		<form class="card" onsubmit={(e) => (e.preventDefault(), runAbort())}>
			<h3>Abort</h3>
			<label for="abort-id" class="muted">Ceremony id (hex)</label>
			<input id="abort-id" bind:value={abortId} />
			<button type="submit" disabled={aborting}>{aborting ? 'Signing…' : 'Abort as subject'}</button>
			{#if abortHex}
				<p class="mono share-text">{abortHex}</p>
				<p class="muted" style="font-size: var(--step--1)">Send this abort to your trustees.</p>
			{/if}
		</form>
	</div>
</section>

<style>
	.row {
		display: flex;
		gap: 1rem;
		align-items: center;
		flex-wrap: wrap;
		margin-bottom: 0.75rem;
	}

	.row label {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		font-size: var(--step--1);
		color: var(--muted);
	}

	.list {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.set-row {
		display: flex;
		gap: 1.5rem;
	}

	.share-row {
		display: flex;
		gap: 0.6rem;
		align-items: center;
		margin-bottom: 0.5rem;
	}

	.share-text {
		flex: 1;
		word-break: break-all;
		background: var(--plate-raised);
		padding: 0.4em 0.6em;
		border-radius: 6px;
	}

	.grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
		gap: 1rem;
	}

	.grid label {
		display: block;
		font-size: var(--step--1);
		margin: 0.5rem 0 0.3rem;
	}

	.grid input {
		width: 100%;
		margin-bottom: 0.5rem;
	}
</style>
