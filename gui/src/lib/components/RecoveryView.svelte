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

	let subject = $state('');
	let claimantDisplay = $state('');
	let ceremonyEnc = $state('');
	let newNode = $state('');
	let reason = $state('');
	let opening = $state(false);
	let openResult = $state<{ ceremony_id: string; open_hex: string; fanout_reached: number } | null>(
		null
	);

	let approveId = $state('');
	let approving = $state(false);
	let approveResult = $state<{ approve_hex: string; broadcast_reached: number } | null>(null);

	let abortId = $state('');
	let aborting = $state(false);
	let abortHex = $state<string | null>(null);

	function phaseLabel(phase: string): string {
		switch (phase) {
			case 'awaiting_new_set':
				return 'Standing up new set';
			case 'ready_to_destroy':
				return 'New set live - destroying old shares';
			case 'complete':
				return 'Complete';
			default:
				return phase;
		}
	}

	// §9.3.4 PROMPT: start a re-split the daemon detected on unfriend but hasn't begun.
	let starting = $state<number | null>(null);
	function onlineCount(suggested: { online: boolean }[]): number {
		return suggested.filter((t) => t.online).length;
	}
	async function startResplit(oldRsid: number) {
		starting = oldRsid;
		try {
			await api.resplitStart(oldRsid);
		} finally {
			starting = null;
		}
	}

	// W15 (§8, §10.2): fetch the printable paper cards for one owned recovery set and open
	// them in a new tab for printing. The HTML embeds the share WORDS (a bearer secret), so
	// it is opened in a standalone print view, never rendered inline in the app chrome.
	let printing = $state<number | null>(null);
	async function printPaperCards(rsid: number) {
		printing = rsid;
		try {
			const html = await api.paperCards(rsid);
			const url = URL.createObjectURL(new Blob([html], { type: 'text/html' }));
			window.open(url, '_blank', 'noopener');
			// Revoke after the new tab has had time to load the document.
			setTimeout(() => URL.revokeObjectURL(url), 60_000);
		} finally {
			printing = null;
		}
	}

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
			openResult = await api.ceremonyOpen({
				subject: subject.trim(),
				claimant_display: claimantDisplay.trim(),
				ceremony_enc: ceremonyEnc.trim(),
				new_node: newNode.trim(),
				reason: reason.trim()
			});
		} finally {
			opening = false;
		}
	}

	async function runApprove() {
		approving = true;
		approveResult = null;
		try {
			approveResult = await api.ceremonyApprove(approveId.trim());
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
	let openHexCopied = $state(false);
	let approveHexCopied = $state(false);
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

	{#if $status?.recovery_grants?.minted?.length}
		<h2 style="margin-top: 1.5rem">Paper cards (offline backstop)</h2>
		<p class="muted" style="font-size: var(--step--1)">
			Print a paper card for each recovery set (§8, §10.2). A card recovers from its words
			alone - offline, with no Carapace software - so it is the backstop that never goes
			offline. The card shows a share's secret words; print it, then keep or destroy the copy.
		</p>
		<div class="list">
			{#each $status.recovery_grants.minted as g (g.rsid)}
				<div class="card set-row">
					<span class="mono">rsid {g.rsid}</span>
					<span class="muted">{g.trustees.length} share(s)</span>
					<button
						type="button"
						disabled={printing === g.rsid}
						onclick={() => printPaperCards(g.rsid)}
					>
						{printing === g.rsid ? 'Opening…' : 'Print / export paper cards'}
					</button>
				</div>
			{/each}
		</div>
	{/if}

	{#if $status?.pending_resplits?.length}
		<h2 style="margin-top: 1.5rem">Re-split required</h2>
		<p class="muted" style="font-size: var(--step--1)">
			An unfriended trustee still held a share of the recovery set below (§9.3.4). Start the
			re-split to hand a fresh share to a new trustee set - the old shares are only destroyed
			once that new set is live.
		</p>
		{#each $status.pending_resplits as pr (pr.old_rsid)}
			<div class="card resplit" style="margin-top: 1rem">
				<div class="resplit-head">
					<span class="mono">rsid {pr.old_rsid}</span>
					<span class="phase required">re-split required</span>
				</div>
				<p class="muted" style="font-size: var(--step--1)">
					<code class="mono">{pr.ex_trustee.slice(0, 12)}…</code> was a trustee of this recovery set and
					was unfriended. Their retained share must be neutralized by re-splitting to a fresh set.
				</p>

				<div class="label muted" style="margin-top: 0.75rem">
					Suggested new trustee set - live reachability
				</div>
				<div class="reach">
					{#each pr.suggested as t (t.user)}
						<div class="reach-row">
							<span class="dot {t.online ? 'online' : 'offline'}" title={t.online ? 'online' : 'offline'}
							></span>
							<code class="mono">{t.user.slice(0, 12)}…</code>
							<span class="muted">{t.online ? 'online' : 'offline'}</span>
						</div>
					{/each}
				</div>

				<p
					class={onlineCount(pr.suggested) === pr.suggested.length && pr.suggested.length > 0
						? 'healthy'
						: 'muted'}
					style="font-size: var(--step--1); margin-top: 0.5rem"
				>
					{onlineCount(pr.suggested)} / {pr.suggested.length} suggested trustee(s) online -
					{#if onlineCount(pr.suggested) === pr.suggested.length && pr.suggested.length > 0}
						will complete immediately once started.
					{:else}
						will complete progressively as offline trustees come online.
					{/if}
				</p>

				<button
					class="primary"
					type="button"
					style="margin-top: 0.75rem"
					disabled={starting === pr.old_rsid}
					onclick={() => startResplit(pr.old_rsid)}
				>
					{starting === pr.old_rsid ? 'Starting…' : 'Start re-split (use suggested set)'}
				</button>
			</div>
		{/each}
	{/if}

	{#if $status?.resplits?.length}
		<h2 style="margin-top: 1.5rem">Trustee re-splits in progress</h2>
		<p class="muted" style="font-size: var(--step--1)">
			An unfriended trustee's share is being neutralized (§9.3 step 4). Both the old and new
			recovery sets stay usable until the new set is live <em>and</em> the old shares are destroyed -
			neither door closes early.
		</p>
		{#each $status.resplits as rs (rs.old_rsid)}
			<div class="card resplit" style="margin-top: 1rem">
				<div class="resplit-head">
					<span class="mono">rsid {rs.old_rsid} → {rs.new_rsid}</span>
					<span class="phase {rs.phase}">{phaseLabel(rs.phase)}</span>
				</div>
				<p class="muted" style="font-size: var(--step--1)">
					ex-trustee {rs.ex_trustee.slice(0, 12)}…
				</p>

				<div class="gauges">
					<div>
						<div class="label muted">New set attested (destroy gate: M + slack)</div>
						<p class="mono">
							{rs.new_attested} / {rs.new_total}
							{#if rs.new_set_live}<span class="healthy">· live</span>{:else}<span class="at-risk">· not live yet</span>{/if}
						</p>
					</div>
					<div>
						<div class="label muted">Old shares destroyed (ack)</div>
						<p class="mono">
							{rs.old_destroyed} / {rs.old_total}
							{#if !rs.new_set_live}<span class="muted">· destroy refused until new set is live</span>{/if}
						</p>
					</div>
				</div>

				<div class="label muted" style="margin-top: 0.75rem">Remaining friends - live reachability</div>
				<div class="reach">
					{#each rs.remaining as fr (fr.node)}
						<div class="reach-row">
							<span class="dot {fr.status}" title={fr.status}></span>
							<code class="mono">{fr.node.slice(0, 12)}…</code>
							<span class="role {fr.role}">{fr.role === 'new' ? 'gets new share' : 'gets destroy step'}</span>
							<span class="muted">
								{#if fr.done}done{:else if fr.online}online - {fr.role === 'new' ? 'sending share' : 'sending destroy'}{:else}offline - queued{/if}
							</span>
						</div>
					{/each}
				</div>
			</div>
		{/each}
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
			<h3>Open (sponsor)</h3>
			<label for="c-subject" class="muted">Subject user pubkey (hex) - you must hold their grant</label>
			<input id="c-subject" bind:value={subject} />
			<label for="c-display" class="muted">Claimant display name</label>
			<input id="c-display" bind:value={claimantDisplay} />
			<label for="c-enc" class="muted">Claimant ceremony pubkey (hex X25519)</label>
			<input id="c-enc" bind:value={ceremonyEnc} />
			<label for="c-node" class="muted">Claimant new device node id (hex)</label>
			<input id="c-node" bind:value={newNode} />
			<label for="c-reason" class="muted">Reason</label>
			<input id="c-reason" bind:value={reason} />
			<button class="primary" type="submit" disabled={opening}>{opening ? 'Opening…' : 'Open ceremony'}</button>
			{#if openResult}
				<p class="mono">id {openResult.ceremony_id.slice(0, 12)}… · fanned out to {openResult.fanout_reached} peer(s)</p>
				<div class="label muted">Signed open - hand to the claimant</div>
				<div class="share-row">
					<code class="mono share-text">{openResult.open_hex}</code>
					<button type="button" onclick={() => copy(openResult!.open_hex, (v) => (openHexCopied = v))}>
						{openHexCopied ? 'Copied' : 'Copy'}
					</button>
				</div>
			{/if}
		</form>

		<form class="card" onsubmit={(e) => (e.preventDefault(), runApprove())}>
			<h3>Approve</h3>
			<label for="approve-id" class="muted">Ceremony id (hex)</label>
			<input id="approve-id" bind:value={approveId} />
			<button class="primary" type="submit" disabled={approving}>{approving ? 'Recording…' : 'Record approval'}</button>
			{#if approveResult}
				<p class="healthy">Approval broadcast to {approveResult.broadcast_reached} co-trustee(s).</p>
				<div class="share-row">
					<code class="mono share-text">{approveResult.approve_hex}</code>
					<button type="button" onclick={() => copy(approveResult!.approve_hex, (v) => (approveHexCopied = v))}>
						{approveHexCopied ? 'Copied' : 'Copy'}
					</button>
				</div>
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

	.resplit-head {
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 1rem;
		flex-wrap: wrap;
	}

	.phase {
		font-size: var(--step--1);
		padding: 0.2em 0.6em;
		border-radius: 999px;
		border: 1px solid var(--hairline);
	}

	.phase.complete {
		color: var(--verdigris);
		border-color: var(--verdigris);
	}

	.phase.ready_to_destroy {
		color: var(--bronze-strong);
		border-color: var(--bronze);
	}

	.phase.required {
		color: var(--coral);
		border-color: var(--coral);
	}

	.gauges {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
		gap: 1rem;
		margin-top: 0.75rem;
	}

	.reach {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
		margin-top: 0.4rem;
	}

	.reach-row {
		display: flex;
		align-items: center;
		gap: 0.6rem;
		flex-wrap: wrap;
	}

	.dot {
		width: 0.6rem;
		height: 0.6rem;
		border-radius: 50%;
		flex: none;
		background: var(--muted);
	}

	.dot.done {
		background: var(--verdigris);
	}

	.dot.online {
		background: var(--bronze);
	}

	.dot.will_queue,
	.dot.offline {
		background: var(--muted);
	}

	.role {
		font-size: var(--step--1);
		color: var(--muted);
	}
</style>
