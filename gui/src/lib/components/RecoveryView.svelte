<script lang="ts">
	import { api } from '$lib/api';
	import { status } from '$lib/statusStore';
	import { copyToClipboard } from '$lib/format';
	import CopyHex from './CopyHex.svelte';

	let mode = $state<'split' | 'resplit'>('split');
	let rsid = $state(1);
	let manualSetId = $state(false);
	let scopeKind = $state<'root' | 'vault'>('root');
	let scopeVid = $state('');
	let m = $state(2);
	let n = $state(3);
	let deliveryMode = $state<'friends' | 'manual'>('friends');
	let selectedTrustees = $state<string[]>([]);
	let allowOverCap = $state(false);
	let splitting = $state(false);
	let splitShares = $state<string[] | null>(null);
	let splitWarnings = $state<string[]>([]);
	let deliveryResult = $state<{ delivered: string[]; undelivered: string[] } | null>(null);
	let nextRsid = $derived(Math.max(0, ...($status?.share_health.sets.map((set) => set.rsid) ?? [])) + 1);

	let extendRsid = $state(1);
	let extendCount = $state(1);
	let extendOverCap = $state(false);
	let extending = $state(false);
	let extendShares = $state<string[] | null>(null);

	let subject = $state('');
	let claimantDisplay = $state('');
	let claimantHandoff = $state('');
	let handoffError = $state('');
	let ceremonyEnc = $state('');
	let newNode = $state('');
	let reason = $state('');
	let opening = $state(false);
	let openResult = $state<{ ceremony_id: string; open_hex: string; fanout_reached: number; sponsor_package: string } | null>(
		null
	);

	function importClaimantHandoff() {
		handoffError = '';
		try {
			const value = JSON.parse(claimantHandoff) as Record<string, unknown>;
			if (
				value.type !== 'carapace.claimant-handoff' ||
				value.version !== 1 ||
				typeof value.ceremony_enc !== 'string' ||
				typeof value.new_node !== 'string' ||
				!/^[0-9a-f]{64}$/i.test(value.ceremony_enc) ||
				!/^[0-9a-f]{64}$/i.test(value.new_node)
			) {
				throw new Error('Package type, version, or public values are invalid.');
			}
			ceremonyEnc = value.ceremony_enc;
			newNode = value.new_node;
		} catch (error) {
			handoffError = error instanceof Error ? error.message : 'The handoff package is invalid.';
		}
	}

	let approveId = $state('');
	let approving = $state(false);
	let approveResult = $state<{ approve_hex: string; broadcast_reached: number } | null>(null);

	let abortId = $state('');
	let abortConfirmed = $state(false);
	let aborting = $state(false);
	let abortHex = $state<string | null>(null);
	let restartOutDir = $state('');
	let restartRestoring = $state(false);
	let restartResult = $state<{ restored: number; refs: number } | null>(null);

	async function runRestartRestore() {
		restartRestoring = true;
		try {
			const result = await api.restartRestore(restartOutDir.trim());
			restartResult = { restored: result.restored.length, refs: result.maximum_epoch_refs };
		} finally {
			restartRestoring = false;
		}
	}

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

	function friendLabel(user: string): string {
		return $status?.peers.find((peer) => peer.user === user)?.display || `Friend ${user.slice(0, 10)}…`;
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
		deliveryResult = null;
		try {
			const scope = scopeKind === 'root' ? ({ kind: 'root' } as const) : ({ kind: 'vault', vid: scopeVid.trim() } as const);
			if (deliveryMode === 'friends') {
				const fn = mode === 'split' ? api.recoverySplitToTrustees : api.recoveryResplitToTrustees;
				const res = await fn(mode === 'split' && !manualSetId ? nextRsid : rsid, scope, m, selectedTrustees, allowOverCap);
				deliveryResult = { delivered: res.delivered, undelivered: res.undelivered };
				splitWarnings = res.warnings;
			} else {
				const fn = mode === 'split' ? api.recoverySplit : api.recoveryResplit;
				const res = await fn(mode === 'split' && !manualSetId ? nextRsid : rsid, scope, m, n, allowOverCap);
				splitShares = res.shares;
				splitWarnings = res.warnings;
			}
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

	function selectApproval(ceremonyId: string) {
		approveId = ceremonyId;
		document.getElementById('approve-id')?.focus();
	}

	function selectAbort(ceremonyId: string) {
		abortId = ceremonyId;
		abortConfirmed = false;
		document.getElementById('abort-id')?.focus();
	}
</script>

<section>
	<h1>Recovery &amp; trustees</h1>
	<p class="muted">
		Split your key into pieces so a group of trustees can rebuild it if you lose access.
		The normal flow sends a signed recovery grant to each selected friend and tracks delivery.
		The advanced manual flow shows bearer shares that you must protect and deliver yourself.
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

	<details class="card" style="margin-top: 1rem">
		<summary>Restore retained vaults after identity recovery</summary>
		<p class="dependency">Discovery-dependent operation · it is safe to retry after a network failure</p>
		<p class="muted">Use the public restart handoff saved by claimant activation. Carapace contacts the verified trustee hints and accepts only the maximum announced epoch for each vault.</p>
		<form onsubmit={(event) => (event.preventDefault(), runRestartRestore())}>
			<label for="restart-out" class="muted">Restore directory</label>
			<input id="restart-out" bind:value={restartOutDir} />
			<button class="primary" type="submit" disabled={restartRestoring || !restartOutDir.trim()}>{restartRestoring ? 'Restoring…' : 'Discover and restore retained vaults'}</button>
		</form>
		<div aria-live="polite">{#if restartRestoring}<p>Restore is in progress.</p>{:else if restartResult}<p class="healthy">Restored {restartResult.restored} vault(s) from {restartResult.refs} maximum-epoch reference(s).</p>{/if}</div>
	</details>

	{#if $status?.ceremonies?.length}
		<h2 style="margin-top: 1.5rem">Active recovery ceremonies</h2>
		<p class="muted" style="font-size: var(--step--1)">
			Review the claimant and reason out of band before you approve a ceremony. Abort any ceremony
			against your identity that you did not start.
		</p>
		<div class="list">
			{#each $status.ceremonies as ceremony (ceremony.ceremony_id)}
				<div class="card ceremony" class:alarm={ceremony.alarm}>
					<div class="resplit-head">
						<div>
							<strong>{ceremony.claimant_display || 'Unnamed claimant'}</strong>
							<div class="mono muted">{ceremony.ceremony_id}</div>
						</div>
						<span class="phase">{ceremony.phase}</span>
					</div>
					{#if ceremony.alarm}
						<p class="alarm-text" role="alert">Recovery request for your identity. Abort it now if you did not start it.</p>
					{/if}
					<dl>
						<div><dt>Reason</dt><dd>{ceremony.reason || 'No reason supplied'}</dd></div>
						<div><dt>Approvals</dt><dd>{ceremony.approvals} / {ceremony.threshold}</dd></div>
						<div><dt>Sponsor</dt><dd class="mono">{ceremony.sponsor}</dd></div>
					</dl>
			<div class="row">
						{#if ceremony.trustee && !ceremony.approved}
							<button class="primary" type="button" onclick={() => selectApproval(ceremony.ceremony_id)}>Review and approve</button>
						{/if}
						{#if ceremony.is_self_subject && !ceremony.takeover}
							<button class="danger" type="button" onclick={() => selectAbort(ceremony.ceremony_id)}>Abort this ceremony</button>
						{/if}
					</div>
				</div>
			{/each}
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

	{#if $status?.share_health.sets.length}
		<h2 style="margin-top: 1.5rem">Authoritative recovery sets</h2>
		<div class="list">
			{#each $status.share_health.sets as rs (rs.rsid)}
				<div class="card set-row">
					<span class="mono">rsid {rs.rsid}</span>
					<span>{rs.scope.kind === 'root' ? 'your root key' : `vault ${rs.scope.vid.slice(0, 10)}…`}</span>
					<span class="mono">{rs.threshold}-of-{rs.issued}</span>
					<span>{rs.trustees.filter((trustee) => trustee.delivered).length}/{rs.trustees.length} trustee grants delivered</span>
					{#if rs.warnings.length}<span class="alarm-text">{rs.warnings.join(', ')}</span>{/if}
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
		{#if mode === 'split'}
			<p class="muted">Carapace will create recovery set {nextRsid}.</p>
			<details><summary>Advanced recovery-set id</summary><label><input type="checkbox" bind:checked={manualSetId} /> Use a manual id</label>{#if manualSetId}<input aria-label="Manual recovery set id" type="number" min="0" bind:value={rsid} />{/if}</details>
		{:else}
			<label for="rsid">Recovery set to replace</label>
			<select id="rsid" bind:value={rsid}>
				{#each $status?.share_health.sets ?? [] as set (set.rsid)}<option value={set.rsid}>{set.scope.kind === 'root' ? 'Identity recovery' : 'Vault recovery'} · {set.threshold}-of-{set.issued}</option>{/each}
			</select>
		{/if}
		<div class="row">
			<label>
				<input type="radio" bind:group={scopeKind} value="root" /> Your whole identity (root key)
			</label>
			<label>
				<input type="radio" bind:group={scopeKind} value="vault" /> One vault
			</label>
			{#if scopeKind === 'vault'}
				<select aria-label="Vault to protect" bind:value={scopeVid}>
					<option value="" disabled>Select a vault</option>
					{#each $status?.vaults.published ?? [] as vault (vault.vid)}<option value={vault.vid}>{vault.name}</option>{/each}
				</select>
			{/if}
			</div>
			<fieldset>
				<legend>Share delivery</legend>
				<label>
					<input type="radio" bind:group={deliveryMode} value="friends" /> Deliver verified shares to friends
				</label>
				<label>
					<input type="radio" bind:group={deliveryMode} value="manual" /> Advanced manual shares
				</label>
			</fieldset>
			{#if deliveryMode === 'friends'}
				<fieldset>
					<legend>Select trustees ({selectedTrustees.length} selected)</legend>
					{#if !$status?.friends.list.length}
						<p class="muted">Add friends before you create recovery protection.</p>
					{:else}
						<div class="trustee-list">
							{#each $status.friends.list as friend (friend)}
								<label title={friend}>
									<input type="checkbox" bind:group={selectedTrustees} value={friend} />
									<span>{friendLabel(friend)}</span>
								</label>
							{/each}
						</div>
					{/if}
				</fieldset>
			{/if}
			<div class="row">
				<label for="m">Trustees needed (M)</label>
				<input id="m" type="number" min="1" bind:value={m} style="width: 5rem" />
				{#if deliveryMode === 'manual'}
					<label for="n">Trustees total (N)</label>
					<input id="n" type="number" min="1" bind:value={n} style="width: 5rem" />
				{:else}
					<span class="muted">of {selectedTrustees.length} selected</span>
				{/if}
		</div>
		<div class="row">
			<label><input type="checkbox" bind:checked={allowOverCap} /> allow exceeding the recommended trustee cap</label>
		</div>
			<button class="primary" type="submit" disabled={splitting || (deliveryMode === 'friends' && (selectedTrustees.length === 0 || m > selectedTrustees.length))}>
			{splitting ? 'Splitting…' : mode === 'split' ? 'Split key' : 'Re-split key'}
		</button>
		</form>

		{#if deliveryResult}
			<div class="card" class:at-risk={deliveryResult.undelivered.length > 0} style="margin-top: 1rem">
				<h3>Verified share delivery</h3>
				<p>{deliveryResult.delivered.length} trustee(s) confirmed that they stored a signed recovery grant.</p>
				{#if deliveryResult.undelivered.length}
					<p>Could not reach {deliveryResult.undelivered.length} trustee(s). Carapace will retry delivery during maintenance.</p>
					<ul>{#each deliveryResult.undelivered as trustee (trustee)}<li class="mono">{trustee}</li>{/each}</ul>
				{:else}
					<p class="healthy">All selected trustees received their shares.</p>
				{/if}
			</div>
		{/if}

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
	<p class="dependency">Peer-dependent operation · offline delivery stays queued and is safe to retry</p>
	<form class="card" onsubmit={(e) => (e.preventDefault(), runExtend())}>
		<div class="row">
			<label for="ext-rsid">Recovery set</label>
			<select id="ext-rsid" bind:value={extendRsid}>{#each $status?.share_health.sets ?? [] as set (set.rsid)}<option value={set.rsid}>{set.scope.kind === 'root' ? 'Identity recovery' : 'Vault recovery'} · {set.threshold}-of-{set.issued}</option>{/each}</select>
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
			<p class="muted" style="font-size: var(--step--1)">
				Use the recovery request from the claimant. Confirm their identity and new device through
				a separate trusted channel before you open the ceremony.
			</p>
			<label for="c-subject" class="muted">Person to recover</label>
			<select id="c-subject" bind:value={subject}>
				<option value="" disabled>choose a person whose grant you hold</option>
				{#each $status?.recovery_grants.held ?? [] as heldSubject (heldSubject)}
					<option value={heldSubject}>{friendLabel(heldSubject)}</option>
				{/each}
			</select>
			{#if !$status?.recovery_grants.held.length}
				<p class="muted" style="font-size: var(--step--1)">
					This device does not hold a recovery grant. It cannot sponsor a ceremony.
				</p>
			{/if}
			<label for="c-display" class="muted">Claimant display name</label>
			<input id="c-display" bind:value={claimantDisplay} />
			<label for="c-handoff" class="muted">Claimant public handoff package</label>
			<textarea id="c-handoff" bind:value={claimantHandoff} rows="5"></textarea>
			<button type="button" onclick={importClaimantHandoff}>Import handoff package</button>
			{#if handoffError}<p role="alert" class="alarm-text">{handoffError}</p>{/if}
			<details>
				<summary>Advanced manual values</summary>
				<label for="c-enc" class="muted">Claimant ceremony pubkey (hex X25519)</label>
				<input id="c-enc" bind:value={ceremonyEnc} />
				<label for="c-node" class="muted">Claimant new device node id (hex)</label>
				<input id="c-node" bind:value={newNode} />
			</details>
			<label for="c-reason" class="muted">Reason</label>
			<input id="c-reason" bind:value={reason} />
			<button
				class="primary"
				type="submit"
				disabled={opening || !subject || !claimantDisplay.trim() || !ceremonyEnc.trim() || !newNode.trim() || !reason.trim()}
			>
				{opening ? 'Opening…' : 'Open ceremony'}
			</button>
			{#if openResult}
				<p class="mono">id {openResult.ceremony_id.slice(0, 12)}… · fanned out to {openResult.fanout_reached} peer(s)</p>
				<div class="label muted">Verified sponsor ceremony package - hand to the claimant</div>
				<div class="share-row">
					<code class="mono share-text">{openResult.sponsor_package}</code>
					<button type="button" onclick={() => copy(openResult!.sponsor_package, (v) => (openHexCopied = v))}>
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
				<label class="confirm-action">
					<input type="checkbox" bind:checked={abortConfirmed} />
					I confirm that this ceremony must stop.
				</label>
				<button class="danger" type="submit" disabled={aborting || !abortId.trim() || !abortConfirmed}>{aborting ? 'Signing…' : 'Abort as subject'}</button>
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

	fieldset {
		border: 1px solid var(--hairline);
		border-radius: var(--radius);
		margin: 0 0 0.75rem;
		padding: 0.75rem;
	}

	fieldset > label,
	.trustee-list label {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		margin: 0.35rem 0;
	}

	legend {
		font-weight: 600;
	}

	.trustee-list {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
		gap: 0 1rem;
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

	.grid select {
		width: 100%;
		margin-bottom: 0.5rem;
	}

	.ceremony.alarm {
		border-color: var(--coral);
	}

	.alarm-text {
		color: var(--coral);
		font-weight: 600;
	}

	dl {
		display: grid;
		gap: 0.5rem;
	}

	dl div {
		display: grid;
		grid-template-columns: minmax(6rem, 0.25fr) 1fr;
		gap: 0.75rem;
	}

	dt {
		color: var(--muted);
	}

	dd {
		margin: 0;
		min-width: 0;
		overflow-wrap: anywhere;
	}

	button.danger {
		border-color: var(--coral);
		color: var(--coral);
	}

	.confirm-action {
		display: flex !important;
		align-items: center;
		gap: 0.5rem;
	}

	.confirm-action input {
		width: auto;
		margin: 0;
	}

	@media (max-width: 640px) {
		.share-row,
		.set-row {
			align-items: stretch;
			flex-direction: column;
		}

		dl div {
			grid-template-columns: 1fr;
			gap: 0.1rem;
		}
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
