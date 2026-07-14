<script lang="ts">
	import { status } from '$lib/statusStore';
	import { notes } from '$lib/notes';
	import { api } from '$lib/api';
	import ShellHero from './ShellHero.svelte';
	import CopyHex from './CopyHex.svelte';
	import type { Plate } from '$lib/types';

	const REPLICA_TARGET = 3;
	const RELAY_TARGET = 2;

	let minReplicas = $state<number | null>(null);

	// Worst-case replica count across every published vault (the shell is only as
	// intact as its weakest vault).
	$effect(() => {
		const vaults = $status?.vaults.published ?? [];
		if (vaults.length === 0) {
			minReplicas = null;
			return;
		}
		Promise.all(vaults.map((v) => api.listReplicas(v.vid).catch(() => ({ members: [] }))))
			.then((results) => {
				minReplicas = Math.min(...results.map((r) => r.members.length));
			})
			.catch(() => {
				minReplicas = null;
			});
	});

	let plates: Plate[] = $derived.by(() => {
		const s = $status;
		if (!s) return [];

		const vaultCount = s.vaults.published.length;
		const replicaAchieved = minReplicas ?? 0;
		const replicasPlate: Plate = {
			key: 'replicas',
			label: 'Replicas',
			achieved: vaultCount === 0 ? 0 : Math.min(replicaAchieved, REPLICA_TARGET),
			target: REPLICA_TARGET,
			valueLabel: vaultCount === 0 ? '—' : `${replicaAchieved}/${REPLICA_TARGET}`,
			state: vaultCount === 0 ? 'empty' : replicaAchieved >= REPLICA_TARGET ? 'healthy' : 'at-risk',
			note:
				vaultCount === 0
					? 'No vaults published yet'
					: `Weakest vault held by ${replicaAchieved} friend${replicaAchieved === 1 ? '' : 's'}`
		};

		const setsOwned = s.share_health.recovery_sets_owned;
		const rootSet = Object.values($notes.recoverySets).find((n) => n.scope.kind === 'root');
		const sharesPlate: Plate = {
			key: 'shares',
			label: 'Recovery shares',
			achieved: setsOwned > 0 ? 1 : 0,
			target: 1,
			valueLabel: rootSet ? `${rootSet.m}-of-${rootSet.n}` : setsOwned > 0 ? 'split' : '—',
			state: setsOwned > 0 ? 'healthy' : 'empty',
			note:
				setsOwned > 0
					? `${s.share_health.shares_held} share${s.share_health.shares_held === 1 ? '' : 's'} held here in trust for others`
					: 'Your key has no trustees yet - nobody could rebuild it'
		};

		const addrs = s.addr.length;
		const relayNetworks = s.relay_networks;
		const atRisk = s.relay_diversity_warning || relayNetworks < RELAY_TARGET;
		const relaysPlate: Plate = {
			key: 'relays',
			label: 'Reachability',
			achieved: Math.min(relayNetworks, RELAY_TARGET),
			target: RELAY_TARGET,
			valueLabel: `${relayNetworks}`,
			state: addrs === 0 ? 'empty' : atRisk ? 'at-risk' : 'healthy',
			note: atRisk
				? `Only ${relayNetworks} relay network${relayNetworks === 1 ? '' : 's'} - add a friend's relay so you can still be reached if one drops`
				: `${s.reachability} · ${relayNetworks} relay networks, ${addrs} dialable address${addrs === 1 ? '' : 'es'}`
		};

		return [replicasPlate, sharesPlate, relaysPlate];
	});
</script>

<section>
	<h1>Shell integrity</h1>
	{#if $status}
		<ShellHero {plates} />

		<div class="node card">
			<div>
				<div class="label muted">This node</div>
				<CopyHex value={$status.node_id} head={12} tail={8} />
			</div>
			<div>
				<div class="label muted">Friends storing your vaults</div>
				<div class="mono">{$status.friends.count}</div>
			</div>
			<div>
				<div class="label muted">Vaults published</div>
				<div class="mono">{$status.vaults.published.length}</div>
			</div>
		</div>

		<div class="actions">
			<a class="button-link" href="#/vaults">Publish a vault</a>
			<a class="button-link" href="#/friends">Add a friend</a>
			<a class="button-link" href="#/recovery">Split your key</a>
		</div>
	{:else}
		<p class="muted">Waiting for the daemon…</p>
	{/if}
</section>

<style>
	.node {
		display: flex;
		flex-wrap: wrap;
		gap: 2rem;
		margin: 1.5rem 0;
	}

	.label {
		font-size: var(--step--1);
		text-transform: uppercase;
		letter-spacing: 0.06em;
		margin-bottom: 0.3em;
	}

	.actions {
		display: flex;
		gap: 0.75rem;
		flex-wrap: wrap;
	}

	.button-link {
		background: var(--plate-raised);
		border: 1px solid var(--hairline);
		color: var(--bone);
		border-radius: var(--radius);
		padding: 0.55em 1em;
		text-decoration: none;
		transition: border-color var(--transition);
	}

	.button-link:hover,
	.button-link:focus-visible {
		border-color: var(--bronze);
	}
</style>
