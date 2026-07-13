<script lang="ts">
	import type { Plate } from '$lib/types';

	let { plates }: { plates: Plate[] } = $props();

	function segments(p: Plate): { filled: boolean }[] {
		const total = Math.max(p.target, p.achieved, 1);
		return Array.from({ length: total }, (_, i) => ({ filled: i < p.achieved }));
	}
</script>

<div class="shell" role="group" aria-label="Shell integrity">
	{#each plates as plate, i (plate.key)}
		<div class="plate-group state-{plate.state}" style="--i: {i}">
			<div class="segments" aria-hidden="true">
				{#each segments(plate) as seg, j (j)}
					<span class="segment" class:filled={seg.filled}></span>
				{/each}
			</div>
			<div class="label">{plate.label}</div>
			<div class="value mono">{plate.valueLabel}</div>
			<div class="note muted">{plate.note}</div>
		</div>
	{/each}
</div>

<style>
	.shell {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
		gap: 1.25rem;
	}

	.plate-group {
		background: var(--plate);
		border: 1px solid var(--hairline);
		border-radius: var(--radius);
		padding: 1.25rem;
		animation: reveal 420ms ease backwards;
		animation-delay: calc(var(--i) * 80ms);
	}

	@keyframes reveal {
		from {
			opacity: 0;
			transform: translateY(8px);
		}
		to {
			opacity: 1;
			transform: translateY(0);
		}
	}

	.segments {
		display: flex;
		margin-bottom: 0.9rem;
	}

	.segment {
		height: 34px;
		flex: 1;
		background: transparent;
		border: 2px solid var(--hairline);
		clip-path: polygon(14% 0, 100% 0, 86% 100%, 0 100%);
		margin-left: -10px;
	}

	.segment:first-child {
		margin-left: 0;
	}

	.state-healthy .segment.filled {
		background: var(--verdigris);
		border-color: var(--verdigris);
	}

	.state-at-risk .segment.filled {
		background: var(--coral);
		border-color: var(--coral);
	}

	.state-at-risk .segment:not(.filled) {
		border-color: var(--coral);
		border-style: dashed;
	}

	.state-empty .segment {
		border-style: dashed;
	}

	.label {
		font-size: var(--step--1);
		text-transform: uppercase;
		letter-spacing: 0.06em;
		color: var(--muted);
	}

	.value {
		font-size: var(--step-3);
		font-weight: 600;
		margin: 0.15em 0;
	}

	.state-healthy .value {
		color: var(--verdigris);
	}

	.state-at-risk .value {
		color: var(--coral);
	}

	.note {
		font-size: var(--step--1);
	}
</style>
