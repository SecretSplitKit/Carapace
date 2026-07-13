<script lang="ts">
	import { truncateHex, copyToClipboard } from '$lib/format';

	let { value, head = 8, tail = 6 }: { value: string; head?: number; tail?: number } = $props();
	let copied = $state(false);

	async function copy() {
		if (await copyToClipboard(value)) {
			copied = true;
			setTimeout(() => (copied = false), 1200);
		}
	}
</script>

<button type="button" class="hex mono" onclick={copy} title={value} aria-label="Copy {value}">
	{truncateHex(value, head, tail)}
	<span class="hint muted">{copied ? 'copied' : 'copy'}</span>
</button>

<style>
	.hex {
		background: none;
		border: none;
		padding: 0;
		display: inline-flex;
		align-items: baseline;
		gap: 0.5em;
		cursor: pointer;
		color: inherit;
	}

	.hex:hover .hint,
	.hex:focus-visible .hint {
		color: var(--bronze);
	}

	.hint {
		font-size: var(--step--1);
		font-family: var(--font-sans);
	}
</style>
