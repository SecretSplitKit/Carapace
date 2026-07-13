<script lang="ts">
	import { lastError, clearError } from '$lib/errors';
</script>

{#if $lastError}
	<div class="banner" role="alert">
		<span>{$lastError}</span>
		<button type="button" onclick={clearError} aria-label="Dismiss">Dismiss</button>
	</div>
{/if}

<style>
	.banner {
		background: var(--plate);
		border: 1px solid var(--coral);
		color: var(--coral);
		border-radius: var(--radius);
		padding: 0.75rem 1rem;
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 1rem;
		margin-bottom: 1rem;
	}

	.banner button {
		background: transparent;
		border-color: var(--coral);
		color: var(--coral);
		flex-shrink: 0;
	}
</style>
