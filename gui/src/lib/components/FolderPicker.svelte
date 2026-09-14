<script lang="ts">
	import { api } from '$lib/api';
	let { value = $bindable(''), id = 'folder' } = $props<{value?:string;id?:string}>();
	let browsing = $state(false);
	let busy = $state(false);
	let listing = $state<{path:string;parent:string|null;directories:{name:string;path:string}[]} | null>(null);
	async function browse(path?: string) {
		browsing = true; busy = true;
		try { listing = await api.directories(path); }
		catch { /* shared error banner */ }
		finally { busy = false; }
	}
</script>
<div>
	<input {id} bind:value placeholder="Folder path" />
	<button type="button" onclick={() => browse(value || undefined)} disabled={busy}>Choose folder…</button>
	{#if browsing}
		<div class="card" role="group" aria-label="Choose a folder">
			{#if listing}
				<p>{listing.path}</p>
				{#if listing.parent}<button type="button" disabled={busy} onclick={() => browse(listing!.parent!)}>Parent folder</button>{/if}
				<ul>{#each listing.directories as dir (dir.path)}<li><button type="button" disabled={busy} onclick={() => browse(dir.path)}>{dir.name}</button></li>{/each}</ul>
				<button type="button" disabled={busy} onclick={() => { value = listing!.path; browsing = false; }}>Use this folder</button>
			{/if}
			<button type="button" onclick={() => browsing = false}>Cancel</button>
		</div>
	{/if}
</div>
<style>
	ul { max-height: 16rem; overflow: auto; list-style: none; padding: 0; }
	li { margin: 0.3rem 0; }
	input { min-width: min(25rem, 100%); }
</style>
