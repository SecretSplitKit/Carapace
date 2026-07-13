<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { startStatusFeed, stopStatusFeed, live } from '$lib/statusStore';
	import ErrorBanner from '$lib/components/ErrorBanner.svelte';
	import OverviewView from '$lib/components/OverviewView.svelte';
	import VaultsView from '$lib/components/VaultsView.svelte';
	import FriendsView from '$lib/components/FriendsView.svelte';
	import RecoveryView from '$lib/components/RecoveryView.svelte';
	import SharedView from '$lib/components/SharedView.svelte';

	const routes: Record<string, string> = {
		'': 'Overview',
		vaults: 'Vaults',
		friends: 'Friends',
		recovery: 'Recovery',
		shared: 'Shared files'
	};

	function currentRoute(): string {
		const h = typeof location !== 'undefined' ? location.hash.replace(/^#\/?/, '') : '';
		return h in routes ? h : '';
	}

	let route = $state(currentRoute());

	function onHashChange() {
		route = currentRoute();
	}

	type Theme = 'dark' | 'light' | null;
	let theme = $state<Theme>(null);

	function applyTheme(t: Theme) {
		if (t) document.documentElement.setAttribute('data-theme', t);
		else document.documentElement.removeAttribute('data-theme');
	}

	function toggleTheme() {
		const prefersLight =
			typeof matchMedia !== 'undefined' && matchMedia('(prefers-color-scheme: light)').matches;
		const currentlyLight = theme ? theme === 'light' : prefersLight;
		theme = currentlyLight ? 'dark' : 'light';
		localStorage.setItem('carapace-theme', theme);
		applyTheme(theme);
	}

	onMount(() => {
		window.addEventListener('hashchange', onHashChange);
		const saved = localStorage.getItem('carapace-theme');
		if (saved === 'dark' || saved === 'light') {
			theme = saved;
			applyTheme(theme);
		}
		startStatusFeed();
		return () => window.removeEventListener('hashchange', onHashChange);
	});

	onDestroy(() => {
		stopStatusFeed();
	});
</script>

<svelte:head>
	<title>Carapace</title>
</svelte:head>

<div class="app">
	<header>
		<div class="brand">
			<span class="mark" aria-hidden="true">◈</span>
			<span>Carapace</span>
		</div>
		<nav aria-label="Views">
			{#each Object.entries(routes) as [key, label] (key)}
				<a href={key ? `#/${key}` : '#/'} class:active={route === key}>{label}</a>
			{/each}
		</nav>
		<div class="status-and-theme">
			<span class="live-dot" class:live={$live} title={$live ? 'Live updates connected' : 'Reconnecting…'}
			></span>
			<button type="button" onclick={toggleTheme} aria-label="Toggle color theme">
				{theme === 'light' ? 'Molt (light)' : 'Dark'}
			</button>
		</div>
	</header>

	<main>
		<ErrorBanner />
		{#if route === 'vaults'}
			<VaultsView />
		{:else if route === 'friends'}
			<FriendsView />
		{:else if route === 'recovery'}
			<RecoveryView />
		{:else if route === 'shared'}
			<SharedView />
		{:else}
			<OverviewView />
		{/if}
	</main>
</div>

<style>
	.app {
		max-width: 960px;
		margin: 0 auto;
		padding: 1.5rem;
	}

	header {
		display: flex;
		align-items: center;
		gap: 1.5rem;
		flex-wrap: wrap;
		margin-bottom: 2rem;
		padding-bottom: 1rem;
		border-bottom: 1px solid var(--hairline);
	}

	.brand {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		font-weight: 700;
		font-size: var(--step-2);
	}

	.mark {
		color: var(--bronze);
	}

	nav {
		display: flex;
		gap: 0.25rem;
		flex-wrap: wrap;
		flex: 1;
	}

	nav a {
		color: var(--muted);
		text-decoration: none;
		padding: 0.4em 0.8em;
		border-radius: var(--radius);
		transition:
			color var(--transition),
			background var(--transition);
	}

	nav a:hover,
	nav a:focus-visible {
		color: var(--bone);
		background: var(--plate);
	}

	nav a.active {
		color: var(--bronze);
		background: var(--plate);
		font-weight: 600;
	}

	.status-and-theme {
		display: flex;
		align-items: center;
		gap: 0.75rem;
	}

	.live-dot {
		width: 10px;
		height: 10px;
		border-radius: 50%;
		background: var(--coral);
		display: inline-block;
	}

	.live-dot.live {
		background: var(--verdigris);
	}
</style>
