import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	// Emit fonts/assets as files (served from 'self'), never inline them as
	// data: URIs - the daemon's CSP is font-src 'self', which blocks data: fonts.
	build: { assetsInlineLimit: 0 },
	plugins: [
		sveltekit({
			compilerOptions: {
				// Force runes mode for the project, except for libraries. Can be removed in svelte 6.
				runes: ({ filename }) =>
					filename.split(/[/\\]/).includes('node_modules') ? undefined : true
			},

			// Fully static SPA: carapace-api serves this dir via rust-embed with an SPA
			// fallback, so there is no per-route prerendering, just one index.html shell.
			adapter: adapter({
				pages: '../crates/carapace-api/static',
				assets: '../crates/carapace-api/static',
				fallback: 'index.html',
				precompress: false,
				strict: true
			})
		})
	]
});
