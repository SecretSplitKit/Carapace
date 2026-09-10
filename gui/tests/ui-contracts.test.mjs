import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const source = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

test('API calls use the authenticated same-origin request boundary', () => {
	const api = source('src/lib/api.ts');
	assert.match(api, /const BASE = ''/);
	assert.match(api, /Authorization: `Bearer \$\{apiToken\(\)\}`/);
	for (const endpoint of [
		"'/api/status'",
		"'/api/sync'",
		"'/api/vaults'",
		"'/api/friends'",
		"'/api/recovery/split'",
		"'/api/recovery/ceremony/open'",
		"'/api/recovery/ceremony/approve'",
		"'/api/recovery/ceremony/abort'"
	]) {
		assert.ok(api.includes(endpoint), `missing API contract ${endpoint}`);
	}
	assert.match(api, /res\.status === 401 \|\| res\.status === 403/);
});

test('the shell and alerts expose keyboard and accessibility semantics', () => {
	const page = source('src/routes/+page.svelte');
	const errorBanner = source('src/lib/components/ErrorBanner.svelte');
	const shellHero = source('src/lib/components/ShellHero.svelte');
	assert.match(page, /<nav aria-label="Views">/);
	assert.match(page, /<button type="button"[^>]+aria-label="Toggle color theme">/);
	assert.match(errorBanner, /role="alert"/);
	assert.match(errorBanner, /<button type="button"/);
	assert.match(shellHero, /role="group" aria-label="Shell integrity"/);

	for (const path of [
		'src/routes/+page.svelte',
		'src/lib/components/FriendsView.svelte',
		'src/lib/components/RecoveryView.svelte',
		'src/lib/components/SharedView.svelte',
		'src/lib/components/VaultsView.svelte'
	]) {
		const markup = source(path);
		const buttons = markup.match(/<button\b[^>]*>/g) ?? [];
		assert.ok(buttons.length > 0, `${path} must contain a keyboard-native action`);
		for (const button of buttons) {
			assert.match(button, /\btype="(?:button|submit)"/, `${path} has an implicit button type`);
		}
	}
});

test('primary views have an explicit narrow-screen layout', () => {
	for (const path of [
		'src/routes/+page.svelte',
		'src/lib/components/VaultsView.svelte',
		'src/lib/components/RecoveryView.svelte',
		'src/lib/components/SharedView.svelte'
	]) {
		assert.match(source(path), /@media \(max-width: 640px\)/, `${path} lacks its mobile contract`);
	}
	const css = source('src/app.css');
	assert.match(css, /@media \(prefers-reduced-motion: reduce\)/);
});

test('destructive actions need explicit confirmation state', () => {
	const friends = source('src/lib/components/FriendsView.svelte');
	assert.match(friends, /confirming === f/);
	assert.match(friends, /onclick=\{\(\) => \(confirming = f\)\}>Unfriend/);
	assert.match(friends, /class="danger"/);

	const recovery = source('src/lib/components/RecoveryView.svelte');
	assert.match(recovery, /I confirm that this ceremony must stop\./);
	assert.match(recovery, /disabled=\{aborting \|\| !abortId\.trim\(\) \|\| !abortConfirmed\}/);

	const shared = source('src/lib/components/SharedView.svelte');
	assert.match(shared, /bind:checked=\{grantConfirmed\}/);
	assert.match(shared, /!grantConfirmed/);
});

test('clipboard failure reports visible feedback and does not claim success', () => {
	const format = source('src/lib/format.ts');
	assert.match(format, /await navigator\.clipboard\.writeText\(text\)/);
	assert.match(format, /reportError\('Could not copy to the clipboard\./);
	assert.match(format, /catch \{[\s\S]*return false;/);
	assert.match(format, /await navigator[\s\S]*return true;/);
});

test('claimant shell stays on the claimant API boundary and guides safe restart', () => {
	const html = source('static/claimant.html');
	const script = source('static/claimant.js');
	assert.match(html, /Claimant mode/);
	assert.match(html, /Ceremony encryption key/);
	assert.match(html, /Public ceremony handoff package/);
	assert.match(html, /Signed RecoveryOpen frame/);
	assert.match(html, /owned-device sync/);
	assert.match(html, /Fetch and restore vault ciphertext/);
	assert.match(html, /guided re-split/);
	assert.match(script, /request\('\/api\/claimant\/status'\)/);
	assert.match(script, /request\('\/api\/claimant\/preview'/);
	assert.match(script, /request\('\/api\/claimant\/complete'/);
	assert.match(script, /request\('\/api\/claimant\/cancel'/);
	assert.match(html, /Verified sponsor ceremony package/);
	assert.match(script, /carapace\.sponsor-ceremony/);
	assert.match(script, /confirmed_subject: confirmedSubject/);
	assert.match(html, /I confirmed this subject identity through a trusted channel/);
	assert.doesNotMatch(script, /['"`]\/api\/(?:status|sync|vaults|friends|recovery\/split)/);
	for (const forbidden of ['k_root', 'node_seed', 'ceremony_private', 'share_json']) {
		assert.ok(!html.includes(forbidden) && !script.includes(forbidden), `claimant shell exposes ${forbidden}`);
	}
});

test('sponsor imports the versioned claimant handoff and keeps manual values advanced', () => {
	const recovery = source('src/lib/components/RecoveryView.svelte');
	assert.match(recovery, /value\.type !== 'carapace\.claimant-handoff'/);
	assert.match(recovery, /value\.version !== 1/);
	assert.match(recovery, /Import handoff package/);
	assert.match(recovery, /<details>[\s\S]*<summary>Advanced manual values<\/summary>/);
	assert.match(recovery, /ceremonyEnc = value\.ceremony_enc/);
	assert.match(recovery, /newNode = value\.new_node/);
});

test('recovery and friend safety facts come from daemon status, not browser notes', () => {
	const types = source('src/lib/types.ts');
	const overview = source('src/lib/components/OverviewView.svelte');
	const recovery = source('src/lib/components/RecoveryView.svelte');
	const friends = source('src/lib/components/FriendsView.svelte');
	assert.match(types, /sets: RecoverySetStatus\[\]/);
	assert.match(types, /grants: FriendGrant\[\]/);
	assert.match(recovery, /\$status\.share_health\.sets/);
	assert.match(overview, /s\.share_health\.sets/);
	assert.match(friends, /\$status\?\.friends\.grants/);
	for (const component of [overview, recovery, friends]) {
		assert.doesNotMatch(component, /localStorage|\$notes|noteRecoverySet|noteFriendGrant/);
	}
});

test('the GUI status contract matches the typed server fixture', () => {
	const fixture = JSON.parse(source('tests/fixtures/status-contract.json'));
	const types = source('src/lib/types.ts');
	for (const key of ['node_id', 'friends', 'peers', 'vaults', 'share_health', 'recovery_grants', 'ceremonies']) {
		assert.ok(Object.hasOwn(fixture, key), `server fixture is missing ${key}`);
	}
	assert.match(types, /peers: PeerOption\[\]/);
	assert.match(types, /name: string/);
	assert.match(types, /recovery: RecoveryHealth\[\]/);
});
