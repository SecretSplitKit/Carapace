import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

const user = 'a'.repeat(64);
const status = {
	node_id: 'b'.repeat(64),
	addr: ['127.0.0.1:9999'],
	friends: { count: 1, list: [user], grants: [{ user, grant_bytes: 1073741824 }] },
	peers: [{ user, display: 'Alex', node: 'b'.repeat(64), addrs: ['127.0.0.1:9999'] }],
	vaults: { published: [], held_replicas: [] },
	share_health: { recovery_sets_owned: 0, shares_held: 0, sets: [], recovery: [] },
	recovery_grants: { minted: [], held: [] },
	ceremonies: [],
	resplits: [],
	pending_resplits: [],
	reachability: 'local',
	relay_networks: 0,
	relay_diversity_warning: false
};

async function mockDaemon(page: Page) {
	await page.route('**/api/**', async (route) => {
		const path = new URL(route.request().url()).pathname;
		if (path === '/api/status') return route.fulfill({ json: status });
		if (path === '/api/friends' && route.request().method() === 'GET') {
			return route.fulfill({ json: { count: 1, list: [user] } });
		}
		if (path === `/api/friends/${user}/unfriend`) {
			return route.fulfill({ json: { was_friend: true, resplit_triggered: false, recovery_set_ids: [] } });
		}
		return route.fulfill({ status: 404, json: { code: 'not_found', error: 'not found' } });
	});
}

test.beforeEach(async ({ page }) => mockDaemon(page));

test('keyboard navigation, destructive confirmation, and accessibility work', async ({ page }) => {
	await page.goto('/#/friends');
	await expect(page.getByRole('heading', { name: 'Friends', exact: true })).toBeVisible();
	await page.keyboard.press('Tab');
	await expect(page.locator(':focus')).toBeVisible();
	await page.getByRole('button', { name: 'Unfriend' }).click();
	await expect(page.getByRole('button', { name: 'Confirm unfriend' })).toBeVisible();
	await page.getByRole('button', { name: 'Cancel' }).click();
	await expect(page.getByRole('button', { name: 'Confirm unfriend' })).toHaveCount(0);
	const results = await new AxeBuilder({ page }).analyze();
	expect(results.violations).toEqual([]);
});

test('the narrow viewport has no horizontal overflow and keeps focus visible', async ({ page }) => {
	await page.goto('/#/recovery');
	const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
	expect(overflow).toBeLessThanOrEqual(1);
	const focusTarget = page.getByRole('link', { name: 'Recovery' });
	await focusTarget.focus();
	await expect(focusTarget).toBeFocused();
	const focusBox = await focusTarget.boundingBox();
	expect(focusBox).not.toBeNull();
	expect(focusBox!.x).toBeGreaterThanOrEqual(0);
	expect(focusBox!.x + focusBox!.width).toBeLessThanOrEqual(await page.evaluate(() => innerWidth));
});

test('changing operation status is announced in a live region', async ({ page }) => {
	await page.route('**/api/sync', async (route) => {
		await new Promise((resolve) => setTimeout(resolve, 150));
		await route.fulfill({ json: { restored: [] } });
	});
	await page.goto('/#/vaults');
	await page.locator('#sync-peer').selectOption('b'.repeat(64));
	await page.locator('#sync-out').fill('/tmp/restore');
	await page.getByRole('button', { name: 'Sync and restore' }).click();
	const live = page.locator('[aria-live="polite"]').filter({ hasText: 'Sync' });
	await expect(live).toContainText('Sync is in progress.');
	await expect(live).toContainText('There were no new vault versions to restore.');
});

test('claimant workflow verifies the subject and moves focus after activation', async ({ page }, testInfo) => {
	test.skip(testInfo.project.name === 'mobile-chromium', 'The separate responsive test covers the mobile viewport.');
	await page.route('**/api/claimant/**', async (route) => {
		const path = new URL(route.request().url()).pathname;
		if (path.endsWith('/status')) return route.fulfill({ json: { phase: 'ready', ceremony_enc: 'enc', new_node: 'node', handoff: 'handoff' } });
		if (path.endsWith('/preview')) return route.fulfill({ json: { session_bound: true, subject: user } });
		return route.fulfill({ json: { restart_required: true } });
	});
	await page.goto('/claimant.html');
	await page.locator('#sponsor-package').fill(JSON.stringify({
		type: 'carapace.sponsor-ceremony', version: 1, open_hex: '00', sponsor_sig: 'd'.repeat(128), roster: [user],
		trustees: [{ node: 'b'.repeat(64), addrs: ['127.0.0.1:1'] }]
	}));
	await page.getByRole('button', { name: 'Import package and show subject' }).click();
	await expect(page.locator('#subject-id')).toHaveText(user);
	await page.locator('#confirm-subject').check();
	await page.getByRole('button', { name: 'Collect approvals and activate' }).click();
	await expect(page.locator('#restart')).toBeVisible();
	await expect(page.locator('#restart')).toBeFocused();
});

test('claimant cancellation clears inputs and starts a fresh retry session', async ({ page }, testInfo) => {
	test.skip(testInfo.project.name === 'mobile-chromium', 'The responsive test covers the mobile viewport.');
	await page.route('**/api/claimant/status', (route) => route.fulfill({ json: { phase: 'ready', ceremony_enc: 'enc', new_node: 'node', handoff: 'handoff' } }));
	await page.route('**/api/claimant/cancel', (route) => route.fulfill({ json: { cancelled: true, retry_ready: true } }));
	await page.goto('/claimant.html');
	await page.locator('#sponsor-package').fill('sensitive attempt data');
	await page.getByRole('button', { name: 'Cancel and clear this attempt' }).click();
	await expect(page.locator('#sponsor-package')).toHaveValue('');
	await expect(page.locator('#progress')).toContainText('fresh retry session is ready');
});

test('claimant clipboard success and failure give truthful feedback', async ({ page, context, browserName }, testInfo) => {
	test.skip(testInfo.project.name === 'mobile-chromium', 'Clipboard permission emulation runs in desktop Chromium.');
	await page.route('**/api/claimant/status', (route) => route.fulfill({ json: { phase: 'ready', ceremony_enc: 'enc', new_node: 'node', handoff: 'handoff' } }));
	if (browserName === 'chromium') await context.grantPermissions(['clipboard-read', 'clipboard-write']);
	await page.goto('/claimant.html');
	await page.getByRole('button', { name: 'Copy handoff package' }).click();
	await expect(page.locator('#notice')).toHaveText('Copied.');
	await page.evaluate(() => Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: () => Promise.reject(new Error('denied')) } }));
	await page.getByRole('button', { name: 'Copy handoff package' }).click();
	await expect(page.getByRole('alert')).toContainText('Select and copy');
});

test('folder browsing publishes the selected path without editing an identifier', async ({ page }) => {
	const folder = '/home/alex/My documents';
	await page.route('**/api/directories*', (route) => route.fulfill({ json: {path:folder,parent:'/home/alex',directories:[]} }));
	let published: unknown;
	await page.route('**/api/vaults', async (route) => {
		if (route.request().method() === 'POST') {
			published = route.request().postDataJSON();
			return route.fulfill({json:{vid:'c'.repeat(64),epoch:1}});
		}
		return route.fulfill({json:{published:[]}});
	});
	await page.goto('/#/vaults');
	await page.getByRole('button',{name:'Choose folder…'}).click();
	await page.getByRole('button',{name:'Use this folder'}).click();
	await expect(page.locator('#vault-dir')).toHaveValue(folder);
	await page.getByRole('button',{name:'Publish vault',exact:true}).click();
	await expect.poll(() => published).toEqual({dir:folder});
});
