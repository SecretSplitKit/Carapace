<script lang="ts">
	import { status } from '$lib/statusStore';
	import { api } from '$lib/api';
	import { copyToClipboard } from '$lib/format';
	let transferPass = $state('');
	let confirmation = $state('');
	let packageHex = $state('');
	let destination = $state('');
	let cardHex = $state('');
	let busy = $state(false);
	let message = $state('');
	async function exportAccount() {
		busy = true;
		try { packageHex = (await api.exportAccount(transferPass)).package_hex; message = 'Copy this encrypted package to your new computer. Send the passphrase separately.'; }
		catch { /* shared error banner */ }
		finally { busy = false; transferPass = ''; confirmation = ''; }
	}
	async function importAccount() {
		busy = true;
		try {
			const result = await api.importAccount({package_hex:packageHex.trim(),passphrase:transferPass,destination:destination.trim()});
			cardHex = result.card_hex;
			message = `Account created at ${result.state_dir}. Return its device card to your existing computer. Stop Carapace here, then run carapaced run --state-dir with that folder to begin sync.`;
		} catch { /* shared error banner */ }
		finally { busy = false; transferPass = ''; }
	}
	async function enroll() {
		busy = true;
		try { await api.enrollDevice(cardHex.trim()); message = 'Device enrolled. Its folders will sync when both computers are reachable.'; cardHex = ''; }
		catch { /* shared error banner */ }
		finally { busy = false; }
	}
</script>
<section class="card">
	<h2>Account and devices</h2>
	<p>Account identifier: <code>{$status?.user_id ?? 'Connecting…'}</code></p>
	<p>{$status?.identity_storage === 'operating_system_credentials' ? 'Account keys are protected by this computer’s credential store.' : $status?.identity_storage === 'passphrase_protected_files' ? 'Account keys are encrypted with a passphrase.' : 'Development mode: account keys are not protected by the credential store.'}</p>
	<details><summary>Add another computer</summary>
		<p>Create an encrypted transfer package on your existing computer. Anyone with the package and passphrase can access your account. Send them separately.</p>
		<form onsubmit={(e) => { e.preventDefault(); exportAccount(); }}>
			<label for="export-pass">New transfer passphrase</label><input id="export-pass" type="password" autocomplete="new-password" bind:value={transferPass} required />
			<label for="export-confirm">Repeat transfer passphrase</label><input id="export-confirm" type="password" autocomplete="new-password" bind:value={confirmation} required />
			<button type="submit" disabled={busy || !transferPass || transferPass !== confirmation}>Create transfer package</button>
		</form>
		<label for="transfer-package">Encrypted transfer package</label><textarea id="transfer-package" bind:value={packageHex}></textarea>
		<button type="button" onclick={() => copyToClipboard(packageHex)} disabled={!packageHex}>Copy package</button>
		<h3>On the new computer</h3>
		<p>Paste the package above. Import creates a new account folder using this computer's protected key storage.</p>
		<form onsubmit={(e) => { e.preventDefault(); importAccount(); }}>
			<label for="import-pass">Transfer passphrase</label><input id="import-pass" type="password" bind:value={transferPass} required />
			<label for="import-folder">New account folder (full path)</label><input id="import-folder" bind:value={destination} required />
			<button type="submit" disabled={busy || !packageHex || !transferPass || !destination}>Import account</button>
		</form>
		<h3>Return the new device card to the existing computer</h3>
		<textarea aria-label="New device card" bind:value={cardHex}></textarea>
		<button type="button" onclick={() => copyToClipboard(cardHex)} disabled={!cardHex}>Copy device card</button>
		<button type="button" onclick={enroll} disabled={busy || !cardHex}>Enroll this device card</button>
	</details>
	{#if message}<p role="status">{message}</p>{/if}
</section>
<style>
	label { display: block; margin-top: 0.7rem; }
	input, textarea { width: 100%; }
	textarea { min-height: 5rem; }
	button { margin: 0.6rem 0; }
	details { margin: 1rem 0; }
	code { overflow-wrap: anywhere; }
</style>
