const token = document.querySelector('meta[name="carapace-claimant-token"]')?.content ?? '';
const errorBox = document.querySelector('#error');
const notice = document.querySelector('#notice');
const progress = document.querySelector('#progress');

function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = false;
}

async function request(path, init) {
  const response = await fetch(path, {
    ...init,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...init?.headers }
  });
  const body = await response.json();
  if (!response.ok) throw new Error(typeof body.error === 'string' ? body.error : 'The claimant request failed.');
  return body;
}

async function copyPublicValue(id) {
  try {
    await navigator.clipboard.writeText(document.querySelector(`#${id}`).value);
    notice.textContent = 'Copied.';
  } catch {
    showError('Could not copy. Select and copy the public value manually.');
  }
}

function lines(id) {
  return document.querySelector(`#${id}`).value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
}

function trusteeRows() {
  return lines('trustees').map((line) => {
    const [node, rawAddresses = ''] = line.split('|', 2);
    return { node: node.trim(), addrs: rawAddresses.split(',').map((value) => value.trim()).filter(Boolean) };
  });
}

let announceRefs = [];

function importSponsorPackage() {
  const value = JSON.parse(document.querySelector('#sponsor-package').value);
  if (value.type !== 'carapace.sponsor-ceremony' || value.version !== 1 ||
      typeof value.open_hex !== 'string' || !Array.isArray(value.roster) || !Array.isArray(value.trustees)) {
    throw new Error('The sponsor ceremony package type, version, or fields are invalid.');
  }
  document.querySelector('#open-hex').value = value.open_hex;
  document.querySelector('#roster').value = value.roster.join('\n');
  document.querySelector('#trustees').value = value.trustees.map((trustee) =>
    `${trustee.node}|${Array.isArray(trustee.addrs) ? trustee.addrs.join(',') : ''}`).join('\n');
  announceRefs = Array.isArray(value.announce_refs) ? value.announce_refs : [];
}

let confirmedSubject = '';

async function previewOpen() {
  errorBox.hidden = true;
  importSponsorPackage();
  const preview = await request('/api/claimant/preview', {
    method: 'POST', body: JSON.stringify({ open_hex: document.querySelector('#open-hex').value.trim() })
  });
  if (!preview.session_bound) throw new Error('The signed open is not bound to this session.');
  confirmedSubject = preview.subject;
  document.querySelector('#subject-id').textContent = preview.subject;
  document.querySelector('#subject-confirmation').hidden = false;
  document.querySelector('#confirm-subject').checked = false;
  document.querySelector('#recover').disabled = true;
}

async function loadSession() {
  const session = await request('/api/claimant/status');
  if (session.phase === 'activation_complete') {
    document.querySelector('#restart').hidden = false;
    document.querySelector('#complete-form').hidden = true;
    return;
  }
  document.querySelector('#ceremony-enc').value = session.ceremony_enc;
  document.querySelector('#new-node').value = session.new_node;
  document.querySelector('#handoff').value = session.handoff;
}

document.querySelectorAll('[data-copy]').forEach((button) => {
  button.addEventListener('click', () => copyPublicValue(button.dataset.copy));
});

document.querySelector('#preview-open').addEventListener('click', () => {
  previewOpen().catch((error) => showError(error instanceof Error ? error.message : 'Could not verify the signed open.'));
});

document.querySelector('#sponsor-package').addEventListener('input', () => {
  confirmedSubject = '';
  announceRefs = [];
  document.querySelector('#subject-confirmation').hidden = true;
  document.querySelector('#recover').disabled = true;
});

document.querySelector('#cancel').addEventListener('click', async () => {
  errorBox.hidden = true;
  await request('/api/claimant/cancel', { method: 'POST', body: '{}' });
  for (const id of ['sponsor-package', 'open-hex', 'roster', 'trustees']) document.querySelector(`#${id}`).value = '';
  confirmedSubject = '';
  announceRefs = [];
  document.querySelector('#subject-confirmation').hidden = true;
  document.querySelector('#recover').disabled = true;
  progress.textContent = 'The old session keys were cleared. A fresh retry session is ready.';
  await loadSession();
});

document.querySelector('#confirm-subject').addEventListener('change', (event) => {
  document.querySelector('#recover').disabled = !(event.target.checked && confirmedSubject);
});

document.querySelector('#complete-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  errorBox.hidden = true;
  const button = document.querySelector('#recover');
  button.disabled = true;
  progress.textContent = 'Contacting trustees. Keep this window open.';
  try {
    const result = await request('/api/claimant/complete', {
      method: 'POST',
      body: JSON.stringify({ open_hex: document.querySelector('#open-hex').value.trim(), confirmed_subject: confirmedSubject, roster: lines('roster'), trustees: trusteeRows(), announce_refs: announceRefs })
    });
    if (!result.restart_required) throw new Error('Activation did not request a safe restart.');
    progress.textContent = 'Recovered identity activation is complete.';
    document.querySelector('#restart').hidden = false;
    document.querySelector('#complete-form').hidden = true;
    document.querySelector('#restart').focus?.();
  } catch (error) {
    showError(error instanceof Error ? error.message : 'Recovery did not complete.');
    progress.textContent = 'Recovery stopped without activation.';
    button.disabled = false;
  }
});

loadSession().catch(() => showError('Could not load the claimant session. Reload this local page.'));
