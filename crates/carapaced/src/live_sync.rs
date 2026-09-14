//! Daemon-owned watching and bounded, retrying own-device anti-entropy.
use super::*;

#[derive(Clone, Debug)]
pub struct LiveSyncConfig {
    pub interval: Duration,
    /// Safety scan for missed filesystem events; registration always scans once.
    pub rescan_interval: Duration,
    pub peer_timeout: Duration,
}
impl Default for LiveSyncConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5),
            rescan_interval: Duration::from_secs(600),
            peer_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Debug)]
pub struct LiveVaultStatus {
    pub vid: [u8; 32],
    pub dir: PathBuf,
    pub epoch: u64,
    pub name: String,
    pub watching: bool,
    pub syncing: bool,
    pub last_error: Option<String>,
    pub last_success: Option<u64>,
    pub recovery_backup: Option<PathBuf>,
}

#[derive(Default)]
pub(super) struct LiveState {
    pub watching: bool,
    pub syncing: bool,
    pub last_error: Option<String>,
    pub sync_error: Option<String>,
    pub last_success: Option<u64>,
}

pub struct LiveSyncHandle {
    task: Option<tokio::task::JoinHandle<()>>,
    watchers: Option<tokio::task::JoinHandle<()>>,
}
impl LiveSyncHandle {
    pub async fn stop(mut self) {
        for task in [self.task.take(), self.watchers.take()]
            .into_iter()
            .flatten()
        {
            task.abort();
            let _ = task.await;
        }
    }
}
impl Drop for LiveSyncHandle {
    fn drop(&mut self) {
        for task in [&self.task, &self.watchers].into_iter().flatten() {
            task.abort();
        }
    }
}

impl Daemon {
    /// Call under the heavy-operation semaphore through the directory/state commit.
    pub(super) fn ensure_disjoint_working_dir(&self, vid: [u8; 32], source: &Path) -> Result<()> {
        let s = self.shared.read().expect("shared lock");
        for (other_vid, directory) in &s.working_dirs {
            if *other_vid == vid {
                continue;
            }
            let other = registered_path(directory).with_context(|| {
                format!("resolve registered vault folder {}", directory.display())
            })?;
            ensure!(
                !source.starts_with(&other) && !other.starts_with(source),
                "vault folder overlaps another registered vault: {}",
                directory.display()
            );
        }
        Ok(())
    }

    pub fn own_device_card(&self) -> ContactCard {
        let mut addrs: Vec<_> = self
            .ep
            .addr()
            .ip_addrs()
            .filter(|addr| !addr.ip().is_unspecified())
            .map(ToString::to_string)
            .collect();
        if let Ok(bound) = self.ep.direct_addr() {
            addrs.extend(
                bound
                    .ip_addrs()
                    .filter(|addr| !addr.ip().is_unspecified())
                    .map(ToString::to_string),
            );
        }
        addrs.sort();
        addrs.dedup();
        let mut s = self.shared.write().expect("shared lock");
        let card = &mut s.cards[0];
        if !addrs.is_empty() && card.nodes[0].addrs != addrs {
            card.nodes[0].addrs = addrs;
            card.version = card.version.saturating_add(1);
            card.sign(&self.user_key);
            self.persist_locked(&s);
        }
        s.cards[0].clone()
    }

    /// Explicitly enroll a root-signed own device; foreign users are never peers.
    pub async fn enroll_own_device(&self, card: ContactCard) -> Result<()> {
        ensure!(
            card.user == self.user_id(),
            "device belongs to another identity"
        );
        card.verify()?;
        ensure!(
            !card.nodes.is_empty() && card.nodes.len() <= 64,
            "invalid device roster size"
        );
        let now = unix_now();
        ensure!(
            card.nodes
                .iter()
                .all(|n| card_delegates_node(&card, &n.node_id, now)),
            "invalid or expired device delegation"
        );
        {
            let mut s = self.shared.write().expect("shared lock");
            remember_own_nodes(&mut s, &card, &self.node_key, &self.user_key, None)?;
            self.persist_locked(&s);
        }
        learn_card_hints(&self.ep.hints(), &card).await;
        Ok(())
    }

    /// Includes bootstrap failures before this device has any local vaults.
    pub fn live_peer_errors(&self) -> Vec<([u8; 32], String)> {
        self.peer_sync_errors
            .lock()
            .expect("peer sync errors")
            .iter()
            .map(|(node, error)| (*node, error.clone()))
            .collect()
    }

    pub fn live_vault_statuses(&self) -> Vec<LiveVaultStatus> {
        let s = self.shared.read().expect("shared lock");
        let live = self.live_state.lock().expect("live state");
        let peer_error = self
            .peer_sync_errors
            .lock()
            .expect("peer sync errors")
            .values()
            .next()
            .cloned();
        let mut statuses: Vec<_> = s
            .working_dirs
            .iter()
            .map(|(vid, dir)| {
                let state = live.get(vid);
                LiveVaultStatus {
                    vid: *vid,
                    dir: dir.clone(),
                    epoch: *s.epochs.get(vid).unwrap_or(&0),
                    name: dir
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned(),
                    watching: state.is_some_and(|s| s.watching),
                    syncing: state.is_some_and(|s| s.syncing),
                    last_error: state
                        .and_then(|s| s.last_error.clone().or_else(|| s.sync_error.clone()))
                        .or_else(|| peer_error.clone()),
                    last_success: state.and_then(|s| s.last_success),
                    recovery_backup: {
                        let path = self.state_dir.join("restore-backups").join(hex32(vid));
                        path.is_dir().then_some(path)
                    },
                }
            })
            .collect();
        statuses.sort_by_key(|s| s.vid);
        statuses
    }

    pub(super) fn note_live_result(&self, vid: [u8; 32], result: &Result<impl Sized>) {
        let mut live = self.live_state.lock().expect("live state");
        let state = live.entry(vid).or_default();
        state.syncing = false;
        match result {
            Ok(_) => {
                state.sync_error = None;
                state.last_success = Some(unix_now());
            }
            Err(error) => state.sync_error = Some(format!("{error:#}")),
        }
    }

    pub(super) fn note_publish_result(&self, vid: [u8; 32], result: &Result<u64>) {
        let mut live = self.live_state.lock().expect("live state");
        let state = live.entry(vid).or_default();
        match result {
            Ok(_) => {
                state.last_error = None;
                state.last_success = Some(unix_now());
            }
            Err(e) => {
                state.last_error = Some(format!("{e:#}"));
            }
        }
    }

    /// Own all filesystem watchers and retry one peer at a time. Polling also repairs
    /// missed OS events and processes edits made while the daemon was stopped.
    pub fn run_live_sync(self: Arc<Self>, cfg: LiveSyncConfig) -> LiveSyncHandle {
        let watch_weak = Arc::downgrade(&self);
        let watch_interval = cfg.interval.max(Duration::from_millis(20));
        let rescan_interval = cfg.rescan_interval.max(watch_interval);
        // Offline peers must never delay watcher discovery for a newly published folder.
        let watch_task = tokio::spawn(async move {
            let mut watchers: HashMap<[u8; 32], (PathBuf, VaultWatcher, tokio::time::Instant)> =
                HashMap::new();
            let mut interval = tokio::time::interval(watch_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let Some(daemon) = watch_weak.upgrade() else {
                    break;
                };
                let dirs = daemon
                    .shared
                    .read()
                    .expect("shared lock")
                    .working_dirs
                    .clone();
                for (vid, dir) in &dirs {
                    if !dir.is_dir() || watchers.get(vid).is_some_and(|(old, _, _)| old != dir) {
                        watchers.remove(vid);
                        daemon
                            .live_state
                            .lock()
                            .expect("live state")
                            .entry(*vid)
                            .or_default()
                            .watching = false;
                    }
                    let new_watch = !watchers.contains_key(vid);
                    if new_watch {
                        match Arc::clone(&daemon).watch_vault(*vid, dir.clone()) {
                            Ok(watcher) => {
                                watchers.insert(
                                    *vid,
                                    (dir.clone(), watcher, tokio::time::Instant::now()),
                                );
                                daemon
                                    .live_state
                                    .lock()
                                    .expect("live state")
                                    .entry(*vid)
                                    .or_default()
                                    .watching = true;
                            }
                            Err(e) => daemon.note_live_result(*vid, &Err::<(), _>(e)),
                        }
                    }
                    if new_watch
                        || watchers
                            .get(vid)
                            .is_some_and(|(_, _, last)| last.elapsed() >= rescan_interval)
                    {
                        let _ = daemon.refresh_vault(dir, *vid).await;
                        if let Some((_, _, last)) = watchers.get_mut(vid) {
                            *last = tokio::time::Instant::now();
                        }
                    }
                }
            }
        });
        let weak = Arc::downgrade(&self);
        let task = tokio::spawn(async move {
            let mut retries: HashMap<[u8; 32], (u32, tokio::time::Instant)> = HashMap::new();
            let mut interval = tokio::time::interval(cfg.interval.max(Duration::from_millis(20)));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let Some(daemon) = weak.upgrade() else {
                    break;
                };
                let dirs = daemon
                    .shared
                    .read()
                    .expect("shared lock")
                    .working_dirs
                    .clone();
                let card = daemon.own_device_card();
                learn_card_hints(&daemon.ep.hints(), &card).await;
                for node in &card.nodes {
                    if node.node_id == daemon.node_id()
                        || !card_delegates_node(&card, &node.node_id, unix_now())
                    {
                        continue;
                    }
                    if retries
                        .get(&node.node_id)
                        .is_some_and(|(_, when)| *when > tokio::time::Instant::now())
                    {
                        continue;
                    }
                    let Some(peer) = resolve_peer(&HashMap::new(), &node.node_id) else {
                        continue;
                    };
                    for vid in dirs.keys() {
                        daemon
                            .live_state
                            .lock()
                            .expect("live state")
                            .entry(*vid)
                            .or_default()
                            .syncing = true;
                    }
                    let result = daemon
                        .sync_impl(
                            peer.clone(),
                            peer,
                            &daemon.state_dir.join("vaults"),
                            true,
                            cfg.peer_timeout,
                        )
                        .await;
                    match &result {
                        Ok(_) => {
                            retries.remove(&node.node_id);
                        }
                        Err(e) => {
                            daemon
                                .peer_sync_errors
                                .lock()
                                .expect("peer sync errors")
                                .insert(
                                    node.node_id,
                                    format!("device {}: {e:#}", hex32(&node.node_id)),
                                );
                            let failures = retries
                                .get(&node.node_id)
                                .map_or(1, |(n, _)| n.saturating_add(1));
                            let delay = cfg.interval.saturating_mul(1 << failures.min(6));
                            retries.insert(
                                node.node_id,
                                (failures, tokio::time::Instant::now() + delay),
                            );
                        }
                    }
                    for vid in dirs.keys() {
                        if result.is_err() {
                            daemon.note_live_result(*vid, &result);
                        } else {
                            daemon
                                .live_state
                                .lock()
                                .expect("live state")
                                .entry(*vid)
                                .or_default()
                                .syncing = false;
                        }
                    }
                }
            }
        });
        LiveSyncHandle {
            task: Some(task),
            watchers: Some(watch_task),
        }
    }
}

/// Keep the local node first and retain verified sibling hints across restarts.
/// Inbound discovery learns only the authenticated node; explicit enrollment can
/// carry the full roster. Existing newest-card authorization still gates discovery.
pub(super) fn remember_own_nodes(
    s: &mut Shared,
    card: &ContactCard,
    node_key: &SigningKey,
    user_key: &SigningKey,
    remote: Option<&[u8; 32]>,
) -> Result<()> {
    let own_id = node_key.verifying_key().to_bytes();
    let mut own = s.cards.first().context("no own card")?.clone();
    let mut changed = false;
    for n in &card.nodes {
        if n.node_id == own_id
            || remote.is_some_and(|id| id != &n.node_id)
            || !card_delegates_node(card, &n.node_id, unix_now())
        {
            continue;
        }
        if let Some(existing) = own.nodes.iter_mut().find(|old| old.node_id == n.node_id) {
            if existing.addrs != n.addrs
                || existing.relay_url != n.relay_url
                || existing.deleg != n.deleg
            {
                *existing = n.clone();
                changed = true;
            }
        } else {
            ensure!(
                own.nodes.len() < 64,
                "at most 64 own devices may be enrolled"
            );
            own.nodes.push(n.clone());
            changed = true;
        }
    }
    if changed {
        own.version = own.version.max(card.version).saturating_add(1);
        own.sign(user_key);
        s.cards[0] = own;
    }
    Ok(())
}

/// Resolve aliases in every existing ancestor while retaining a missing folder's
/// reserved path. Permission errors and dangling links are never treated as absence.
pub(super) fn registered_path(path: &Path) -> Result<PathBuf> {
    let mut ancestor = path.to_path_buf();
    let mut missing = Vec::new();
    loop {
        match std::fs::canonicalize(&ancestor) {
            Ok(mut resolved) => {
                for name in missing.into_iter().rev() {
                    resolved.push(name);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match std::fs::symlink_metadata(&ancestor) {
                    Ok(metadata) => ensure!(
                        !metadata.file_type().is_symlink(),
                        "registered vault has a dangling link: {}",
                        ancestor.display()
                    ),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                missing.push(
                    ancestor
                        .file_name()
                        .context("registered vault has no existing ancestor")?
                        .to_os_string(),
                );
                ensure!(ancestor.pop(), "registered vault has no existing ancestor");
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// Publish first-run addressing only after its complete value is durable. Never
/// clobber a surviving selection, including when another starter wins the race.
pub(super) fn write_peer_port(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let parent = path.parent().context("peer port parent")?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).context("create temporary peer port")?;
    temporary
        .write_all(bytes)
        .context("write persisted peer port")?;
    temporary
        .as_file()
        .sync_all()
        .context("sync persisted peer port")?;
    temporary
        .persist_noclobber(path)
        .context("publish persisted peer port")?;
    #[cfg(unix)]
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_port_is_complete_and_never_clobbered() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("peer-port");
        write_peer_port(&path, b"23456")?;
        ensure!(std::fs::read(&path)? == b"23456");
        ensure!(write_peer_port(&path, b"34567").is_err());
        ensure!(std::fs::read(&path)? == b"23456");
        Ok(())
    }
}
