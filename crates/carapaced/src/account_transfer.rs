//! Explicit encrypted account enrollment; the running identity is never replaced.
use super::*;

pub struct AccountImportReport {
    pub user_id: [u8; 32],
    pub state_dir: PathBuf,
    pub card: ContactCard,
    pub source_card: ContactCard,
}

impl Daemon {
    pub fn account_export(&self, passphrase: &[u8]) -> Result<(Vec<u8>, ContactCard)> {
        let card = self.own_device_card();
        Ok((
            State::seal_transfer(&self.k_root, &card.encode_frame(), passphrase)?,
            card,
        ))
    }

    pub async fn account_import(
        &self,
        package: &[u8],
        passphrase: &[u8],
        destination: &Path,
    ) -> Result<AccountImportReport> {
        ensure!(
            destination.is_absolute(),
            "account destination must be absolute"
        );
        let payload = State::open_transfer(package, passphrase)?;
        let root = Zeroizing::new(<[u8; 32]>::try_from(&payload[..32])?);
        let source_card = ContactCard::decode_frame(&payload[32..])?;
        source_card.verify()?;
        let subject = carapace_crypto::identity::user_key_from_seed(&kdf::k_userid(&*root))
            .verifying_key()
            .to_bytes();
        ensure!(
            source_card.user == subject,
            "transfer source card does not match account key"
        );
        State::prepare_account_import(destination, package)?;
        let claimant = ClaimantDevice::load_or_create(destination)?;
        let state = if destination.join("credential.id").exists() {
            let state = State::load_or_generate(destination)?;
            ensure!(
                *state.k_root == *root && state.node_key.to_bytes() == claimant.node_seed(),
                "saved transfer identity differs from package"
            );
            state
        } else {
            activate_recovered_identity(destination, claimant.node_seed(), *root)?
        };
        let relays = source_card
            .nodes
            .iter()
            .filter_map(|node| node.relay_url.as_ref())
            .map(|url| url.parse())
            .collect::<Result<Vec<_>, _>>()?;
        let imported = Daemon::start_on(
            state,
            ReplicaLimits::default(),
            NetConfig {
                bind: Some(std::net::SocketAddr::from((
                    std::net::Ipv4Addr::UNSPECIFIED,
                    0,
                ))),
                relays,
                ..NetConfig::default()
            },
        )
        .await?;
        let enrolled = imported.enroll_own_device(source_card.clone()).await;
        let card = imported.own_device_card();
        imported.shutdown().await;
        enrolled?;
        Ok(AccountImportReport {
            user_id: subject,
            state_dir: destination.to_path_buf(),
            card,
            source_card,
        })
    }

    pub fn identity_storage_label(&self) -> &'static str {
        if self.state_dir.join("credential.id").is_file() {
            "operating_system_credentials"
        } else if ["root.key", "node.key"].iter().all(|name| {
            std::fs::read(self.state_dir.join(name))
                .is_ok_and(|bytes| bytes.starts_with(b"CRPCSEAL"))
        }) {
            "passphrase_protected_files"
        } else {
            "insecure_development"
        }
    }
}
