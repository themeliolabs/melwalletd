use anyhow::Context;
use blkstructs::melvm::Covenant;
use dashmap::DashMap;
use std::io::prelude::*;
use std::path::{Path, PathBuf};

use crate::{acidjson::AcidJson, walletdata::WalletData};

/// Represents a whole directory of wallet JSON files.
pub struct MultiWallet {
    cache: DashMap<String, AcidJson<WalletData>>,
    dirname: PathBuf,
}

fn valid_wallet_name(name: &str) -> bool {
    name.chars().all(|x| x.is_ascii_alphanumeric() || x == '_')
}

impl MultiWallet {
    /// Opens a new MultiWallet.
    pub fn open(directory: &Path) -> anyhow::Result<Self> {
        std::fs::read_dir(directory).context("cannot open directory")?;
        Ok(MultiWallet {
            cache: Default::default(),
            dirname: directory.to_owned(),
        })
    }

    /// Lists all the wallets in the directory.
    pub fn list(&self) -> impl Iterator<Item = String> {
        std::fs::read_dir(&self.dirname)
            .unwrap()
            .map(|v| v.unwrap().file_name().to_string_lossy().to_string())
            .filter(|v| v.ends_with(".json"))
            .map(|v| v.replace(".json", ""))
            .filter(|v| valid_wallet_name(v))
    }

    /// Obtains a wallet by name.
    pub fn get_wallet(&self, name: &str) -> anyhow::Result<AcidJson<WalletData>> {
        let fname = format!("{}.json", name);
        let mut fpath = self.dirname.clone();
        fpath.push(PathBuf::from(fname));
        let labooyah = self
            .cache
            .entry(name.to_string())
            .or_try_insert_with(|| AcidJson::open(&fpath))?;
        Ok(labooyah.value().clone())
    }

    /// Creates a wallet. **WARNING**: will silently overwrite any wallet with the same name.
    pub fn create_wallet(&self, name: &str, covenant: Covenant) -> anyhow::Result<()> {
        if !valid_wallet_name(name) {
            anyhow::bail!("invalid wallet name")
        }
        let wdata = WalletData::new(covenant);
        let fname = format!("{}.json", name);
        let mut fpath = self.dirname.clone();
        fpath.push(PathBuf::from(fname));
        atomicwrites::AtomicFile::new(fpath, atomicwrites::OverwriteBehavior::AllowOverwrite)
            .write(|file| file.write_all(&serde_json::to_vec_pretty(&wdata).unwrap()))?;
        Ok(())
    }
}
