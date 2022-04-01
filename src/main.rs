mod database;
mod multi;
mod secrets;
mod signer;
mod state;
mod walletdata;
use std::{collections::BTreeMap, ffi::CString, net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::Context;
use base32::Alphabet;
use http_types::headers::HeaderValue;
use multi::MultiWallet;
use serde::Deserialize;
use state::AppState;
use std::fmt::Debug;
use structopt::StructOpt;
use tap::Tap;
use themelio_nodeprot::ValClient;
use themelio_stf::PoolKey;
use themelio_structs::{
    BlockHeight, CoinData, CoinID, CoinValue, Denom, NetID, Transaction, TxKind,
};
use tide::security::CorsMiddleware;
use tide::{Body, Request, StatusCode};
use tmelcrypt::{Ed25519SK, HashVal, Hashable};
use walletdata::{AnnCoinID, TransactionStatus};

use crate::{database::Database, secrets::SecretStore, signer::Signer};

#[derive(StructOpt)]
struct Args {
    #[structopt(long)]
    wallet_dir: PathBuf,

    #[structopt(long, default_value = "127.0.0.1:11773")]
    listen: SocketAddr,

    #[structopt(long)]
    mainnet_connect: Option<SocketAddr>,

    #[structopt(long)]
    testnet_connect: Option<SocketAddr>,
}

// If "MELWALLETD_AUTH_TOKEN" environment variable is set, check that every HTTP request has X-Melwalletd-Auth-Token set to that string
static AUTH_TOKEN: once_cell::sync::Lazy<Option<String>> =
    once_cell::sync::Lazy::new(|| std::env::var("MELWALLETD_AUTH_TOKEN").ok());

fn check_auth<T>(req: &Request<T>) -> tide::Result<()> {
    if let Some(auth_token) = AUTH_TOKEN.as_ref() {
        if &req
            .header("X-Melwalletd-Auth-Token")
            .map(|v| v.get(0).unwrap().to_string())
            .unwrap_or_default()
            != auth_token
        {
            return Err(tide::Error::new(
                tide::StatusCode::Forbidden,
                anyhow::anyhow!("missing auth token"),
            ));
        }
    }
    Ok(())
}


fn main() -> anyhow::Result<()> {
    println!(speedup::optimise!("SPEEDING UP!!!"));
    println!(speedup::optimise!("SPEEDING UP!!!"));
    println!(speedup::optimise!("SPEEDING UP!!!"));

    smolscale::block_on(async {
        let log_conf = std::env::var("RUST_LOG").unwrap_or_else(|_| "melwalletd=debug,warn".into());
        std::env::set_var("RUST_LOG", log_conf);
        tracing_subscriber::fmt::init();
        let args = Args::from_args();
        std::fs::create_dir_all(&args.wallet_dir).context("cannot create wallet_dir")?;
        // SAFETY: this is perfectly safe because chmod cannot lead to memory unsafety.
        unsafe {
            libc::chmod(
                CString::new(args.wallet_dir.to_string_lossy().as_bytes().to_vec())?.as_ptr(),
                0o700,
            );
        }
        let multiwallet = MultiWallet::open(&args.wallet_dir)?;
        log::info!(
            "opened LEGACY wallet directory: {:?}",
            multiwallet.list().collect::<Vec<_>>()
        );

        let mainnet_db = Database::open(
            args.wallet_dir
                .clone()
                .tap_mut(|p| p.push("mainnet-wallets.db")),
        )
        .await?;
        let testnet_db = Database::open(
            args.wallet_dir
                .clone()
                .tap_mut(|p| p.push("testnet-wallets.db")),
        )
        .await?;
        let mainnet_addr = args
            .mainnet_connect
            .unwrap_or_else(|| themelio_bootstrap::bootstrap_routes(NetID::Mainnet)[0]);
        let mainnet_client = ValClient::new(NetID::Mainnet, mainnet_addr);
        mainnet_client.trust(themelio_bootstrap::checkpoint_height(NetID::Mainnet).unwrap());
        for wallet_name in multiwallet.list() {
            let wallet = multiwallet.get_wallet(&wallet_name)?;
            if wallet.read().network() == NetID::Mainnet {
                if mainnet_db.get_wallet(&wallet_name).await.is_none() {
                    let wallet = wallet.read().clone();
                    log::info!("restoring mainnet {}", wallet_name);
                    mainnet_db.restore_wallet_dump(&wallet_name, wallet).await;
                }
            } else if testnet_db.get_wallet(&wallet_name).await.is_none() {
                let wallet = wallet.read().clone();
                log::info!("restoring testnet {}", wallet_name);
                testnet_db.restore_wallet_dump(&wallet_name, wallet).await;
            }
        }

        let mut secret_path = args.wallet_dir.clone();
        secret_path.push(".secrets.json");
        let secrets = SecretStore::open(&secret_path)?;

        let state = AppState::new(
            mainnet_db,
            testnet_db,
            secrets,
            args.mainnet_connect
                .unwrap_or_else(|| themelio_bootstrap::bootstrap_routes(NetID::Mainnet)[0]),
            args.testnet_connect
                .unwrap_or_else(|| themelio_bootstrap::bootstrap_routes(NetID::Testnet)[0]),
        );

        let mut app = tide::with_state(Arc::new(state));
        // set CORS
        app.with(
            CorsMiddleware::new()
                .allow_methods("GET, POST, PUT, OPTIONS".parse::<HeaderValue>().unwrap())
                .allow_origin("*"),
        );
        // interpret errors
        app.with(tide::utils::After(|mut res: tide::Response| async move {
            if let Some(err) = res.error() {
                // put the error string in the response
                let err_str = format!("ERROR: {:?}", err);
                log::warn!("{}", err_str);
                res.set_body(err_str);
            }
            Ok(res)
        }));
        app.at("/summary").get(get_summary);
        app.at("/pools/:pair").get(get_pool);
        app.at("/wallets").get(list_wallets);
        app.at("/wallets/:name").get(summarize_wallet);
        app.at("/wallets/:name").put(create_wallet);
        app.at("/wallets/:name/lock").post(lock_wallet);
        app.at("/wallets/:name/unlock").post(unlock_wallet);
        app.at("/wallets/:name/export-sk")
            .post(export_sk_from_wallet);
        app.at("/wallets/:name/check").put(check_wallet);
        app.at("/wallets/:name/coins").get(dump_coins);
        app.at("/wallets/:name/prepare-tx").post(prepare_tx);
        app.at("/wallets/:name/prepare-stake-tx")
            .post(prepare_stake_tx);
        app.at("/wallets/:name/send-tx").post(send_tx);
        app.at("/wallets/:name/send-faucet").post(send_faucet);
        app.at("/wallets/:name/transactions").get(dump_transactions);
        app.at("/wallets/:name/transactions/:txhash").get(get_tx);
        app.at("/wallets/:name/transactions/:txhash/balance")
            .get(get_tx_balance);
        app.at("/wallets/:name/transactions/:txhash")
            .delete(force_revert_tx);
        app.listen(args.listen).await?;
        Ok(())
    })
}

async fn summarize_wallet(req: Request<Arc<AppState>>) -> tide::Result<Body> {
    check_auth(&req)?;
    let wallet_name = req.param("name")?;
    let summary = req
        .state()
        .wallet_summary(wallet_name)
        .await
        .context("not found")
        .map_err(to_notfound)?;
    Body::from_json(&summary)
}

async fn get_summary(req: Request<Arc<AppState>>) -> tide::Result<Body> {
    check_auth(&req)?;
    let query: BTreeMap<String, String> = req.query()?;
    let network = if query.get("testnet").is_some() {
        NetID::Testnet
    } else {
        NetID::Mainnet
    };
    let client = req.state().client(network).clone();
    let snap = client.snapshot().await?;
    Body::from_json(&snap.current_header())
}

async fn get_pool(req: Request<Arc<AppState>>) -> tide::Result<Body> {
    check_auth(&req)?;
    let query: BTreeMap<String, String> = req.query()?;
    let network = if query.get("testnet").is_some() {
        NetID::Testnet
    } else {
        NetID::Mainnet
    };
    let client = req.state().client(network).clone();
    let pool_key: PoolKey = req
        .param("pair")?
        .replace(":", "/")
        .parse()
        .map_err(to_badreq)?;
    let pool_key = pool_key
        .to_canonical()
        .ok_or_else(|| to_badreq(anyhow::anyhow!("bad pool key")))?;
    let pool_state = client
        .snapshot()
        .await
        .map_err(to_badgateway)?
        .get_pool(pool_key)
        .await
        .map_err(to_badgateway)?
        .ok_or_else(|| to_badreq(anyhow::anyhow!("pool not found")))?;
    Body::from_json(&pool_state)
}

async fn list_wallets(req: Request<Arc<AppState>>) -> tide::Result<Body> {
    check_auth(&req)?;
    Body::from_json(&req.state().list_wallets().await)
}

async fn create_wallet(mut req: Request<Arc<AppState>>) -> tide::Result<Body> {
    check_auth(&req)?;
    #[derive(Deserialize)]
    struct Query {
        testnet: bool,
        password: Option<String>,
        secret: Option<String>,
    }
    let query: Query = req.body_json().await?;
    let wallet_name = req.param("name").map(|v| v.to_string())?;
    let sk = if let Some(secret) = query.secret {
        // We must reconstruct the secret key using the ed25519-dalek library
        let secret =
            base32::decode(Alphabet::Crockford, &secret).context("cannot decode secret key")?;
        let secret = ed25519_dalek::SecretKey::from_bytes(&secret)?;
        let public: ed25519_dalek::PublicKey = (&secret).into();
        let mut vv = [0u8; 64];
        vv[0..32].copy_from_slice(&secret.to_bytes());
        vv[32..].copy_from_slice(&public.to_bytes());
        Ed25519SK(vv)
    } else {
        tmelcrypt::ed25519_keygen().1
    };
    req.state()
        .create_wallet(
            &wallet_name,
            if query.testnet {
                NetID::Testnet
            } else {
                NetID::Mainnet
            },
            sk,
            query.password,
        )
        .await
        .context("cannot create wallet")?;
    Ok("".into())
}

async fn check_wallet(req: Request<Arc<AppState>>) -> tide::Result<Body> {
    check_auth(&req)?;
    todo!()
}

// async fn sweep_coins(req: Request<Arc<AppState>>) -> tide::Result<Body> {
//     check_auth(&req)?;
//     let wallet_name = req.param("name").map(|v| v.to_string())?;

// }

async fn dump_coins(req: Request<Arc<AppState>>) -> tide::Result<Body> {
    check_auth(&req)?;
    let wallet_name = req.param("name").map(|v| v.to_string())?;
    let (wallet, _) = req
        .state()
        .get_wallet(&wallet_name)
        .await
        .context("not found")
        .map_err(to_notfound)?;
    let coins = wallet.get_coin_mapping(true, false).await;
    Body::from_json(&coins.into_iter().collect::<Vec<_>>())
}

async fn dump_transactions(req: Request<Arc<AppState>>) -> tide::Result<Body> {
    check_auth(&req)?;
    let wallet_name = req.param("name").map(|v| v.to_string())?;
    let (wallet, _) = req
        .state()
        .get_wallet(&wallet_name)
        .await
        .context("not found")
        .map_err(to_notfound)?;
    let transactions = wallet.get_transaction_history().await;
    Body::from_json(&transactions)
}

async fn lock_wallet(req: Request<Arc<AppState>>) -> tide::Result<Body> {
    check_auth(&req)?;
    let wallet_name = req.param("name").map(|v| v.to_string())?;
    req.state().lock(&wallet_name);
    Ok("".into())
}

async fn unlock_wallet(mut req: Request<Arc<AppState>>) -> tide::Result<Body> {
    check_auth(&req)?;
    #[derive(Deserialize)]
    struct Req {
        password: Option<String>,
    }
    let wallet_name = req.param("name").map(|v| v.to_string())?;
    let request: Req = req.body_json().await?;
    // attempt to unlock
    req.state()
        .unlock(&wallet_name, request.password)
        .context("incorrect password")
        .map_err(to_forbidden)?;
    Ok("".into())
}

async fn export_sk_from_wallet(mut req: Request<Arc<AppState>>) -> tide::Result<Body> {
    check_auth(&req)?;
    #[derive(Deserialize)]
    struct Req {
        password: Option<String>,
    }
    let wallet_name = req.param("name").map(|v| v.to_string())?;
    let request: Req = req.body_json().await?;
    // attempt to unlock
    let secret = req
        .state()
        .get_secret_key(&wallet_name, request.password)
        .context("incorrect password")
        .map_err(to_forbidden)?;
    Ok(base32::encode(Alphabet::Crockford, &secret.0[..32]).into())
}

async fn prepare_stake_tx(req: Request<Arc<AppState>>) -> tide::Result<Body> {
    check_auth(&req)?;
    todo!()
}

async fn prepare_tx(mut req: Request<Arc<AppState>>) -> tide::Result<Body> {
    check_auth(&req)?;
    #[derive(Deserialize)]
    struct Req {
        #[serde(default)]
        inputs: Vec<CoinID>,
        outputs: Vec<CoinData>,
        signing_key: Option<String>,
        kind: Option<TxKind>,
        data: Option<String>,
        #[serde(default, with = "stdcode::hexvec")]
        covenants: Vec<Vec<u8>>,
        #[serde(default)]
        nobalance: Vec<Denom>,
    }
    let wallet_name = req.param("name").map(|v| v.to_string())?;
    let request: Req = req.body_json().await?;
    let signing_key: Arc<dyn Signer> = if let Some(signing_key) = request.signing_key.as_ref() {
        Arc::new(signing_key.parse::<Ed25519SK>()?)
    } else {
        req.state()
            .get_signer(&wallet_name)
            .context("wallet is locked")
            .map_err(to_forbidden)?
    };
    let (wallet, network) = req
        .state()
        .get_wallet(&wallet_name)
        .await
        .context("no wallet")
        .map_err(to_badreq)?;

    // calculate fees
    let client = req.state().client(network).clone();
    let snapshot = client.snapshot().await.map_err(to_badgateway)?;
    let fee_multiplier = snapshot.current_header().fee_multiplier;
    let kind = request.kind;
    let data = match request.data.as_ref() {
        Some(v) => Some(hex::decode(v).map_err(to_badreq)?),
        None => None,
    };
    let prepared_tx = wallet
        .prepare(
            request.inputs.clone(),
            request.outputs.clone(),
            fee_multiplier,
            |mut tx: Transaction| {
                if let Some(kind) = kind {
                    tx.kind = kind
                }
                if let Some(data) = data.clone() {
                    tx.data = data
                }
                tx.covenants.extend_from_slice(&request.covenants);
                for i in 0..tx.inputs.len() {
                    tx = signing_key.sign_tx(tx, i)?;
                }
                Ok(tx)
            },
            request.nobalance.clone(),
        )
        .await
        .map_err(to_badreq)?;

    Ok(Body::from_json(&prepared_tx)?)
}

async fn send_tx(mut req: Request<Arc<AppState>>) -> tide::Result<Body> {
    check_auth(&req)?;
    let wallet_name = req.param("name").map(|v| v.to_string())?;
    let tx: Transaction = req.body_json().await?;
    let (wallet, netid) = req
        .state()
        .get_wallet(&wallet_name)
        .await
        .context("fail")
        .map_err(to_badreq)?;
    let snapshot = req.state().client(netid).snapshot().await?;
    // we send it off ourselves
    snapshot.get_raw().send_tx(tx.clone()).await?;
    // we mark the TX as sent in this thread.
    wallet
        .commit_sent(
            tx.clone(),
            snapshot.current_header().height + BlockHeight(10),
        )
        .await
        .map_err(to_badreq)?;
    log::info!("sent transaction with hash {}", tx.hash_nosigs());
    Ok(Body::from_json(&tx.hash_nosigs())?)
}

async fn force_revert_tx(req: Request<Arc<AppState>>) -> tide::Result<Body> {
    check_auth(&req)?;
    todo!()
}

async fn get_tx_balance(req: Request<Arc<AppState>>) -> tide::Result<Body> {
    check_auth(&req)?;
    let wallet_name = req.param("name").map(|v| v.to_string())?;
    let (wallet, network) = req
        .state()
        .get_wallet(&wallet_name)
        .await
        .context("wtf")
        .map_err(to_badreq)?;
    let txhash: HashVal = req.param("txhash")?.parse().map_err(to_badreq)?;
    let raw = wallet
        .get_transaction(txhash.into(), async {
            Ok(req.state().client(network).snapshot().await?)
        })
        .await
        .map_err(to_badgateway)?
        .context("not found")
        .map_err(to_notfound)?;
    // Is this self-originated? We check the covenants
    let self_originated = raw.covenants.iter().any(|c| c.hash() == wallet.address().0);
    // Total balance out
    let mut balance: BTreeMap<String, i128> = BTreeMap::new();
    // Add all outputs to balance
    if self_originated {
        *balance
            .entry(hex::encode(Denom::Mel.to_bytes()))
            .or_default() -= raw.fee.0 as i128;
    }
    for (idx, output) in raw.outputs.iter().enumerate() {
        let coinid = raw.output_coinid(idx as u8);
        let denom_key = hex::encode(output.denom.to_bytes());
        // first we *deduct* any balance if this self-originated
        if self_originated {
            *balance.entry(denom_key).or_default() -= output.value.0 as i128;
        }
        // then, if we find this value in our coins, we add it back. this turns out to take care of swap tx well
        if let Some(ours) = wallet.get_one_coin(coinid).await {
            let denom_key = hex::encode(ours.denom.to_bytes());
            if ours.covhash == wallet.address() {
                *balance.entry(denom_key).or_default() += ours.value.0 as i128;
            }
        }
    }
    Body::from_json(&(self_originated, balance))
}

async fn get_tx(req: Request<Arc<AppState>>) -> tide::Result<Body> {
    check_auth(&req)?;
    let wallet_name = req.param("name").map(|v| v.to_string())?;
    let (wallet, _) = req
        .state()
        .get_wallet(&wallet_name)
        .await
        .context("wtf")
        .map_err(to_badreq)?;
    let txhash: HashVal = req.param("txhash")?.parse().map_err(to_badreq)?;

    // Must either be pending or

    let raw = wallet
        .get_cached_transaction(txhash.into())
        .await
        .context("not found")
        .map_err(to_notfound)?;
    let mut confirmed_height = None;
    for idx in 0..raw.outputs.len() {
        if let Some(cdh) = wallet
            .get_coin_confirmation(raw.output_coinid(idx as u8))
            .await
        {
            confirmed_height = Some(cdh.height);
        }
    }
    let outputs = raw
        .outputs
        .iter()
        .enumerate()
        .map(|(i, cd)| {
            let coin_id = raw.output_coinid(i as u8).to_string();
            let is_change = cd.covhash == wallet.address();
            let coin_data = cd.clone();
            AnnCoinID {
                coin_data,
                is_change,
                coin_id,
            }
        })
        .collect();

    if confirmed_height.is_none() {
        // Must be pending
        if !wallet.is_pending(txhash.into()).await {
            Err(anyhow::anyhow!(
                "no longer pending but not confirmed; probably gave up"
            ))
            .map_err(to_notfound)?;
        }
    }
    Body::from_json(&TransactionStatus {
        raw,
        confirmed_height,
        outputs,
    })
}

async fn send_faucet(req: Request<Arc<AppState>>) -> tide::Result<Body> {
    check_auth(&req)?;
    let wallet_name = req.param("name").map(|v| v.to_string())?;
    let (wallet, network) = req
        .state()
        .get_wallet(&wallet_name)
        .await
        .context("wtf")
        .map_err(to_badreq)?;
    if network != NetID::Testnet {
        return Err(tide::Error::new(
            StatusCode::BadRequest,
            anyhow::anyhow!("not testnet"),
        ));
    }
    let tx = Transaction {
        kind: TxKind::Faucet,
        inputs: vec![],
        outputs: vec![CoinData {
            covhash: wallet.address(),
            value: CoinValue::from_millions(1001u64),
            denom: Denom::Mel,
            additional_data: vec![],
        }],
        data: (0..32).map(|_| fastrand::u8(0..=255)).collect(),
        fee: CoinValue::from_millions(1001u64),
        covenants: vec![],
        sigs: vec![],
    };
    // we mark the TX as sent in this thread
    let txhash = tx.hash_nosigs();
    wallet
        .commit_sent(tx, BlockHeight(u64::MAX))
        .await
        .map_err(to_badreq)?;
    Ok(Body::from_json(&txhash)?)
}

fn to_badreq<E: Into<anyhow::Error> + Send + 'static + Sync + Debug>(e: E) -> tide::Error {
    tide::Error::new(StatusCode::BadRequest, e)
}

fn to_forbidden<E: Into<anyhow::Error> + Send + 'static + Sync + Debug>(e: E) -> tide::Error {
    tide::Error::new(StatusCode::Forbidden, e)
}

fn to_notfound<E: Into<anyhow::Error> + Send + 'static + Sync + Debug>(e: E) -> tide::Error {
    tide::Error::new(StatusCode::NotFound, e)
}

fn to_badgateway<E: Into<anyhow::Error> + Send + 'static + Sync + Debug>(e: E) -> tide::Error {
    log::warn!("bad upstream: {:#?}", e);
    tide::Error::new(StatusCode::BadGateway, e)
}

// fn notfound_with(s: String) -> tide::Error {
//     tide::Error::new(StatusCode::NotFound, anyhow::anyhow!("{s}"))
// }

// fn wallet_notfound() -> tide::Error {
//     notfound_with("wallet not found".into())
// }
