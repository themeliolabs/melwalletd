use std::{convert::TryFrom, fs::File, io::Read, net::SocketAddr, path::PathBuf};

use clap::{ArgGroup, Parser};
use serde::*;
use terminal_size::{terminal_size, Width};
use themelio_structs::NetID;
#[derive(Parser, Clone, Deserialize, Debug)]
#[clap(group(
    ArgGroup::new("options")
        .required(true)
        .args(&["wallet-dir", "config"])),
    max_term_width(1024),
    term_width(
        if let Some((Width(w), _)) = terminal_size(){
            w as usize
        }
        else{120}
    ),
)]
pub struct Args {
    #[clap(long, display_order(1))]
    /// Required: directory of the wallet database
    pub wallet_dir: Option<PathBuf>,

    #[clap(long, default_value = "mainnet", display_order(2))]
    /// Network ID: "testnet", "custom02",...
    pub network: NetID,

    #[clap(long, display_order(3))]
    /// Address of full node on specified `network`. Required when using networks other than "mainnet" and "testnet"
    pub connect: Option<SocketAddr>,

    #[clap(long, default_value = "127.0.0.1:11773", display_order(4))]
    /// melwalletd server address
    pub listen: SocketAddr,

    #[clap(long, short, default_value = "*", display_order(998))]
    /// CORS origins allowed to access daemon
    pub allowed_origin: Vec<String>, // TODO: validate as urls


    #[serde(skip_serializing)]
    #[clap(long, display_order(998))]
    /// 
    pub config: Option<String>,

    #[serde(skip_serializing)]
    #[clap(long, display_order(998))]
    /// send the generated config to stdout
    pub output_config: bool,

    #[serde(skip_serializing)]
    #[clap(long, display_order(998))]
    /// run without starting server
    pub dry_run: bool,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct Config {
    pub wallet_dir: PathBuf,
    pub listen: SocketAddr,
    pub network_addr: SocketAddr,
    pub allowed_origins: Vec<String>,
    pub network: NetID,
}
impl Config {
    fn new(
        wallet_dir: PathBuf,
        listen: SocketAddr,
        allowed_origins: Vec<String>,
        network_addr: SocketAddr,
        network: NetID,
    ) -> Config {
        Config {
            wallet_dir,
            listen,
            network_addr,
            allowed_origins,
            network,
        }
    }
}

impl TryFrom<Args> for Config {
    type Error = anyhow::Error;

    fn try_from(cmd: Args) -> Result<Self, Self::Error> {
        match cmd.config {
            Some(filename) => {
                let mut config_file = File::open(filename)?;
                let mut buf: String = "".into();
                config_file.read_to_string(&mut buf)?;
                let config: Config = serde_yaml::from_str(&buf)?;

                anyhow::Ok(config)
            }
            None => {
                let args = cmd;
                let network = args.network;
                let network_addr = args
                    .connect
                    .or_else(|| first_bootstrap_route(network))
                    .unwrap_or_else(|| {
                        panic!(
                            "{}",
                            "No bootstrap nodes available for network: {network:?}"
                        )
                    });
                Ok(Config::new(
                    args.wallet_dir.unwrap(),
                    args.listen,
                    args.allowed_origin,
                    network_addr,
                    network,
                ))
            }
        }
    }
}

fn first_bootstrap_route(network: NetID) -> Option<SocketAddr> {
    let routes = themelio_bootstrap::bootstrap_routes(network);
    if routes.is_empty() {
        None
    } else {
        Some(routes[0])
    }
}
