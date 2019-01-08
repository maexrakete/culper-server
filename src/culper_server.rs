extern crate actix;
extern crate actix_web;
extern crate env_logger;
#[macro_use]
extern crate slog;
extern crate slog_async;
extern crate slog_json;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate failure;

use self::admin_service::AdminService;
use actix_web::{http, middleware, server, App, HttpRequest, HttpResponse, Json};
use base64::decode;
use clap::ArgMatches;
use culper_lib::config;
use failure::{Error, ResultExt};
use log::{debug, error, info, warn};
use r2d2_sqlite::SqliteConnectionManager;
use sequoia::core::Context;
use sequoia::openpgp::armor::{Kind, Writer};
use sequoia::openpgp::serialize::Serialize;
use sequoia::openpgp::TSK;
use sequoia::store::Store;
use slog::Drain;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::path::PathBuf;
use std::process::exit;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

lazy_static! {
    static ref matches: ArgMatches<'static> = culper_server_cli::build().get_matches();
    static ref config_reader: config::ConfigReader =
        config::ConfigReader::new(matches.value_of("home"));
    static ref homedir: PathBuf = home_dir(matches.value_of("home"));
    static ref keypath: PathBuf = priv_key_path(
        home_dir(matches.value_of("home")),
        matches.value_of("priv_key")
    );
}

/// Application state
struct AppState {
    pubkey: String,
    secret: Arc<Mutex<Option<String>>>,
    admin_store: AdminService,
}

/// Admin registration request
#[derive(Serialize, Deserialize)]
struct AdminRegisterRequest {
    name: String,
    key: String,
}

/// simple handle
fn index(req: &HttpRequest<AppState>) -> HttpResponse {
    HttpResponse::Ok().body(format!("{}", req.state().pubkey))
}

fn add_admin(
    (req, admin_request): (HttpRequest<AppState>, Json<AdminRegisterRequest>),
) -> actix_web::Result<HttpResponse> {
    match (
        req.request().headers().get("x-setup-key"),
        req.state().secret.lock(),
    ) {
        (None, _) => Ok(HttpResponse::Unauthorized().finish()),
        (Some(key), Ok(mut mutex_secret)) => match *(mutex_secret) {
            Some(ref secret) => {
                if key == secret {
                    debug!("Decode base64-encoded public key.");
                    let key_bytes = decode(admin_request.key.as_bytes()).or_else(|_| {
                        error!("Failed decode base64 key.");
                        Err(format_err!("Invalid key format."))
                    })?;

                    debug!("Parsing public key into TSK.");
                    let tpk = TSK::from_bytes(key_bytes.as_slice())
                        .or_else(|_| {
                            error!("Submitted key could not be parsed into TSK.");
                            Err(format_err!("Submitted key seems to be invalid."))
                        })?
                        .into_tpk();

                    req.state().admin_store.import(&admin_request.name, tpk)?;
                    let _ = mutex_secret.take();
                    Ok(HttpResponse::Ok().finish())
                } else {
                    warn!("Invalid key given");
                    Ok(HttpResponse::Unauthorized().finish())
                }
            }
            None => {
                warn!("Secret was consumed");
                Ok(HttpResponse::Unauthorized().finish())
            }
        },
        (_, Err(err)) => {
            error!("Error acquiring mutex lock: {}", err);
            Ok(HttpResponse::InternalServerError().finish())
        }
    }
}

fn main() {
    if let Err(e) = app() {
        let mut cause = e.as_fail();
        eprint!("{}", cause);
        while let Some(c) = cause.cause() {
            eprint!(":\n  {}", c);
            cause = c;
        }
        eprintln!();
        exit(2);
    }
}

fn app() -> Result<(), failure::Error> {
    let root_logger = default_root_logger("culper-server");
    let _guard = slog_scope::set_global_logger(root_logger);
    slog_stdlog::init().unwrap();

    let ctx = Context::configure("localhost")
        .home(home_dir(matches.value_of("home")))
        .build()?;
    let admin_store = Store::open(&ctx, "admins").context("Failed to open the store")?;
    info!(
        "Using {} as key store.",
        format!(
            "{}/public-key-store.sqlite",
            homedir.to_str().expect("Could not get home dir as string.")
        )
    );
    let manager = SqliteConnectionManager::file(format!(
        "{}/public-key-store.sqlite",
        homedir.to_str().expect("Could not get home dir as string.")
    ));
    let pool = r2d2::Pool::new(manager)?;

    if !system_is_setup(homedir.to_path_buf(), keypath.to_path_buf()) {
        generate_certificate(keypath.to_path_buf()).context("Could not generate keys")?;
    };

    let secret_option = if admin_store.iter()?.count() == 0usize {
        let secret_key = Uuid::new_v4().to_simple().to_string();
        info!("Generated key for admin setup: {}", secret_key);
        Some(secret_key)
    } else {
        None
    };

    let secret = Arc::new(Mutex::new(secret_option));
    let pubkey = String::from_utf8(system_initialize()?)?;

    let sys = actix::System::new("culper-server");

    //move is necessary to give closure below ownership of counter
    server::new(move || {
        App::with_state(AppState {
            pubkey: pubkey.clone(),
            secret: secret.clone(),
            admin_store: AdminService::new(pool.get().unwrap()).unwrap(),
        }) // <- create app with shared state
        // enable logger
        .middleware(middleware::Logger::default())
        // register simple handler, handle all methods
        .resource("/", |r| r.f(index))
        .resource("/admin", |r| r.method(http::Method::POST).with(add_admin))
    })
    .bind("0.0.0.0:8080")
    .unwrap()
    .start();

    info!("Started http server: 0.0.0.0:8080");
    let _ = sys.run();
    Ok(())
}

pub fn default_json_drain() -> slog_async::Async {
    let drain = slog_json::Json::new(std::io::stdout())
        .add_key_value(slog_o!(
           "msg" => slog::PushFnValue(move |record : &slog::Record, ser| {
               ser.emit(record.msg())
           }),
           "tag" => slog::PushFnValue(move |record : &slog::Record, ser| {
               ser.emit(record.tag())
           }),
           "ts" => slog::PushFnValue(move |_ : &slog::Record, ser| {
               ser.emit(chrono::Local::now().to_rfc3339())
           }),
           "level" => slog::FnValue(move |rinfo : &slog::Record| {
               rinfo.level().as_str()
           }),
        ))
        .build()
        .fuse();
    let mut log_builder =
        slog_envlogger::LogBuilder::new(drain).filter(None, slog::FilterLevel::Info);
    if let Ok(s) = env::var("RUST_LOG") {
        log_builder = log_builder.parse(&s);
    }
    slog_async::Async::default(log_builder.build())
}

pub fn default_root_logger(process_name: &'static str) -> slog::Logger {
    let drain = default_json_drain();
    slog::Logger::root(
        drain.fuse(),
        slog_o!(
          "version" => env!("CARGO_PKG_VERSION"),
          "process" => process_name,
        ),
    )
}

use sequoia::openpgp::tpk::{CipherSuite, TPKBuilder};
fn generate_certificate(priv_key_path: PathBuf) -> Result<(), failure::Error> {
    let builder = TPKBuilder::default()
        .set_cipher_suite(CipherSuite::RSA3k)
        .add_signing_subkey()
        .add_encryption_subkey();

    let (tpk, _) = builder.generate()?;
    let tsk = tpk.into_tsk();
    info!("Create key at {:?}", priv_key_path);

    let file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(priv_key_path)
        .context("Failed to create output file")?;

    let mut writer = Writer::new(file, Kind::SecretKey, &[])?;
    tsk.serialize(&mut writer)?;

    Ok(())
}

fn system_is_setup(config_path: PathBuf, priv_key_path: PathBuf) -> bool {
    config_path.exists() && priv_key_path.exists()
}

use sequoia::openpgp::parse::Parse;
fn system_initialize() -> Result<Vec<u8>, Error> {
    let priv_key: String = read_priv_key(keypath.to_path_buf())?;
    let tpk = TSK::from_bytes(priv_key.as_bytes())?.into_tpk();
    let mut buffer = vec![];
    {
        let mut w = Writer::new(&mut buffer, Kind::PublicKey, &[])?;
        tpk.serialize(&mut w)?;
    }
    Ok(buffer)
}

fn home_dir(maybe_home: Option<&str>) -> PathBuf {
    let mut path = PathBuf::new();
    match maybe_home {
        Some(given_home) => path.push(given_home),
        None => match dirs::home_dir() {
            Some(home) => path.push(home),
            None => path.push("./.culper"),
        },
    }
    path
}

fn priv_key_path(home_dir: PathBuf, maybe_priv_key: Option<&str>) -> PathBuf {
    let mut path = PathBuf::new();
    match maybe_priv_key {
        // key is not at home location or named differently
        Some(priv_key_path) => path.push(priv_key_path),
        // key is at home location with standard name
        None => {
            path.push(home_dir);
            path.push("privkey.asc");
        }
    };
    path
}

fn read_priv_key(path: PathBuf) -> Result<String, Error> {
    let mut content = String::new();
    File::open(&path)
        .context(format!(
            "Could not open private key {}",
            path.clone().to_str().unwrap_or_default()
        ))?
        .read_to_string(&mut content)
        .context(format!(
            "Could not read private key {}",
            path.clone().to_str().unwrap_or_default()
        ))?;

    Ok(content)
}
mod admin_service;
mod culper_server_cli;
