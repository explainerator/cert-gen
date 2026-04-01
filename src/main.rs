use anyhow::{anyhow, Context, Result};
use clap::Parser;
use rcgen::{CertificateParams, DnType, KeyPair};
use serde::Deserialize;
use sha1::{Digest, Sha1};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "cert-gen",
    about = "Generate mTLS client certificates signed by a CA stored in OVHCloud OKMS"
)]
struct Cli {
    /// Client name (used as Common Name in the certificate)
    name: String,

    /// Certificate validity in days
    #[arg(short, long, default_value = "365")]
    days: u32,

    /// Output directory for generated files
    #[arg(short, long, default_value = ".")]
    output: PathBuf,

    /// Path to secrets.toml config file
    #[arg(short, long, default_value = "secrets.toml")]
    config: PathBuf,
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Config {
    ovh: OvhConfig,
    okms: OkmsConfig,
}

#[derive(Deserialize)]
struct OvhConfig {
    endpoint: String,
    application_key: String,
    application_secret: String,
    consumer_key: String,
}

#[derive(Deserialize)]
struct OkmsConfig {
    id: String,
    ca_cert_path: String,
    ca_key_path: String,
}

// ---------------------------------------------------------------------------
// OVH API client
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct OkmsSecretResponse {
    version: OkmsSecretVersion,
}

#[derive(Deserialize)]
struct OkmsSecretVersion {
    data: serde_json::Value,
}

struct OvhClient {
    http: reqwest::blocking::Client,
    base_url: String,
    application_key: String,
    application_secret: String,
    consumer_key: String,
}

impl OvhClient {
    fn new(config: &OvhConfig) -> Result<Self> {
        let base_url = match config.endpoint.as_str() {
            "ovh-ca" => "https://ca.api.ovh.com",
            "ovh-eu" => "https://eu.api.ovh.com",
            "ovh-us" => "https://api.us.ovhcloud.com",
            url if url.starts_with("https://") => url,
            other => return Err(anyhow!("Unknown OVH endpoint: {other}")),
        };

        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self {
            http,
            base_url: base_url.to_string(),
            application_key: config.application_key.clone(),
            application_secret: config.application_secret.clone(),
            consumer_key: config.consumer_key.clone(),
        })
    }

    fn get_timestamp(&self) -> Result<i64> {
        let url = format!("{}/1.0/auth/time", self.base_url);
        let resp = self.http.get(&url).send()?.text()?;
        resp.trim()
            .parse::<i64>()
            .context("Failed to parse OVH server timestamp")
    }

    fn sign(&self, method: &str, url: &str, body: &str, timestamp: i64) -> String {
        let to_sign = format!(
            "{}+{}+{}+{}+{}+{}",
            self.application_secret, self.consumer_key, method, url, body, timestamp
        );
        let hash = Sha1::digest(to_sign.as_bytes());
        format!("$1${}", hex::encode(hash))
    }

    fn get_json(&self, path: &str) -> Result<serde_json::Value> {
        let url = format!("{}{}", self.base_url, path);
        let timestamp = self.get_timestamp()?;
        let signature = self.sign("GET", &url, "", timestamp);

        let resp = self
            .http
            .get(&url)
            .header("X-Ovh-Application", &self.application_key)
            .header("X-Ovh-Timestamp", timestamp.to_string())
            .header("X-Ovh-Signature", &signature)
            .header("X-Ovh-Consumer", &self.consumer_key)
            .header("Content-Type", "application/json")
            .send()?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("OVH API error ({status}): {body}"));
        }

        resp.json().context("Failed to parse OVH API response")
    }

    fn read_secret(&self, okms_id: &str, secret_path: &str) -> Result<String> {
        let encoded_id = urlencoding::encode(okms_id);
        let encoded_path = urlencoding::encode(secret_path);
        let api_path = format!(
            "/v2/okms/resource/{encoded_id}/secret/{encoded_path}?includeData=true"
        );

        let json = self.get_json(&api_path)?;
        let resp: OkmsSecretResponse =
            serde_json::from_value(json).context("Failed to parse OKMS secret response")?;

        resp.version
            .data
            .get("pem")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Secret at '{secret_path}' missing 'pem' key in data"))
    }
}

// ---------------------------------------------------------------------------
// Certificate generation
// ---------------------------------------------------------------------------

fn generate_client_cert(
    ca_cert_pem: &str,
    ca_key_pem: &str,
    client_name: &str,
    validity_days: u32,
) -> Result<(String, String)> {
    // Load CA key pair
    let ca_key =
        KeyPair::from_pem(ca_key_pem).context("Failed to parse CA private key PEM")?;

    // Reconstruct CA certificate from existing PEM
    let ca_cert = CertificateParams::from_ca_cert_pem(ca_cert_pem)
        .context("Failed to parse CA certificate PEM")?
        .self_signed(&ca_key)
        .context("Failed to reconstruct CA certificate")?;

    // Generate a new key pair for the client
    let client_key = KeyPair::generate().context("Failed to generate client key pair")?;

    // Build client certificate parameters
    let mut params = CertificateParams::new(vec![client_name.to_string()])
        .context("Failed to create certificate params")?;
    params
        .distinguished_name
        .push(DnType::CommonName, client_name);

    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(i64::from(validity_days));

    // Sign with CA
    let client_cert = params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .context("Failed to sign client certificate with CA")?;

    Ok((client_cert.pem(), client_key.serialize_pem()))
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load config
    let config_str = fs::read_to_string(&cli.config)
        .with_context(|| format!("Failed to read {}", cli.config.display()))?;
    let config: Config =
        toml::from_str(&config_str).context("Failed to parse config file")?;

    // Connect to OVH API
    let client = OvhClient::new(&config.ovh)?;

    // Fetch CA material from OKMS
    eprintln!("Fetching CA certificate from OKMS...");
    let ca_cert_pem = client.read_secret(&config.okms.id, &config.okms.ca_cert_path)?;

    eprintln!("Fetching CA private key from OKMS...");
    let ca_key_pem = client.read_secret(&config.okms.id, &config.okms.ca_key_path)?;

    // Generate client certificate
    eprintln!("Generating client certificate for '{}'...", cli.name);
    let (cert_pem, key_pem) =
        generate_client_cert(&ca_cert_pem, &ca_key_pem, &cli.name, cli.days)?;

    // Write output files
    fs::create_dir_all(&cli.output)?;

    let cert_path = cli.output.join(format!("{}.crt", cli.name));
    let key_path = cli.output.join(format!("{}.key", cli.name));
    let ca_path = cli.output.join("ca.crt");

    fs::write(&cert_path, &cert_pem)?;
    fs::write(&key_path, &key_pem)?;
    fs::write(&ca_path, &ca_cert_pem)?;

    eprintln!("Generated files:");
    eprintln!("  Certificate: {}", cert_path.display());
    eprintln!("  Private key: {}", key_path.display());
    eprintln!("  CA cert:     {}", ca_path.display());
    eprintln!("Valid for {} days.", cli.days);

    Ok(())
}
