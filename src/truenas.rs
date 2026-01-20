use anyhow::{Context, Result, bail};
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue};
use serde::Serialize;
use serde_json::Value;
use std::time::Duration;
use url::Url;

#[derive(Clone, Copy)]
pub enum UnlockSecret<'a> {
    Passphrase(&'a str),
    Key(&'a str),
}

#[derive(Clone, Copy)]
pub struct UnlockOptions {
    pub recursive: bool,
    pub force: bool,
    pub toggle_attachments: bool,
}

pub enum Auth<'a> {
    Basic {
        username: &'a str,
        password: &'a str,
    },
    ApiKey {
        key: &'a str,
    },
}

#[derive(Default)]
pub struct UnlockResult {
    pub job_id: Option<i64>,
    pub unlocked: Vec<String>,
    pub failed: Vec<(String, String)>,
    pub message: Option<String>,
}

pub fn build_client(skip_tls_verify: bool) -> Result<Client> {
    let mut builder = ClientBuilder::new()
        .timeout(Duration::from_secs(30))
        .user_agent("naslock/0.1");
    if skip_tls_verify {
        builder = builder.danger_accept_invalid_certs(true);
    }
    Ok(builder.build()?)
}

pub fn parse_base_url(host: &str) -> Result<Url> {
    let trimmed = host.trim();
    let mut host = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("https://{}", trimmed)
    };
    if host.ends_with('/') {
        host.pop();
    }
    let mut url = Url::parse(&host).context("invalid NAS host URL")?;
    url.set_path("/");
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

pub fn unlock_dataset(
    client: &Client,
    base_url: &Url,
    auth: Auth<'_>,
    dataset: &str,
    secret: UnlockSecret<'_>,
    options: UnlockOptions,
) -> Result<UnlockResult> {
    let url = base_url
        .join("api/v2.0/pool/dataset/unlock")
        .context("failed to build API URL")?;

    let (passphrase, key) = match secret {
        UnlockSecret::Passphrase(value) => (Some(value), None),
        UnlockSecret::Key(value) => (None, Some(value)),
    };

    let body = UnlockRequest {
        id: dataset,
        unlock_options: UnlockOptionsBody {
            recursive: options.recursive,
            force: options.force,
            toggle_attachments: options.toggle_attachments,
            key_file: false,
            datasets: vec![UnlockDataset {
                name: dataset,
                passphrase,
                key,
            }],
        },
    };

    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

    let mut request = client.post(url).headers(headers).json(&body);
    request = match auth {
        Auth::Basic { username, password } => request.basic_auth(username, Some(password)),
        Auth::ApiKey { key } => {
            let value = format!("Bearer {}", key);
            request.header(AUTHORIZATION, value)
        }
    };

    let response = request.send().context("failed to send unlock request")?;
    let status = response.status();
    let text = response
        .text()
        .context("failed to read unlock response body")?;

    if !status.is_success() {
        bail!("TrueNAS API error ({}): {}", status, text.trim());
    }

    parse_unlock_response(&text)
}

#[derive(Serialize)]
struct UnlockRequest<'a> {
    id: &'a str,
    unlock_options: UnlockOptionsBody<'a>,
}

#[derive(Serialize)]
struct UnlockOptionsBody<'a> {
    recursive: bool,
    force: bool,
    toggle_attachments: bool,
    key_file: bool,
    datasets: Vec<UnlockDataset<'a>>,
}

#[derive(Serialize)]
struct UnlockDataset<'a> {
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    passphrase: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<&'a str>,
}

fn parse_unlock_response(text: &str) -> Result<UnlockResult> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(UnlockResult::default());
    }

    let mut result = UnlockResult::default();
    match serde_json::from_str::<Value>(trimmed) {
        Ok(Value::Object(map)) => {
            if let Some(job_id) = map.get("job_id").and_then(|v| v.as_i64()) {
                result.job_id = Some(job_id);
            }
            if let Some(unlocked) = map.get("unlocked").and_then(|v| v.as_array()) {
                for value in unlocked {
                    if let Some(item) = value.as_str() {
                        result.unlocked.push(item.to_string());
                    }
                }
            }
            if let Some(failed) = map.get("failed").and_then(|v| v.as_object()) {
                for (name, reason) in failed {
                    let reason = reason
                        .as_str()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| reason.to_string());
                    result.failed.push((name.to_string(), reason));
                }
            }
            if let Some(message) = map.get("message").and_then(|v| v.as_str()) {
                result.message = Some(message.to_string());
            }
        }
        Ok(other) => {
            result.message = Some(other.to_string());
        }
        Err(_) => {
            result.message = Some(trimmed.to_string());
        }
    }
    Ok(result)
}
