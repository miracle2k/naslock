use anyhow::{Context, Result, bail};
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue};
use serde::Serialize;
use serde_json::{Value, json};
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

#[derive(Clone, Copy)]
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

#[derive(Default)]
pub struct LockResult {
    pub job_id: Option<i64>,
    pub locked: bool,
    pub message: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct JobInfo {
    pub id: i64,
    pub state: Option<String>,
    pub error: Option<String>,
    pub exception: Option<String>,
    pub progress_percent: Option<f64>,
    pub progress_description: Option<String>,
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
    request = apply_auth(request, auth);

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

pub fn lock_dataset(
    client: &Client,
    base_url: &Url,
    auth: Auth<'_>,
    dataset: &str,
    force_umount: bool,
) -> Result<LockResult> {
    let url = base_url
        .join("api/v2.0/pool/dataset/lock")
        .context("failed to build API URL")?;

    let body = LockRequest {
        id: dataset,
        lock_options: LockOptionsBody { force_umount },
    };

    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

    let mut request = client.post(url).headers(headers).json(&body);
    request = apply_auth(request, auth);

    let response = request.send().context("failed to send lock request")?;
    let status = response.status();
    let text = response
        .text()
        .context("failed to read lock response body")?;

    if !status.is_success() {
        bail!("TrueNAS API error ({}): {}", status, text.trim());
    }

    parse_lock_response(&text)
}

pub fn wait_for_job(
    client: &Client,
    base_url: &Url,
    auth: Auth<'_>,
    job_id: i64,
) -> Result<JobInfo> {
    let poll_interval = Duration::from_secs(1);
    let mut last_progress: Option<(Option<f64>, Option<String>)> = None;

    loop {
        let job = get_job(client, base_url, auth, job_id)?;

        if let Some(state) = job.state.as_deref() {
            match state {
                "SUCCESS" => return Ok(job),
                "FAILED" | "ABORTED" => {
                    let detail = job
                        .error
                        .clone()
                        .or(job.exception.clone())
                        .unwrap_or_else(|| "job failed".to_string());
                    bail!("job {} failed: {}", job_id, detail.trim());
                }
                _ => {}
            }
        }

        let progress = (job.progress_percent, job.progress_description.clone());
        if progress.0.is_some() || progress.1.is_some() {
            if last_progress.as_ref() != Some(&progress) {
                if let Some(percent) = progress.0 {
                    if let Some(desc) = progress.1.as_deref() {
                        println!("job {}: {:.0}% {}", job_id, percent, desc);
                    } else {
                        println!("job {}: {:.0}%", job_id, percent);
                    }
                } else if let Some(desc) = progress.1.as_deref() {
                    println!("job {}: {}", job_id, desc);
                }
                last_progress = Some(progress);
            }
        }

        std::thread::sleep(poll_interval);
    }
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

#[derive(Serialize)]
struct LockRequest<'a> {
    id: &'a str,
    lock_options: LockOptionsBody,
}

#[derive(Serialize)]
struct LockOptionsBody {
    force_umount: bool,
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
        Ok(Value::Number(num)) => {
            if let Some(job_id) = num.as_i64() {
                result.job_id = Some(job_id);
            } else {
                result.message = Some(num.to_string());
            }
        }
        Ok(Value::String(text)) => {
            if let Ok(job_id) = text.trim().parse::<i64>() {
                result.job_id = Some(job_id);
            } else {
                result.message = Some(text);
            }
        }
        Ok(other) => {
            result.message = Some(other.to_string());
        }
        Err(_) => {
            if let Ok(job_id) = trimmed.parse::<i64>() {
                result.job_id = Some(job_id);
            } else {
                result.message = Some(trimmed.to_string());
            }
        }
    }
    Ok(result)
}

fn parse_lock_response(text: &str) -> Result<LockResult> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(LockResult::default());
    }

    let mut result = LockResult::default();
    match serde_json::from_str::<Value>(trimmed) {
        Ok(Value::Object(map)) => {
            if let Some(job_id) = map.get("job_id").and_then(|v| v.as_i64()) {
                result.job_id = Some(job_id);
            }
            if let Some(locked) = map.get("locked").and_then(|v| v.as_bool()) {
                result.locked = locked;
            }
            if let Some(message) = map.get("message").and_then(|v| v.as_str()) {
                result.message = Some(message.to_string());
            }
        }
        Ok(Value::Bool(value)) => {
            result.locked = value;
        }
        Ok(Value::Number(num)) => {
            if let Some(job_id) = num.as_i64() {
                result.job_id = Some(job_id);
            } else {
                result.message = Some(num.to_string());
            }
        }
        Ok(Value::String(text)) => {
            if let Ok(job_id) = text.trim().parse::<i64>() {
                result.job_id = Some(job_id);
            } else if let Ok(value) = text.trim().parse::<bool>() {
                result.locked = value;
            } else {
                result.message = Some(text);
            }
        }
        Ok(other) => {
            result.message = Some(other.to_string());
        }
        Err(_) => {
            if let Ok(job_id) = trimmed.parse::<i64>() {
                result.job_id = Some(job_id);
            } else if let Ok(value) = trimmed.parse::<bool>() {
                result.locked = value;
            } else {
                result.message = Some(trimmed.to_string());
            }
        }
    }
    Ok(result)
}

fn apply_auth(
    request: reqwest::blocking::RequestBuilder,
    auth: Auth<'_>,
) -> reqwest::blocking::RequestBuilder {
    match auth {
        Auth::Basic { username, password } => request.basic_auth(username, Some(password)),
        Auth::ApiKey { key } => {
            let value = format!("Bearer {}", key);
            request.header(AUTHORIZATION, value)
        }
    }
}

fn get_job(client: &Client, base_url: &Url, auth: Auth<'_>, job_id: i64) -> Result<JobInfo> {
    let url = base_url
        .join("api/v2.0/core/get_jobs")
        .context("failed to build jobs API URL")?;

    let post_result = fetch_job_via_post(client, url.clone(), auth, job_id);
    if let Ok(job) = post_result {
        return Ok(job);
    }

    let get_result = fetch_job_via_get(client, url, auth, job_id);
    match (post_result.err(), get_result) {
        (_, Ok(job)) => Ok(job),
        (Some(post_err), Err(get_err)) => Err(anyhow::anyhow!(
            "failed to query job status: post error: {}; get error: {}",
            post_err,
            get_err
        )),
        (None, Err(get_err)) => Err(get_err),
    }
}

fn fetch_job_via_post(client: &Client, url: Url, auth: Auth<'_>, job_id: i64) -> Result<JobInfo> {
    let mut request = client
        .post(url)
        .header(ACCEPT, "application/json")
        .json(&json!([[["id", "=", job_id]]]));
    request = apply_auth(request, auth);

    let response = request.send().context("failed to query job status")?;
    let status = response.status();
    let text = response
        .text()
        .context("failed to read job status response body")?;

    if !status.is_success() {
        bail!("TrueNAS API error ({}): {}", status, text.trim());
    }

    parse_job_response(&text, job_id)
}

fn fetch_job_via_get(
    client: &Client,
    mut url: Url,
    auth: Auth<'_>,
    job_id: i64,
) -> Result<JobInfo> {
    url.query_pairs_mut().append_pair("id", &job_id.to_string());

    let mut request = client.get(url).header(ACCEPT, "application/json");
    request = apply_auth(request, auth);

    let response = request.send().context("failed to query job status")?;
    let status = response.status();
    let text = response
        .text()
        .context("failed to read job status response body")?;

    if !status.is_success() {
        bail!("TrueNAS API error ({}): {}", status, text.trim());
    }

    parse_job_response(&text, job_id)
}

fn parse_job_response(text: &str, job_id: i64) -> Result<JobInfo> {
    let trimmed = text.trim();
    let value: Value = serde_json::from_str(trimmed)
        .with_context(|| format!("failed to parse job status: {}", trimmed))?;

    if let Some(job) = extract_job(&value, job_id) {
        return Ok(job);
    }

    bail!("job {} not found in response", job_id);
}

fn extract_job(value: &Value, job_id: i64) -> Option<JobInfo> {
    match value {
        Value::Array(items) => items
            .iter()
            .find_map(|item| parse_job_info(item).filter(|j| j.id == job_id)),
        Value::Object(_) => parse_job_info(value).filter(|j| j.id == job_id),
        _ => None,
    }
}

fn parse_job_info(value: &Value) -> Option<JobInfo> {
    let obj = value.as_object()?;
    let id = obj.get("id")?.as_i64()?;
    let state = obj
        .get("state")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let error = obj
        .get("error")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let exception = obj
        .get("exception")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let (progress_percent, progress_description) = obj
        .get("progress")
        .and_then(|v| v.as_object())
        .map(|progress| {
            let percent = progress.get("percent").and_then(|v| v.as_f64());
            let desc = progress
                .get("description")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            (percent, desc)
        })
        .unwrap_or((None, None));

    Some(JobInfo {
        id,
        state,
        error,
        exception,
        progress_percent,
        progress_description,
    })
}
