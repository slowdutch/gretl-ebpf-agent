/// HTTP reporter — batches events and flushes to the Gretl backend via OTLP.
/// Sends to:
///   POST {endpoint}/otlp/v1/events   — security + execve events
///   POST {endpoint}/otlp/v1/metrics  — CPU/memory metrics (OTLP JSON)

use anyhow::Result;
use reqwest::Client;
use serde::Serialize;
use std::time::Duration;

const FLUSH_INTERVAL: Duration = Duration::from_secs(15);
const MAX_BATCH: usize = 200;

#[derive(Debug, Clone, Serialize)]
pub struct SecurityEventPayload {
    pub cluster_id:    String,
    pub ts:            u64,   // unix ms
    pub namespace:     String,
    pub workload:      String,
    pub pod:           String,
    pub node:          String,
    pub event_type:    String,
    pub severity:      String,
    pub pid:           u32,
    pub process_name:  String,
    pub cmdline:       String,
    pub parent_process: String,
    pub remote_ip:     String,
    pub remote_port:   u16,
    pub local_port:    u16,
    pub protocol:      String,
    pub rule_id:       String,
    pub description:   String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricDataPoint {
    pub attributes:    Vec<OtlpAttr>,
    #[serde(rename = "timeUnixNano")]
    pub time_unix_nano: String,
    #[serde(rename = "asInt")]
    pub as_int:        u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct OtlpAttr {
    pub key:   String,
    pub value: OtlpAttrValue,
}

#[derive(Debug, Clone, Serialize)]
pub struct OtlpAttrValue {
    #[serde(rename = "stringValue")]
    pub string_value: String,
}

pub struct Reporter {
    client:   Client,
    endpoint: String,
    token:    String,
    events:   Vec<SecurityEventPayload>,
}

impl Reporter {
    pub fn new(endpoint: String, token: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("failed to build HTTP client");
        Self { client, endpoint, token, events: Vec::new() }
    }

    pub fn push_event(&mut self, ev: SecurityEventPayload) {
        self.events.push(ev);
        if self.events.len() >= MAX_BATCH {
            // Non-async fire-and-forget via blocking spawn
            let batch   = std::mem::take(&mut self.events);
            let client  = self.client.clone();
            let url     = format!("{}/otlp/v1/events", self.endpoint);
            let token   = self.token.clone();
            tokio::spawn(async move {
                let _ = post_json(&client, &url, &token, &batch).await;
            });
        }
    }

    pub async fn flush_events(&mut self) -> Result<()> {
        if self.events.is_empty() { return Ok(()); }
        let batch = std::mem::take(&mut self.events);
        let url   = format!("{}/otlp/v1/events", self.endpoint);
        post_json(&self.client, &url, &self.token, &batch).await
    }

    /// Send a simple CPU metrics payload in OTLP JSON format.
    pub async fn send_cpu_metrics(
        &self,
        server_id: &str,
        pid:       u32,
        process:   &str,
        cpu_mc:    u32,
        mem_mib:   u32,
        ts_ns:     u64,
    ) -> Result<()> {
        let attr = |k: &str, v: &str| OtlpAttr {
            key:   k.to_string(),
            value: OtlpAttrValue { string_value: v.to_string() },
        };

        let payload = serde_json::json!({
            "resourceMetrics": [{
                "resource": {
                    "attributes": [
                        attr("server.id",  server_id),
                    ]
                },
                "scopeMetrics": [{
                    "metrics": [
                        {
                            "name": "process.cpu.utilization",
                            "gauge": {
                                "dataPoints": [{
                                    "attributes": [
                                        attr("process.name", process),
                                        attr("process.pid", &pid.to_string()),
                                    ],
                                    "timeUnixNano": ts_ns.to_string(),
                                    "asDouble": cpu_mc as f64 / 1000.0,
                                }]
                            }
                        },
                        {
                            "name": "process.memory.usage",
                            "gauge": {
                                "dataPoints": [{
                                    "attributes": [
                                        attr("process.name", process),
                                        attr("process.pid", &pid.to_string()),
                                    ],
                                    "timeUnixNano": ts_ns.to_string(),
                                    "asInt": (mem_mib as u64 * 1024 * 1024).to_string(),
                                }]
                            }
                        }
                    ]
                }]
            }]
        });

        let url = format!("{}/otlp/v1/metrics", self.endpoint);
        post_json(&self.client, &url, &self.token, &payload).await
    }
}

async fn post_json<T: Serialize>(
    client: &Client,
    url:    &str,
    token:  &str,
    body:   &T,
) -> Result<()> {
    let res = client
        .post(url)
        .bearer_auth(token)
        .json(body)
        .send()
        .await?;

    if !res.status().is_success() {
        let status = res.status();
        let text   = res.text().await.unwrap_or_default();
        anyhow::bail!("POST {url} → {status}: {text}");
    }
    Ok(())
}
