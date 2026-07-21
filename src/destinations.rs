//! Destination classifier for builder-workstation traffic (LLM, registries, cloud, LAN).

use crate::models::DestinationCategory;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ClassifiedDestination {
    pub host_or_ip: String,
    pub category: DestinationCategory,
    pub label: Option<String>,
    pub resolved_host: Option<String>,
}

/// Known host suffixes and exact matches for common builder tooling.
const HOST_RULES: &[(&str, DestinationCategory, &str)] = &[
    // LLM / AI APIs
    ("api.openai.com", DestinationCategory::Llm, "OpenAI API"),
    ("openai.com", DestinationCategory::Llm, "OpenAI"),
    (
        "api.anthropic.com",
        DestinationCategory::Llm,
        "Anthropic API",
    ),
    ("anthropic.com", DestinationCategory::Llm, "Anthropic"),
    (
        "generativelanguage.googleapis.com",
        DestinationCategory::Llm,
        "Google Gemini",
    ),
    ("api.cohere.ai", DestinationCategory::Llm, "Cohere"),
    ("api.groq.com", DestinationCategory::Llm, "Groq"),
    ("api.x.ai", DestinationCategory::Llm, "xAI"),
    ("x.ai", DestinationCategory::Llm, "xAI"),
    ("api.mistral.ai", DestinationCategory::Llm, "Mistral"),
    ("huggingface.co", DestinationCategory::Llm, "Hugging Face"),
    ("hf.co", DestinationCategory::Llm, "Hugging Face"),
    ("ollama.com", DestinationCategory::Llm, "Ollama"),
    ("openrouter.ai", DestinationCategory::Llm, "OpenRouter"),
    ("api.together.xyz", DestinationCategory::Llm, "Together AI"),
    ("api.perplexity.ai", DestinationCategory::Llm, "Perplexity"),
    ("cursor.sh", DestinationCategory::Llm, "Cursor"),
    ("cursor.com", DestinationCategory::Llm, "Cursor"),
    ("grok.x.ai", DestinationCategory::Llm, "Grok / xAI"),
    // Package registries
    ("registry.npmjs.org", DestinationCategory::Registry, "npm"),
    ("npmjs.org", DestinationCategory::Registry, "npm"),
    (
        "registry.yarnpkg.com",
        DestinationCategory::Registry,
        "Yarn",
    ),
    ("pypi.org", DestinationCategory::Registry, "PyPI"),
    (
        "files.pythonhosted.org",
        DestinationCategory::Registry,
        "PyPI files",
    ),
    ("crates.io", DestinationCategory::Registry, "crates.io"),
    (
        "static.crates.io",
        DestinationCategory::Registry,
        "crates.io static",
    ),
    (
        "index.crates.io",
        DestinationCategory::Registry,
        "crates.io index",
    ),
    (
        "proxy.golang.org",
        DestinationCategory::Registry,
        "Go modules",
    ),
    (
        "sum.golang.org",
        DestinationCategory::Registry,
        "Go checksums",
    ),
    (
        "repo.maven.apache.org",
        DestinationCategory::Registry,
        "Maven Central",
    ),
    ("rubygems.org", DestinationCategory::Registry, "RubyGems"),
    // Cloud / dev platforms
    ("github.com", DestinationCategory::Cloud, "GitHub"),
    (
        "githubusercontent.com",
        DestinationCategory::Cloud,
        "GitHub content",
    ),
    ("gitlab.com", DestinationCategory::Cloud, "GitLab"),
    ("bitbucket.org", DestinationCategory::Cloud, "Bitbucket"),
    ("docker.io", DestinationCategory::Cloud, "Docker Hub"),
    ("docker.com", DestinationCategory::Cloud, "Docker"),
    (
        "ghcr.io",
        DestinationCategory::Cloud,
        "GitHub Container Registry",
    ),
    (
        "azurecr.io",
        DestinationCategory::Cloud,
        "Azure Container Registry",
    ),
    ("amazonaws.com", DestinationCategory::Cloud, "AWS"),
    ("azure.com", DestinationCategory::Cloud, "Azure"),
    ("googleapis.com", DestinationCategory::Cloud, "Google APIs"),
    ("gstatic.com", DestinationCategory::Cloud, "Google static"),
    ("google.com", DestinationCategory::Cloud, "Google"),
    ("1e100.net", DestinationCategory::Cloud, "Google"),
    (
        "googlevideo.com",
        DestinationCategory::Cloud,
        "YouTube / Google",
    ),
    ("cloudflare.com", DestinationCategory::Cloud, "Cloudflare"),
    (
        "cloudflaressl.com",
        DestinationCategory::Cloud,
        "Cloudflare",
    ),
    (
        "cloudflare-dns.com",
        DestinationCategory::Cloud,
        "Cloudflare DNS",
    ),
    ("microsoft.com", DestinationCategory::Cloud, "Microsoft"),
    (
        "microsoftonline.com",
        DestinationCategory::Cloud,
        "Microsoft login",
    ),
    (
        "visualstudio.com",
        DestinationCategory::Cloud,
        "Visual Studio",
    ),
    ("vscode.dev", DestinationCategory::Cloud, "VS Code"),
    ("office.com", DestinationCategory::Cloud, "Microsoft 365"),
    ("live.com", DestinationCategory::Cloud, "Microsoft Live"),
];

/// Well-known local builder ports (even on loopback).
fn local_service_label(port: u16) -> Option<(&'static str, DestinationCategory)> {
    match port {
        11434 => Some(("Ollama (local)", DestinationCategory::Llm)),
        1234 => Some(("LM Studio? (local)", DestinationCategory::Llm)),
        5678 => Some(("n8n? (local)", DestinationCategory::Cloud)),
        3000 | 5173 | 8080 | 8888 => Some(("Local dev server", DestinationCategory::Localhost)),
        _ => None,
    }
}

struct DnsCacheEntry {
    host: Option<String>,
    at: Instant,
}

fn dns_cache() -> &'static Mutex<HashMap<IpAddr, DnsCacheEntry>> {
    static CACHE: OnceLock<Mutex<HashMap<IpAddr, DnsCacheEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

const DNS_TTL: Duration = Duration::from_secs(600);
const DNS_NEG_TTL: Duration = Duration::from_secs(120);

/// Reverse DNS with TTL cache. Returns lowercase hostname when available.
pub fn reverse_dns_cached(ip: IpAddr) -> Option<String> {
    {
        let cache = dns_cache().lock();
        if let Some(entry) = cache.get(&ip) {
            let ttl = if entry.host.is_some() {
                DNS_TTL
            } else {
                DNS_NEG_TTL
            };
            if entry.at.elapsed() < ttl {
                return entry.host.clone();
            }
        }
    }

    let host = dns_lookup::lookup_addr(&ip)
        .ok()
        .map(|h| h.trim_end_matches('.').to_ascii_lowercase());

    dns_cache().lock().insert(
        ip,
        DnsCacheEntry {
            host: host.clone(),
            at: Instant::now(),
        },
    );
    host
}

pub fn classify_ip(ip: IpAddr) -> ClassifiedDestination {
    classify_ip_with_context(ip, None, false)
}

/// Classify an IP, optionally using reverse DNS and remote port context.
pub fn classify_ip_with_context(
    ip: IpAddr,
    remote_port: Option<u16>,
    do_reverse_dns: bool,
) -> ClassifiedDestination {
    let host_or_ip = ip.to_string();

    if ip.is_loopback() {
        if let Some(port) = remote_port {
            if let Some((label, category)) = local_service_label(port) {
                return ClassifiedDestination {
                    host_or_ip,
                    category,
                    label: Some(label.into()),
                    resolved_host: Some("localhost".into()),
                };
            }
        }
        return ClassifiedDestination {
            host_or_ip,
            category: DestinationCategory::Localhost,
            label: Some("Loopback".into()),
            resolved_host: Some("localhost".into()),
        };
    }

    if is_private_or_link_local(ip) {
        return ClassifiedDestination {
            host_or_ip,
            category: DestinationCategory::Lan,
            label: Some("Private / LAN".into()),
            resolved_host: None,
        };
    }

    let resolved = if do_reverse_dns {
        reverse_dns_cached(ip)
    } else {
        None
    };

    if let Some(ref hostname) = resolved {
        let by_host = classify_host(hostname);
        if by_host.category != DestinationCategory::Unknown {
            return ClassifiedDestination {
                host_or_ip,
                category: by_host.category,
                label: by_host.label,
                resolved_host: resolved,
            };
        }
        // Hostname known but not in catalog — still attach it for UI
        return ClassifiedDestination {
            host_or_ip,
            category: DestinationCategory::Unknown,
            label: None,
            resolved_host: resolved,
        };
    }

    ClassifiedDestination {
        host_or_ip,
        category: DestinationCategory::Unknown,
        label: None,
        resolved_host: None,
    }
}

pub fn classify_host(host: &str) -> ClassifiedDestination {
    let lower = host.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return ClassifiedDestination {
            host_or_ip: host.to_string(),
            category: DestinationCategory::Unknown,
            label: None,
            resolved_host: None,
        };
    }

    if let Ok(ip) = lower.parse::<IpAddr>() {
        return classify_ip(ip);
    }

    for (suffix, category, label) in HOST_RULES {
        if host_matches(&lower, suffix) {
            return ClassifiedDestination {
                host_or_ip: lower.clone(),
                category: category.clone(),
                label: Some((*label).to_string()),
                resolved_host: Some(lower),
            };
        }
    }

    ClassifiedDestination {
        host_or_ip: lower,
        category: DestinationCategory::Unknown,
        label: None,
        resolved_host: None,
    }
}

/// Boost category using process context (e.g. ollama → LLM).
pub fn apply_process_boost(
    mut classified: ClassifiedDestination,
    process_name: Option<&str>,
    stack_hint: Option<&str>,
) -> ClassifiedDestination {
    let proc = process_name.unwrap_or("").to_ascii_lowercase();
    if (stack_hint == Some("llm-local")
        || proc.contains("ollama")
        || proc.contains("lmstudio")
        || proc.contains("llama"))
        && (classified.category == DestinationCategory::Localhost
            || classified.category == DestinationCategory::Lan
            || classified.category == DestinationCategory::Unknown)
    {
        classified.category = DestinationCategory::Llm;
        if classified.label.is_none() {
            classified.label = Some("Local / process LLM".into());
        }
    }
    classified
}

fn host_matches(host: &str, rule: &str) -> bool {
    host == rule || host.ends_with(&format!(".{rule}"))
}

fn is_private_or_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_link_local()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0b1100_0000) == 0b0100_0000)
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            let unique_local = (segments[0] & 0xfe00) == 0xfc00;
            let link_local = (segments[0] & 0xffc0) == 0xfe80;
            unique_local
                || link_local
                || v6
                    .to_ipv4_mapped()
                    .map(|v4| is_private_or_link_local(IpAddr::V4(v4)))
                    .unwrap_or(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn classifies_openai() {
        let c = classify_host("api.openai.com");
        assert_eq!(c.category, DestinationCategory::Llm);
        assert!(c.label.as_deref().unwrap_or("").contains("OpenAI"));
    }

    #[test]
    fn classifies_npm_subdomain() {
        let c = classify_host("registry.npmjs.org");
        assert_eq!(c.category, DestinationCategory::Registry);
    }

    #[test]
    fn classifies_lan() {
        let c = classify_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(c.category, DestinationCategory::Lan);
    }

    #[test]
    fn classifies_loopback() {
        let c = classify_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(c.category, DestinationCategory::Localhost);
    }

    #[test]
    fn classifies_local_ollama_port() {
        let c = classify_ip_with_context(IpAddr::V4(Ipv4Addr::LOCALHOST), Some(11434), false);
        assert_eq!(c.category, DestinationCategory::Llm);
    }

    #[test]
    fn unknown_public() {
        let c = classify_ip_with_context(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), Some(443), false);
        assert_eq!(c.category, DestinationCategory::Unknown);
    }

    #[test]
    fn process_boost_ollama() {
        let base = classify_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let boosted = apply_process_boost(base, Some("ollama.exe"), Some("llm-local"));
        assert_eq!(boosted.category, DestinationCategory::Llm);
    }

    #[test]
    fn reverse_dns_google_public() {
        // Best-effort; CI/network may block — only assert no panic.
        let _ = reverse_dns_cached(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    }
}
