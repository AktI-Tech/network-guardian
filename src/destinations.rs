//! Destination classifier for builder-workstation traffic (LLM, registries, cloud, LAN).

use crate::models::DestinationCategory;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct ClassifiedDestination {
    pub host_or_ip: String,
    pub category: DestinationCategory,
    pub label: Option<String>,
}

/// Known host suffixes and exact matches for common builder tooling.
/// Order: more specific suffixes first where it matters.
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
    ("cloudflare.com", DestinationCategory::Cloud, "Cloudflare"),
    ("microsoft.com", DestinationCategory::Cloud, "Microsoft"),
    (
        "visualstudio.com",
        DestinationCategory::Cloud,
        "Visual Studio",
    ),
    ("vscode.dev", DestinationCategory::Cloud, "VS Code"),
];

pub fn classify_ip(ip: IpAddr) -> ClassifiedDestination {
    let host = ip.to_string();
    if ip.is_loopback() {
        return ClassifiedDestination {
            host_or_ip: host,
            category: DestinationCategory::Localhost,
            label: Some("Loopback".into()),
        };
    }
    if is_private_or_link_local(ip) {
        return ClassifiedDestination {
            host_or_ip: host,
            category: DestinationCategory::Lan,
            label: Some("Private / LAN".into()),
        };
    }
    ClassifiedDestination {
        host_or_ip: host,
        category: DestinationCategory::Unknown,
        label: None,
    }
}

pub fn classify_host(host: &str) -> ClassifiedDestination {
    let lower = host.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return ClassifiedDestination {
            host_or_ip: host.to_string(),
            category: DestinationCategory::Unknown,
            label: None,
        };
    }

    if let Ok(ip) = lower.parse::<IpAddr>() {
        return classify_ip(ip);
    }

    for (suffix, category, label) in HOST_RULES {
        if host_matches(&lower, suffix) {
            return ClassifiedDestination {
                host_or_ip: lower,
                category: category.clone(),
                label: Some((*label).to_string()),
            };
        }
    }

    ClassifiedDestination {
        host_or_ip: lower,
        category: DestinationCategory::Unknown,
        label: None,
    }
}

fn host_matches(host: &str, rule: &str) -> bool {
    host == rule || host.ends_with(&format!(".{}", rule))
}

fn is_private_or_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_link_local()
                // CGNAT 100.64.0.0/10
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0b1100_0000) == 0b0100_0000)
        }
        IpAddr::V6(v6) => {
            // fc00::/7 unique local and fe80::/10 link-local (stable APIs only)
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
    fn unknown_public() {
        let c = classify_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(c.category, DestinationCategory::Unknown);
    }
}
