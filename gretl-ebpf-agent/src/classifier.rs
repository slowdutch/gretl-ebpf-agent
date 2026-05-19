/// Agent type classification from process name + argv.
/// Returns Some("langgraph") etc. if the process looks like a known AI agent framework.

pub fn classify_agent(comm: &str, filename: &str, argv1: &str) -> Option<&'static str> {
    let comm     = comm.trim_matches('\0').to_lowercase();
    let filename = filename.trim_matches('\0').to_lowercase();
    let argv1    = argv1.trim_matches('\0').to_lowercase();

    // vLLM inference server
    if comm.contains("vllm") || filename.contains("vllm") || argv1.contains("vllm") {
        return Some("vllm");
    }

    // Ollama
    if comm == "ollama" || filename.ends_with("/ollama") {
        return Some("ollama");
    }

    // Ray (distributed agent workloads)
    if comm.starts_with("ray::") || comm == "raylet" || filename.contains("/ray/") {
        return Some("ray");
    }

    // LangGraph / LangChain
    if argv1.contains("langgraph") || argv1.contains("langchain") || filename.contains("langgraph") {
        return Some("langgraph");
    }

    // CrewAI
    if argv1.contains("crewai") || filename.contains("crewai") {
        return Some("crewai");
    }

    // Python running a file that looks like an agent entrypoint
    if (comm == "python" || comm == "python3") && (
        argv1.contains("agent") || argv1.contains("worker") || argv1.contains("serve")
    ) {
        return Some("custom");
    }

    // Node.js running an agent-looking script
    if comm == "node" && (
        argv1.contains("agent") || argv1.contains("worker")
    ) {
        return Some("custom");
    }

    None
}

/// Returns true if this process spawn looks security-relevant.
/// Events that pass this check are forwarded to the security audit log.
pub fn is_security_relevant(comm: &str, filename: &str, uid: u32) -> Option<SecurityHint> {
    let comm     = comm.trim_matches('\0');
    let filename = filename.trim_matches('\0');

    // Shells spawned inside a container by non-root are often breakout attempts
    if uid != 0 && matches!(comm, "bash" | "sh" | "zsh" | "dash" | "ash") {
        return Some(SecurityHint {
            event_type: "unusual_process",
            severity: "warn",
            rule_id: "SHELL_SPAWN_NONROOT",
            description: "Shell spawned by non-root process",
        });
    }

    // Network scanning / recon tools
    if matches!(comm, "nmap" | "masscan" | "netcat" | "nc" | "ncat" | "socat") {
        return Some(SecurityHint {
            event_type: "unusual_process",
            severity: "critical",
            rule_id: "NETWORK_TOOL_EXEC",
            description: "Network scanning tool executed",
        });
    }

    // Credential dumpers
    if matches!(comm, "mimikatz" | "secretsdump" | "john" | "hashcat") {
        return Some(SecurityHint {
            event_type: "unusual_process",
            severity: "critical",
            rule_id: "CREDENTIAL_TOOL_EXEC",
            description: "Credential access tool executed",
        });
    }

    // Privilege escalation attempts
    if matches!(filename, "/usr/bin/sudo" | "/bin/su" | "/usr/bin/su") && uid != 0 {
        return Some(SecurityHint {
            event_type: "privilege_change",
            severity: "warn",
            rule_id: "SUDO_EXEC",
            description: "Privilege escalation via sudo/su",
        });
    }

    // Package managers inside running containers — unusual, may indicate supply-chain attack
    if matches!(comm, "apt" | "apt-get" | "yum" | "dnf" | "pip" | "npm" | "pip3") {
        return Some(SecurityHint {
            event_type: "unusual_process",
            severity: "info",
            rule_id: "PKG_MANAGER_EXEC",
            description: "Package manager executed at runtime",
        });
    }

    None
}

#[derive(Debug, Clone)]
pub struct SecurityHint {
    pub event_type:  &'static str,
    pub severity:    &'static str,
    pub rule_id:     &'static str,
    pub description: &'static str,
}
