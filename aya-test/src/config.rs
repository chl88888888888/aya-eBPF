//! Configuration via TOML file and CLI arguments.
//!
//! Priority: CLI arguments > config file > defaults.

use serde::Deserialize;


// TOML file schema


/// Top-level configuration, deserializable from TOML.
#[derive(Debug, Deserialize)]
pub struct ConfigFile {
    pub redis: Option<RedisSection>,
    pub sampling: Option<SamplingSection>,
    pub report: Option<ReportSection>,
    pub flamegraph: Option<FlamegraphSection>,
    pub output: Option<OutputSection>,
}

#[derive(Debug, Deserialize)]
pub struct RedisSection {
    pub pid_file: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SamplingSection {
    pub frequency_hz: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct ReportSection {
    pub interval_secs: Option<u64>,
    pub command_stats: Option<bool>,
    pub client_stats: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct FlamegraphSection {
    pub output: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OutputSection {
    pub file: Option<String>,
}


// Resolved configuration


/// Resolved configuration with all fields populated (no Options).
#[derive(Debug, Clone)]
pub struct Config {
    pub pid_file: String,
    pub frequency_hz: u64,
    pub interval_secs: u64,
    pub flamegraph_output: String,
    pub output_file: Option<String>,
    pub command_stats: bool,
    pub client_stats: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            pid_file: "/var/run/redis/redis.pid".into(),
            frequency_hz: 99,
            interval_secs: 10,
            flamegraph_output: "/tmp/redis_flamegraph.svg".into(),
            output_file: None,
            command_stats: true,
            client_stats: true,
        }
    }
}


// CLI (clap derive)


/// Command-line arguments.  All fields are optional; when `None` the
/// value is taken from the config file or the hard-coded default.
#[derive(clap::Parser)]
#[command(name = "aya-test", about = "Redis eBPF performance tracing")]
pub struct Cli {
    /// Path to Redis PID file
    #[arg(long)]
    pub pid_file: Option<String>,

    /// CPU sampling frequency in Hz (flame graph)
    #[arg(long)]
    pub frequency: Option<u64>,

    /// Statistics report interval in seconds
    #[arg(long)]
    pub interval: Option<u64>,

    /// Flame graph SVG output path
    #[arg(long)]
    pub flamegraph_output: Option<String>,

    /// Write all statistics output to this file (stdout otherwise)
    #[arg(long)]
    pub output: Option<String>,

    /// Disable per-command latency breakdown (reduces overhead)
    #[arg(long)]
    pub no_command_stats: bool,

    /// Disable per-client-IP statistics (reduces overhead)
    #[arg(long)]
    pub no_client_stats: bool,

    /// Path to TOML configuration file
    #[arg(long = "config", help = "Path to TOML configuration file")]
    pub config: Option<String>,
}


// Loader


impl Config {
    /// Load configuration from an optional TOML file, then overlay CLI
    /// arguments (which take highest priority).
    pub fn load(cli: &Cli) -> anyhow::Result<Self> {
        let mut cfg = Self::default();

        // Layer 1 — config file
        if let Some(path) = &cli.config {
            let content = std::fs::read_to_string(path)?;
            let file: ConfigFile = toml::from_str(&content)?;
            if let Some(r) = &file.redis {
                if let Some(v) = &r.pid_file {
                    cfg.pid_file = v.clone();
                }
            }
            if let Some(s) = &file.sampling {
                if let Some(v) = s.frequency_hz {
                    cfg.frequency_hz = v;
                }
            }
            if let Some(r) = &file.report {
                if let Some(v) = r.interval_secs {
                    cfg.interval_secs = v;
                }
                if let Some(v) = r.command_stats {
                    cfg.command_stats = v;
                }
                if let Some(v) = r.client_stats {
                    cfg.client_stats = v;
                }
            }
            if let Some(f) = &file.flamegraph {
                if let Some(v) = &f.output {
                    cfg.flamegraph_output = v.clone();
                }
            }
            if let Some(o) = &file.output {
                if let Some(v) = &o.file {
                    cfg.output_file = Some(v.clone());
                }
            }
        }

        // Layer 2 — CLI overrides (highest priority)
        if let Some(v) = &cli.pid_file {
            cfg.pid_file = v.clone();
        }
        if let Some(v) = cli.frequency {
            cfg.frequency_hz = v;
        }
        if let Some(v) = cli.interval {
            cfg.interval_secs = v;
        }
        if let Some(v) = &cli.flamegraph_output {
            cfg.flamegraph_output = v.clone();
        }
        if let Some(v) = &cli.output {
            cfg.output_file = Some(v.clone());
        }
        if cli.no_command_stats {
            cfg.command_stats = false;
        }
        if cli.no_client_stats {
            cfg.client_stats = false;
        }

        Ok(cfg)
    }
}
