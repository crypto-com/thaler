use structopt::StructOpt;

/// Configuration required by SP for remote attestation
#[derive(Debug, StructOpt)]
pub struct SpRaConfig {
    /// IAS API key
    #[structopt(
        short = "a",
        long = "address",
        help = "TCP address of SP serder (default: `0.0.0.0:8989`)",
        default_value = "0.0.0.0:8989"
    )]
    pub address: String,
    /// IAS API key
    #[structopt(
        short = "i",
        long = "ias-key",
        help = "IAS API Key",
        env = "IAS_KEY",
        hide_env_values = true
    )]
    pub ias_key: String,
    /// SPID
    #[structopt(
        short = "s",
        long = "spid",
        help = "SPID",
        env = "SPID",
        hide_env_values = true
    )]
    pub spid: String,
    /// Quote type (possible values: `Linkable` or `Unlinkable`)
    #[structopt(
        short = "q",
        long = "quote-type",
        help = "Quote type",
        possible_values = &["linkable", "unlinkable"],
        case_insensitive = true
    )]
    pub quote_type: String,
}
