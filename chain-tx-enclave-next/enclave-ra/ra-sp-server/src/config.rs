use structopt::StructOpt;

/// Configuration required by SP for remote attestation
#[derive(Debug, StructOpt)]
pub struct SpRaConfig {
    /// TCP address of SP server
    #[structopt(
        short = "a",
        long = "address",
        help = "TCP address of SP server (default: `0.0.0.0:8989`)",
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
        possible_values = &["Linkable", "Unlinkable"],
        case_insensitive = false
    )]
    pub quote_type: String,
    /// Base URI of intel attestation service (IAS)
    #[structopt(
        long = "ias-base-uri",
        help = "Base URI of intel attestation service (IAS) (default: `https://api.trustedservices.intel.com/sgx/dev`)",
        default_value = "https://api.trustedservices.intel.com/sgx/dev"
    )]
    pub ias_base_uri: String,
    /// API path to get SigRL from IAS
    #[structopt(
        long = "ias-sig-rl-path",
        help = "API path to get SigRL from IAS (default: `/attestation/v4/sigrl/`)",
        default_value = "/attestation/v4/sigrl/"
    )]
    pub ias_sig_rl_path: String,
    /// API path to get attestation report from IAS
    #[structopt(
        long = "ias-report-path",
        help = "API path to get attestation report from IAS (default: `/attestation/v4/report`)",
        default_value = "/attestation/v4/report"
    )]
    pub ias_report_path: String,
}
