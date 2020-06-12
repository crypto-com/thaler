use crate::{gen_keypackage, verify_keypackage};
use client_common::{ErrorKind, Result, ResultExt};
use structopt::StructOpt;
#[derive(Debug, StructOpt)]
pub enum KeypackageCommand {
    #[structopt(name = "generate", about = "Generate key-package")]
    GenKeypackage {
        #[structopt(
            name = "Path to mls enclave",
            short = "p",
            long = "path",
            help = "Path to mls enclave  (e.g. mls.sgxs)"
        )]
        path: String,
        #[structopt(
            name = "Path to key-package",
            short = "o",
            long = "output",
            help = "Path to key-package  (e.g. key.txt)"
        )]
        output: String,
    },
    #[structopt(name = "verify", about = "Verify key-package")]
    VerifyKeypackage {
        #[structopt(
            name = "Path to base64 encoded keypackage",
            short = "p",
            long = "path",
            help = "Path to keypackage enclave which is base64 encoded"
        )]
        path: String,
    },
}

impl KeypackageCommand {
    pub fn execute(&self) -> Result<()> {
        match self {
            KeypackageCommand::GenKeypackage { path, output } => {
                let blob = gen_keypackage(&path)?;
                let encoded = base64::encode(&blob);
                std::fs::write(&output, &encoded)
                    .chain(|| (ErrorKind::IoError, "Cannot write encoded key-package"))?;
                Ok(())
            }
            KeypackageCommand::VerifyKeypackage { path } => {
                let contents = std::fs::read_to_string(&path)
                    .chain(|| (ErrorKind::IoError, "Unable to read keypackage"))?;
                let kp = base64::decode(&contents)
                    .chain(|| (ErrorKind::IoError, "Unable to parse keypackage"))?;
                verify_keypackage(&kp)?;
                Ok(())
            }
        }
    }
}
