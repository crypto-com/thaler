use std::ops::Deref;

use failure::Error;

use crate::{Secrets, Storage};

pub struct SecretsService(Storage);

impl SecretsService {
    pub fn new() -> Result<SecretsService, Error> {
        Ok(SecretsService(Storage::new()?))
    }

    pub fn generate(&self, name: &str, passphrase: &str) -> Result<(), Error> {
        let secrets = Secrets::generate()?;
        self.0.set(name, &secrets, passphrase)
    }
}

impl Deref for SecretsService {
    type Target = Storage;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
