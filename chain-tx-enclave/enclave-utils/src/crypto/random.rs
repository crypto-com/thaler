use ring::rand::SystemRandom;

pub struct RandomState {
    inner: SystemRandom,
}

impl RandomState {
    pub fn new() -> Self {
        Self {
            inner: SystemRandom::new(),
        }
    }

    pub fn as_ref(&self) -> &SystemRandom {
        &self.inner
    }
}
