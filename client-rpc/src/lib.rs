mod program;
/// Used by c api
pub mod rpc;
mod server;

pub fn run() {
    crate::program::run_electron();
}
