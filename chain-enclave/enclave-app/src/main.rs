use std::io;
use std::net::TcpListener;

mod server;

fn main() -> io::Result<()> {
    // TODO: custom runner with args, TLS, remote attestation...
    for stream in TcpListener::bind("0.0.0.0:7878")?.incoming() {
        let mut stream = stream?;
        println!("Got connection! {:?}", stream);
        server::handle_stream(&mut stream);
    }
    Ok(())
}
