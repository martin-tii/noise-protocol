#![cfg_attr(
    not(any(feature = "default-resolver", feature = "ring-accelerated",)),
    allow(dead_code, unused_extern_crates, unused_imports)
)]
//! This is a barebones TCP Client/Server that establishes a `Noise_XX` session, and sends
//! an important message across the wire.
//!
//! # Usage
//! Run the server a-like-a-so `cargo run -- -s true`, then run the client
//! as `cargo run -- -i 127.0.0.1` to see the magic happen.
//! 


//extern crate hex;
use hex;

use colored::Colorize;

//extern crate blake2;
use blake2::Blake2b512;


// extern crate sha2;
use sha2::{Digest, Sha256};

use rand::RngCore;

use rand::rngs::OsRng;
use lazy_static::lazy_static;
use clap::{Command, ArgAction, Arg};
use snow::{params::NoiseParams, Builder};
use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    fs::File,
    error::Error,
    convert::TryInto,
};

// extern crate rustls;
use rustls::Certificate;



static SECRET: &[u8] = b"i don't care for fidget spinners";
lazy_static! {
    static ref PARAMS: NoiseParams = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
}

// #[cfg(any(feature = "default-resolver", feature = "ring-accelerated"))]
fn main() {
    let matches = Command::new("example")
        .arg(Arg::new("server")
            .short('s')
            .long("server")
            .help("Server mode")
        )
        .arg(Arg::new("ipaddress")
            .short('i')
            .long("ipaddress")
            .help("IP address")
            .value_name("127.0.0.1")
            .action(ArgAction::Set)
        )
        .get_matches();


    if matches.contains_id("server") {
        run_server("../../root_cert.pem");
    } else {
        let ip_address = matches.get_one::<String>("ipaddress").unwrap();
        println!("Connecting to: {}", ip_address);
        run_client(ip_address, "../../root_cert.pem");
    }
    println!("all done.");
}

// #[cfg(any(feature = "default-resolver", feature = "ring-accelerated"))]
fn run_server(certificate: &str) {
    let mut buf = vec![0u8; 65535];

    // Initialize our responder using a builder.
    let builder: Builder<'_> = Builder::new(PARAMS.clone());
    let static_key = builder.generate_keypair().unwrap().private;
    let mut noise =
        builder.local_private_key(&static_key).psk(3, SECRET).build_responder().unwrap();

    // Wait on our client's arrival...
    println!("listening on 127.0.0.1:9999");
    let (mut stream, _) = TcpListener::bind("127.0.0.1:9999").unwrap().accept().unwrap();

    // <- e
    noise.read_message(&recv(&mut stream).unwrap(), &mut buf).unwrap();

    // -> e, ee, s, es
    let len = noise.write_message(&[0u8; 0], &mut buf).unwrap();
    send(&mut stream, &buf[..len]);

    // <- s, se
    noise.read_message(&recv(&mut stream).unwrap(), &mut buf).unwrap();

    // Transition the state machine into transport mode now that the handshake is complete.
    let mut noise = noise.into_transport_mode().unwrap();
    let nonce = generate_nonce();

    let nonce_bytes: &[u8] = &nonce;
    // lets send the nonce
    let len = noise.write_message(nonce_bytes, &mut buf).unwrap();
    send(&mut stream, &buf[..len]);

    println!("here.");

    while let Ok(msg) = recv(&mut stream) {
        println!("here now");

        let len = noise.read_message(&msg, &mut buf).unwrap();
        println!("client said: {}", String::from_utf8_lossy(&buf[..len]));
        let message: [u8; 16] = buf[..len].try_into().unwrap();
        let _ = validate_message(message, &nonce, &certificate);
    }
    println!("connection closed.");
}

// #[cfg(any(feature = "default-resolver", feature = "ring-accelerated"))]
fn run_client(ip_address: &str, certificate: &str) {
    let mut buf = vec![0u8; 65535];

    // Initialize our initiator using a builder.
    let builder: Builder<'_> = Builder::new(PARAMS.clone());
    let static_key = builder.generate_keypair().unwrap().private;
    let mut noise =
        builder.local_private_key(&static_key).psk(3, SECRET).build_initiator().unwrap();

    // Connect to our server, which is hopefully listening.
    let mut stream = TcpStream::connect(ip_address.to_owned()+":9999").unwrap();
    println!("connected...");

    // -> e
    let len = noise.write_message(&[], &mut buf).unwrap();
    send(&mut stream, &buf[..len]);

    // <- e, ee, s, es
    noise.read_message(&recv(&mut stream).unwrap(), &mut buf).unwrap();

    // -> s, se
    let len = noise.write_message(&[], &mut buf).unwrap();
    send(&mut stream, &buf[..len]);

    let mut noise = noise.into_transport_mode().unwrap();
    println!("session established...");


    while let Ok(msg) = recv(&mut stream) {
        let len = noise.read_message(&msg, &mut buf).unwrap();
        let received_nonce: [u8; 16] = buf[..len].try_into().unwrap();
        let nonce = u128::from_le_bytes(received_nonce);
        println!("received nonce: {}",nonce);
        let nonce_result = challenge(&received_nonce, certificate).unwrap();
        let nonce_bytes: &[u8] = nonce_result.as_ref();
        let len = noise.write_message(nonce_bytes, &mut buf).unwrap();
        send(&mut stream, &buf[..len]);
    }

    // // send 10 different messages
    // for _ in 0..10 {
    //     let mut user_input = String::new();
    //     let stdin = io::stdin(); // We get `Stdin` here.
    //     stdin.read_line(&mut user_input);
    //     let len = noise.write_message(user_input.as_bytes(), &mut buf).unwrap();
    //     send(&mut stream, &buf[..len]);
    // }
}

/// Hyper-basic stream transport receiver. 16-bit BE size followed by payload.
fn recv(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut msg_len_buf = [0u8; 2];
    stream.read_exact(&mut msg_len_buf)?;
    let msg_len = ((msg_len_buf[0] as usize) << 8) + (msg_len_buf[1] as usize);
    let mut msg = vec![0u8; msg_len];
    stream.read_exact(&mut msg[..])?;
    Ok(msg)
}

/// Hyper-basic stream transport sender. 16-bit BE size followed by payload.
fn send(stream: &mut TcpStream, buf: &[u8]) {
    let msg_len_buf = [(buf.len() >> 8) as u8, (buf.len() & 0xff) as u8];
    stream.write_all(&msg_len_buf).unwrap();
    stream.write_all(buf).unwrap();
}



fn generate_nonce() -> [u8; 16] {    let mut rng = OsRng;
    let mut nonce_bytes = [0u8; 16];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = u128::from_le_bytes(nonce_bytes);
    println!("Nonce Value: {}", nonce);
    nonce_bytes
}



fn load_cert(root_cert: &str) -> Result<Certificate, Box<dyn Error>> {
    // Read the root certificate file
    let mut file = File::open(root_cert)?;
    let mut cert_data = vec![];
    file.read_to_end(&mut cert_data)?;

    // Parse the certificate
    let cert = Certificate(cert_data);

    Ok(cert)
}

fn calculate_fingerprint(cert: &Certificate) -> Result<String, Box<dyn Error>> {
    let cert_data = &cert.0;
    let fingerprint = Sha256::digest(cert_data);
    Ok(hex::encode(fingerprint))
}


fn challenge(nonce: &[u8], certificate: &str) -> Result<[u8; 16], Box<dyn Error>> {
    let expected_cert = load_cert(certificate)?;
    let fingerprint = calculate_fingerprint(&expected_cert)?;
    let mut gfg = Blake2b512::new();
    gfg.update(fingerprint.as_bytes());
    gfg.update(nonce);

    let result: [u8; 64] = gfg.finalize().into();
    let response = hex::encode(result);
    println!("Response: {}",response);

    // Convert the result to [u8; 16]
    let mut nonce_result = [0u8; 16];
    nonce_result.copy_from_slice(&result[..16]);

    Ok(nonce_result)
}

fn validate_message(message: [u8; 16], my_nonce: &[u8], certificate: &str) -> Result<bool, Box<dyn Error>> {
    let computed_digest = challenge(my_nonce, certificate)?;
    if message != computed_digest {
        println!("{}", "Not Valid Client Certificate".red());
        return Ok(false);
    } else {
        println!("{}", "Valid Response".green());
        return Ok(true);
    }
}

// #[cfg(not(any(feature = "default-resolver", feature = "ring-accelerated")))]
// fn main() {
//     panic!("Example must be compiled with some cryptographic provider.");
// }