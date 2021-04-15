use clap::Clap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::IpAddress;
use smoltcp::wire::IpCidr;
use smoltcp::wire::{EthernetFrame, PrettyPrinter};
use smoltcp::wire::{IpEndpoint, IpProtocol, IpRepr, UdpRepr};
use std::str::FromStr;

extern crate pest;
#[macro_use]
extern crate pest_derive;

use pest::Parser;

#[derive(Parser)]
#[grammar = "packets-def.pest"]
pub struct PacketsDefParser;

/// This program does something useful, but its author needs to edit this.
/// Else it will be just hanging around forever
#[derive(Debug, Clone, Clap, Serialize, Deserialize)]
#[clap(version = env!("GIT_VERSION"), author = "Andrew Yourtchenko <ayourtch@gmail.com>")]
struct Opts {
    /// Target hostname to do things on
    #[clap(short, long, default_value = "localhost")]
    target_host: String,

    /// Override options from this yaml/json file
    #[clap(short, long)]
    options_override: Option<String>,

    /// packet definition file
    #[clap(short, long)]
    input_filename: Option<String>,

    /// A level of verbosity, and can be used multiple times
    #[clap(short, long, parse(from_occurrences))]
    verbose: i32,
}

fn main() {
    let opts: Opts = Opts::parse();

    // allow to load the options, so far there is no good built-in way
    let opts = if let Some(fname) = &opts.options_override {
        if let Ok(data) = std::fs::read_to_string(&fname) {
            let res = serde_json::from_str(&data);
            if res.is_ok() {
                res.unwrap()
            } else {
                serde_yaml::from_str(&data).unwrap()
            }
        } else {
            opts
        }
    } else {
        opts
    };

    if opts.verbose > 4 {
        let data = serde_json::to_string_pretty(&opts).unwrap();
        println!("{}", data);
        println!("===========");
        let data = serde_yaml::to_string(&opts).unwrap();
        println!("{}", data);
    }

    println!("Hello, here is your options: {:#?}", &opts);
    let udp_repr = UdpRepr {
        src_port: 12345,
        dst_port: 53,
        payload: &[0xaa; 5],
    };

    let ip_repr = IpRepr::Unspecified {
        src_addr: IpAddress::from_str("192.0.2.1").unwrap(),
        dst_addr: IpAddress::from_str("192.0.2.2").unwrap(),
        protocol: IpProtocol::Udp,
        payload_len: udp_repr.buffer_len(),
        hop_limit: 0x40,
    };

    let mut out: Vec<u8> = vec![0; 1000];

    let ip_repr = ip_repr
        .lower(&[IpCidr::new(IpAddress::from_str("192.0.2.1").unwrap(), 24)])
        .unwrap();

    ip_repr.emit(&mut out, &ChecksumCapabilities::ignored());

    println!("IP: {:0x?}", &out);

    if let Some(fname) = opts.input_filename {
        if let Ok(data) = std::fs::read_to_string(&fname) {
            let mut pairs = PacketsDefParser::parse(Rule::packets_def, &data)
                .unwrap_or_else(|e| panic!("{}", e));
            println!("{:#?}", pairs);

            let pairs = pairs.nth(0).unwrap().into_inner();

            for pair in pairs {
                // A pair is a combination of the rule which matched and a span of input
                println!("Rule:    {:?}", pair.as_rule());
                println!("Span:    {:?}", pair.as_span());
                println!("Text:    {}", pair.as_str());

                // A pair can be converted to an iterator of the tokens which make it up:
                for inner_pair in pair.into_inner() {
                    match inner_pair.as_rule() {
                        x => println!("x: {:?}", x),
                    };
                }
            }
        }
    }

    std::thread::sleep(std::time::Duration::from_secs(1));
}
