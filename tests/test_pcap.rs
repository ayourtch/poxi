use scarust::Value::Random;
use scarust::*;
#[macro_use]
extern crate scarust_derive;

extern crate pcap_parser;
use std::fs::File;
use std::path::PathBuf;

use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::LegacyPcapReader;
use pcap_parser::*;

#[derive(FromStringHashmap, NetworkProtocol, Clone, Debug, Eq, PartialEq)]
pub struct testProto {
    #[nproto(default = 4, encode = Skip)]
    pub version: Value<u8>,
    pub tos: Value<u8>,
    pub mac1: Value<MacAddr>,
    #[nproto(default = Random)]
    pub mac2: Value<MacAddr>,
    #[nproto(default = "00:01:02:03:04:05")]
    pub mac3: Value<MacAddr>,
    #[nproto(default = Random)]
    pub id: Value<u16>,
}

fn get_pcap_path(name: &str) -> PathBuf {
    let mut path = PathBuf::from(file!());
    path.pop();
    path.pop();
    path.push("pcap");
    path.push(name);
    path
}

pub fn decode_pcap(pcapname: &str) -> Vec<LayerStack> {
    let path = get_pcap_path(pcapname);
    let file = File::open(path).expect("File open failed");
    let mut reader = LegacyPcapReader::new(65536, file).expect("LegacyPcapReader");
    let mut num_blocks = 0;
    let mut out: Vec<LayerStack> = vec![];
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                num_blocks += 1;

                match block {
                    PcapBlockOwned::LegacyHeader(_hdr) => {
                        // save hdr.network (linktype)
                    }
                    PcapBlockOwned::Legacy(b) => {
                        let p = Ether!().decode(&b.data).unwrap().0;
                        out.push(p);
                    }
                    PcapBlockOwned::NG(_) => unreachable!(),
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete) => {
                reader.refill().unwrap();
            }
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }
    out
}

#[test]
pub fn test_pcap1() {
    let packets = decode_pcap("pcap1.pcap");
    for p in packets {
        println!("p: {:?}", &p);
    }
}

#[test]
pub fn test_pcap2() {
    let packets = decode_pcap("pcap2.pcap");
    for p in packets {
        println!("p: {:?}", &p);
    }
}

#[test]
pub fn test_pcap3() {
    let packets = decode_pcap("pcap3.pcap");
    for p in packets {
        println!("p: {:?}", &p);
    }
}
