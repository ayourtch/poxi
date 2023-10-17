use scarust::Value::Random;
use scarust::*;
#[macro_use]
extern crate scarust_derive;

use scarust::protocols::all::*;
use scarust::protocols::pcap_file::*;

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

fn get_file_as_byte_vec(filename: &str) -> Vec<u8> {
    use std::fs::File;
    use std::io::Read;
    let mut f = File::open(&filename).expect("no file found");
    let metadata = std::fs::metadata(&filename).expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");

    buffer
}

fn read_pcap_bytes(name: &str) -> Vec<u8> {
    let path = get_pcap_path(name);
    get_file_as_byte_vec(path.to_str().unwrap())
}

pub fn read_pcap(pcapname: &str) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = vec![];
    let path = get_pcap_path(pcapname);
    let file = File::open(path).expect("File open failed");
    let mut reader = LegacyPcapReader::new(65536, file).expect("LegacyPcapReader");
    let mut num_blocks = 0;
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                num_blocks += 1;

                match block {
                    PcapBlockOwned::LegacyHeader(_hdr) => {
                        // save hdr.network (linktype)
                    }
                    PcapBlockOwned::Legacy(b) => {
                        out.push(b.data.to_vec());
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

pub fn decode_pcap(pcapname: &str) -> Vec<LayerStack> {
    let d = read_pcap(pcapname);
    d.into_iter()
        .map(|x| Ether!().decode(&x).unwrap().0)
        .collect()
}

#[test]
pub fn test_read_pcap_bytes() {
    let bytes = read_pcap_bytes("pcap_3pkts.pcap");
    println!("Bytes: {:02x?}", &bytes);
    let pcap = PcapFile!().decode(&bytes).unwrap().0;
    println!("Pcap: {:#02x?}", &pcap);
}
