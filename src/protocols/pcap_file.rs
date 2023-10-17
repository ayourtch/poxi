use crate::encdec::binary_little_endian::BinaryLittleEndian;
use crate::*;

/*
 * This is a toy pcap encoder/decoder
 */

fn encode_data<E: Encoder>(
    me: &pcapFile,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let mut out: Vec<u8> = vec![];
    me.d.encode_with_encoder::<BinaryLittleEndian>(stack, my_index, encoded_layers)
}

fn decode_data<D: Decoder>(buf: &[u8], me: &mut pcapFile) -> Option<(pcapFileData, usize)> {
    let mut vp: Vec<pcapPacket> = vec![];
    let mut ci = 0;

    let dec = match me.magic_number.value() {
        0xa1b2c3d4 => PcapFileData!().decode_with_decoder::<BinaryBigEndian>(buf),
        0xd4c3b2a1 => PcapFileData!().decode_with_decoder::<BinaryLittleEndian>(buf),
        x => {
            panic!("Architecture {:02x?} not supported", x);
        }
    };
    dec.map(|(lyr, delta)| (lyr.layers_of(PcapFileData!())[0].clone(), delta))
}

fn encode_packets<E: Encoder>(
    me: &pcapFileData,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let mut out: Vec<u8> = vec![];
    for p in &me.packets {
        let po = p.encode_with_encoder::<E>(stack, my_index, encoded_layers);
        out.extend_from_slice(&po);
    }
    out
}

fn decode_packets<D: Decoder>(
    buf: &[u8],
    me: &mut pcapFileData,
) -> Option<(Vec<pcapPacket>, usize)> {
    let mut vp: Vec<pcapPacket> = vec![];
    let mut ci = 0;
    while ci < buf.len() {
        if let Some((stk, delta)) = PcapPacket!().decode_with_decoder::<D>(&buf[ci..]) {
            let mut pkts = stk
                .layers_of(PcapPacket!())
                .into_iter()
                .map(|p| p.clone())
                .collect::<Vec<pcapPacket>>();
            vp.extend_from_slice(&pkts);
            ci += delta;
        } else {
            break;
        }
    }
    Some((vp, ci))
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq)]
pub struct pcapFile {
    pub magic_number: Value<u32>, // magic number  0xa1b2c3d4: no swap required, 0xd4c3b2a1: swapped
    #[nproto(encode = encode_data, decode = decode_data)]
    d: pcapFileData,
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq)]
pub struct pcapFileData {
    pub version_major: Value<u16>, // major version number
    pub version_minor: Value<u16>, // minor version number
    pub thiszone: Value<i32>,      // GMT to local correction
    pub sigfigs: Value<u32>,       // accuracy of timestamps
    pub snaplen: Value<u32>,       // max length of captured packets, in octets
    pub network: Value<u32>,       // data link type
    #[nproto(encode = encode_packets, decode = decode_packets)]
    pub packets: Vec<pcapPacket>, // encoded packets
}

fn decode_packet_data<D: Decoder>(buf: &[u8], me: &mut pcapPacket) -> Option<(Vec<u8>, usize)> {
    let plen = me.incl_len.value() as usize;
    D::decode_vec(buf, plen)
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq)]
#[nproto(non_greedy_decode)]
pub struct pcapPacket {
    pub ts_sec: Value<u32>,   /* timestamp seconds */
    pub ts_usec: Value<u32>,  /* timestamp microseconds */
    pub incl_len: Value<u32>, /* number of octets of packet saved in file */
    pub orig_len: Value<u32>, /* actual length of packet */
    #[nproto(decode = decode_packet_data)]
    pub data: Vec<u8>, /* incl_len bytes worth of data */
}
