use crate::*;

/*
 * This is a toy pcap encoder/decoder
 */

fn encode_packets<E: Encoder>(
    me: &pcapFile,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let mut out: Vec<u8> = vec![];
    for p in &me.packets {
        let po = p.encode(stack, my_index, encoded_layers);
        out.extend_from_slice(&po);
    }
    out
}

fn decode_packets<D: Decoder>(buf: &[u8], me: &mut pcapFile) -> Option<(Vec<pcapPacket>, usize)> {
    let mut vp: Vec<pcapPacket> = vec![];
    let mut ci = 0;
    while ci < buf.len() {
        if let Some((stk, delta)) = PcapPacket!().decode(buf) {
           let mut pkts = stk.layers_of(PcapPacket!()).into_iter().map(|p| p.clone()).collect::<Vec<pcapPacket>>();
           vp.extend_from_slice(&pkts);
           ci += delta;
        } else {
            break;
        }
    }
    Some((vp, ci))
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq)]
#[nproto(encoder(PcapEncoder))]
pub struct pcapFile {
    pub magic_number: Value<u32>, // magic number  0xa1b2c3d4: no swap required, 0xd4c3b2a1: swapped
    pub version_major: Value<u16>, // major version number
    pub version_minor: Value<u16>, // minor version number
    pub thiszone: Value<i32>,     // GMT to local correction
    pub sigfigs: Value<u32>,      // accuracy of timestamps
    pub snaplen: Value<u32>,      // max length of captured packets, in octets
    pub network: Value<u32>,      // data link type
    #[nproto(encode = encode_packets, decode = decode_packets)]
    pub packets: Vec<pcapPacket>, // encoded packets
}

fn decode_packet_data<D: Decoder>(buf: &[u8], me: &mut pcapPacket) -> Option<(Vec<u8>, usize)> {
    println!("Packet in progress: {:?}", &me);
    let plen = u32::from_be(me.incl_len.value()) as usize;
    println!("Included len: {}", plen);
    println!("Buf len: {}", buf.len());

    D::decode_vec(buf, plen)
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq)]
#[nproto(non_greedy_decode)]
pub struct pcapPacket {
    pub ts_sec: Value<u32>,   /* timestamp seconds */
    pub ts_usec: Value<u32>,  /* timestamp microseconds */
    pub incl_len: Value<u32>, /* number of octets of packet saved in file */
    pub orig_len: Value<u32>, /* actual length of packet */
    #[nproto(encode = Skip, decode = decode_packet_data)]
    pub data: Vec<u8>, /* incl_len bytes worth of data */
}
