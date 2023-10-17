use crate::*;

use std::num::ParseIntError;

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct IpFlags {
    // FIXME
}

impl Encode for Vec<IpOption> {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        vec![]
    }
}

impl Encode for IpFlags {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        vec![]
    }
}

impl From<u8> for IpFlags {
    fn from(v: u8) -> Self {
        IpFlags {}
    }
}
impl FromStr for IpFlags {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(IpFlags {})
    }
}

impl Distribution<IpFlags> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> IpFlags {
        IpFlags {}
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IpOption {
    NOP(),
    SourceRoute(Vec<Ipv4Address>),
}

impl FromStr for IpOption {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(IpOption::NOP())
    }
}

fn encode_ver_ihl<E: Encoder>(
    my_layer: &Ip,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let ver = (my_layer.version.value() as u8) & 0xf;
    let ihl = if my_layer.ihl.is_auto() {
        // fixme
        5
    } else {
        (my_layer.ihl.value() as u8) & 0xf
    };
    E::encode_u8(ver << 4 | ihl)
}

fn decode_ver_ihl<D: Decoder>(buf: &[u8], me: &mut Ip) -> Option<(u8, usize)> {
    let (v_ihl, delta) = u8::decode::<D>(buf)?;
    let ihl = v_ihl & 0xf;
    me.version = Value::Set(v_ihl >> 4);
    Some((ihl, delta))
}

fn fill_ihl_auto(layer: &dyn Layer, stack: &LayerStack, my_index: usize) -> Value<u8> {
    Value::Auto
}

fn fill_ip_len_auto(layer: &dyn Layer, stack: &LayerStack, my_index: usize) -> Value<u16> {
    Value::Auto
}

fn fill_ip_chksum_auto(layer: &dyn Layer, stack: &LayerStack, my_index: usize) -> Value<u16> {
    Value::Auto
}

fn encode_ip_len<E: Encoder>(
    me: &Ip,
    stack: &LayerStack,
    my_index: usize,
    encoded_data: &EncodingVecVec,
) -> Vec<u8> {
    use std::convert::TryInto;
    let mut data_len: usize = 0;

    for i in my_index + 1..encoded_data.len() {
        data_len += encoded_data[i].len();
    }
    data_len += 20; // IP HDR
    let len: u16 = data_len.try_into().unwrap();

    len.encode::<E>()
}

fn encode_ip_chksum<E: Encoder>(
    me: &Ip,
    stack: &LayerStack,
    my_index: usize,
    encoded_data: &EncodingVecVec,
) -> Vec<u8> {
    use std::convert::TryInto;
    if !me.chksum.is_auto() {
        return me.chksum.value().encode::<E>();
    }

    let encoded_ip_header = if let Some(ip) = stack.item_at(IP!(), my_index) {
        ip.clone().chksum(0).encode(stack, my_index, encoded_data)
    } else {
        vec![]
    };
    // eprintln!("Encoded IP header: {:02x?}", &encoded_ip_header);
    let sum = get_inet_sum(&encoded_ip_header);
    let sum = fold_u32(sum);
    sum.encode::<E>()
}

#[derive(FromStringHashmap, NetworkProtocol, Clone, Debug, Eq, PartialEq)]
#[nproto(register(ETHERTYPE_LAYERS, Ethertype = 0x800))]
#[nproto(register(IANA_LAYERS, Proto = 4))]
pub struct Ip {
    #[nproto(default = 4, encode = Skip, decode = Skip)]
    pub version: Value<u8>,
    #[nproto(encode = encode_ver_ihl, decode = decode_ver_ihl, fill = fill_ihl_auto)]
    pub ihl: Value<u8>,
    pub tos: Value<u8>,
    #[nproto(encode = encode_ip_len, fill = fill_ip_len_auto)]
    pub len: Value<u16>,
    #[nproto(default = Random)]
    pub id: Value<u16>,
    #[nproto(decode = Skip)]
    pub flags: Value<IpFlags>,
    pub frag: Value<u16>,
    #[nproto(default = 64)]
    pub ttl: Value<u8>,
    #[nproto(next: IANA_LAYERS => Proto )]
    pub proto: Value<u8>,
    #[nproto(encode = encode_ip_chksum, fill = fill_ip_chksum_auto)]
    pub chksum: Value<u16>,
    #[nproto(default = "127.0.0.1")]
    pub src: Value<Ipv4Address>,
    #[nproto(default = "127.0.0.1")]
    pub dst: Value<Ipv4Address>,
    #[nproto(decode = Skip)]
    pub options: Vec<IpOption>,
}
