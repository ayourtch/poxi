//use std::any::Any;
pub use std::any::TypeId;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt;
use std::fmt::Debug;
use std::net::Ipv4Addr;
use std::ops::Deref;
pub use std::ops::Div;
use std::ops::Index;
use std::str::FromStr;
#[macro_use]
extern crate mopa;
extern crate itertools;
extern crate mac_address;

#[macro_use]
extern crate lazy_static;

pub struct ParseNumberError;
use crate::Value::Random;
use rand::distributions::{Distribution, Standard};
use rand::Rng;

use linkme::distributed_slice;

#[derive(NetworkProtocol, Debug, Clone)]
#[nproto(registry(ETHERTYPE_LAYERS, Ethertype: u16))]
#[nproto(registry(IANA_LAYERS, Proto: u8))]
/* Only here as a target of derive + attribute macros to make registries */
struct protocolRegistriesSentinel;

pub trait Encoder {
    fn encode_u8(v1: u8) -> Vec<u8>;
    fn encode_u16(v1: u16) -> Vec<u8>;
    fn encode_u32(v1: u32) -> Vec<u8>;
    fn encode_u64(v1: u64) -> Vec<u8>;
    fn encode_vec(v1: &Vec<u8>) -> Vec<u8>;
}

pub trait Decoder {
    fn decode_u8(buf: &[u8]) -> Option<(u8, usize)>;
    fn decode_u16(buf: &[u8]) -> Option<(u16, usize)>;
    fn decode_u32(buf: &[u8]) -> Option<(u32, usize)>;
    fn decode_u64(buf: &[u8]) -> Option<(u64, usize)>;
    fn decode_vec(buf: &[u8], len: usize) -> Option<(Vec<u8>, usize)>;
}

pub struct BinaryBigEndian;

impl Decoder for BinaryBigEndian {
    fn decode_u8(buf: &[u8]) -> Option<(u8, usize)> {
        if buf.len() >= 1 {
            Some((buf[0], 1))
        } else {
            None
        }
    }
    fn decode_u16(buf: &[u8]) -> Option<(u16, usize)> {
        if buf.len() >= 2 {
            let v = buf[0] as u16;
            let v = (v << 8) + buf[1] as u16;
            Some((v, 2))
        } else {
            None
        }
    }
    fn decode_u32(buf: &[u8]) -> Option<(u32, usize)> {
        if buf.len() >= 4 {
            let v = buf[0] as u32;
            let v = (v << 8) + buf[1] as u32;
            let v = (v << 8) + buf[2] as u32;
            let v = (v << 8) + buf[3] as u32;
            Some((v, 4))
        } else {
            None
        }
    }
    fn decode_u64(buf: &[u8]) -> Option<(u64, usize)> {
        if buf.len() >= 8 {
            let v = buf[0] as u64;
            let v = (v << 8) + buf[1] as u64;
            let v = (v << 8) + buf[2] as u64;
            let v = (v << 8) + buf[3] as u64;
            let v = (v << 8) + buf[4] as u64;
            let v = (v << 8) + buf[5] as u64;
            let v = (v << 8) + buf[6] as u64;
            let v = (v << 8) + buf[7] as u64;
            Some((v, 8))
        } else {
            None
        }
    }
    fn decode_vec(buf: &[u8], len: usize) -> Option<(Vec<u8>, usize)> {
        if buf.len() >= len {
            Some((buf[0..len].to_vec(), len))
        } else {
            None
        }
    }
}

impl Encoder for BinaryBigEndian {
    fn encode_u8(v1: u8) -> Vec<u8> {
        let o0 = v1;
        vec![o0]
    }
    fn encode_u16(v1: u16) -> Vec<u8> {
        let o0 = (v1 >> 8) as u8;
        let o1 = (v1 & 0xff) as u8;
        vec![o0, o1]
    }
    fn encode_u32(v1: u32) -> Vec<u8> {
        let o0 = ((v1 >> 24) & 0xff) as u8;
        let o1 = ((v1 >> 16) & 0xff) as u8;
        let o2 = ((v1 >> 8) & 0xff) as u8;
        let o3 = ((v1 >> 0) & 0xff) as u8;
        vec![o0, o1, o2, o3]
    }
    fn encode_u64(v1: u64) -> Vec<u8> {
        let o0 = ((v1 >> 56) & 0xff) as u8;
        let o1 = ((v1 >> 48) & 0xff) as u8;
        let o2 = ((v1 >> 40) & 0xff) as u8;
        let o3 = ((v1 >> 32) & 0xff) as u8;
        let o4 = ((v1 >> 24) & 0xff) as u8;
        let o5 = ((v1 >> 16) & 0xff) as u8;
        let o6 = ((v1 >> 8) & 0xff) as u8;
        let o7 = ((v1 >> 0) & 0xff) as u8;
        vec![o0, o1, o2, o3, o4, o5, o6, o7]
    }
    fn encode_vec(v1: &Vec<u8>) -> Vec<u8> {
        v1.clone()
    }
}

pub trait Decode {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)>
    where
        Self: Sized;
}

impl Decode for u8 {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        D::decode_u8(buf)
    }
}

impl Decode for u16 {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        D::decode_u16(buf)
    }
}

impl Decode for u32 {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        D::decode_u32(buf)
    }
}

impl Decode for u64 {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        D::decode_u64(buf)
    }
}

impl Decode for Ipv4Address {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        D::decode_u32(buf).map(|(a, i)| (Self::from(a), i))
    }
}

impl Decode for MacAddr {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        if let Some((mac_vec, count)) = D::decode_vec(buf, 6) {
            Some((MacAddr::from(&mac_vec[..]), count))
        } else {
            None
        }
    }
}

pub trait Encode {
    fn encode<E: Encoder>(&self) -> Vec<u8>;
}

impl Encode for u8 {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        E::encode_u8(*self)
    }
}

impl Encode for u16 {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        E::encode_u16(*self)
    }
}

impl Encode for u32 {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        E::encode_u32(*self)
    }
}

impl Encode for u64 {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        E::encode_u64(*self)
    }
}

impl Encode for Ipv4Address {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        E::encode_u32(u32::from_be_bytes(self.0.octets()))
    }
}

impl Encode for MacAddr {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        self.0.bytes().to_vec()
    }
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

impl Encode for Vec<u8> {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        E::encode_vec(self)
    }
}

#[derive(PartialEq, Clone, Eq)]
pub enum Value<T> {
    Auto,
    Random,
    Func(fn() -> T),
    Set(T),
}

impl<T: Clone + std::default::Default> Value<T>
where
    Standard: Distribution<T>,
{
    pub fn value(&self) -> T {
        match self {
            Self::Auto => Default::default(),
            Self::Random => {
                use rand::Rng;
                let mut rng = rand::thread_rng();
                rng.gen()
            }
            Self::Set(x) => x.clone(),
            Self::Func(f) => f(),
        }
    }
}

impl<T: std::cmp::PartialEq> Value<T> {
    pub fn is_auto(&self) -> bool {
        self == &Self::Auto
    }
}

impl<T: std::fmt::Display> fmt::Display for Value<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => f.write_str(&format!("Auto")),
            Self::Random => f.write_str(&format!("Random")),
            Self::Set(x) => x.fmt(f),
            Self::Func(x) => f.write_str(&format!("Fn: {:?}", x)),
        }
    }
}

impl<T: std::fmt::Debug> fmt::Debug for Value<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => f.write_str(&format!("Auto")),
            Self::Random => f.write_str(&format!("Random")),
            Self::Set(x) => f.write_str(&format!("{:?}", &x)),
            Self::Func(x) => f.write_str(&format!("Fn: {:?}", x)),
        }
    }
}

impl<T> Default for Value<T> {
    fn default() -> Self {
        Self::Auto
    }
}

impl<'a, T: From<&'a str>> From<&'a str> for Value<T> {
    fn from(s: &'a str) -> Self {
        Self::Set(T::from(s))
    }
}

#[derive(Clone, Debug)]
pub enum ValueParseError {
    Error,
}

impl<T: FromStr> FromStr for Value<T> {
    type Err = ValueParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match T::from_str(s) {
            Ok(res) => Ok(Self::Set(res)),
            Err(e) => panic!("Could not parse!"),
        }
    }
}

#[derive(PartialEq, Clone, Eq)]
pub struct MacAddr(mac_address::MacAddress);

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("{}", &self.0))
    }
}

impl Default for MacAddr {
    fn default() -> Self {
        MacAddr(mac_address::MacAddress::new([0, 0, 0, 0, 0, 0]))
    }
}

impl MacAddr {
    pub fn new(o1: u8, o2: u8, o3: u8, o4: u8, o5: u8, o6: u8) -> Self {
        MacAddr(mac_address::MacAddress::new([o1, o2, o3, o4, o5, o6]))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseMacAddrError;

impl FromStr for MacAddr {
    type Err = ParseMacAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let res = s.parse();
        if res.is_err() {
            return Err(ParseMacAddrError);
        }
        Ok(MacAddr(res.unwrap()))
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(arg: [u8; 6]) -> Self {
        Self::new(arg[0], arg[1], arg[2], arg[3], arg[4], arg[5])
    }
}

impl From<&[u8]> for MacAddr {
    fn from(arg: &[u8]) -> Self {
        if arg.len() < 6 {
            panic!("the buffer len {} too short for MacAddr", arg.len());
        }
        Self::new(arg[0], arg[1], arg[2], arg[3], arg[4], arg[5])
    }
}

impl From<Value<MacAddr>> for MacAddr {
    fn from(v: Value<MacAddr>) -> MacAddr {
        match v {
            Value::Auto => {
                panic!("can not return value of auto mac addr");
            }
            Value::Random => {
                unimplemented!();
            }
            Value::Set(x) => x.clone(),
            Value::Func(x) => x(),
        }
    }
}

impl From<&str> for MacAddr {
    fn from(s: &str) -> Self {
        let res = s.parse().unwrap();
        MacAddr(res)
    }
}

impl Distribution<MacAddr> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> MacAddr {
        MacAddr::new(
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
        )
    }
}

#[derive(PartialEq, Clone, Eq)]
pub struct Ipv4Address(std::net::Ipv4Addr);

impl fmt::Debug for Ipv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("{:?}", &self.0))
    }
}

impl Default for Ipv4Address {
    fn default() -> Self {
        Ipv4Address(Ipv4Addr::new(0, 0, 0, 0))
    }
}

impl Ipv4Address {
    pub fn new(o1: u8, o2: u8, o3: u8, o4: u8) -> Self {
        Ipv4Address(Ipv4Addr::new(o1, o2, o3, o4))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseIpv4AddressError;

impl FromStr for Ipv4Address {
    type Err = ParseIpv4AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let res = s.parse();
        if res.is_err() {
            return Err(ParseIpv4AddressError);
        }
        Ok(Ipv4Address(res.unwrap()))
    }
}

impl From<[u8; 4]> for Ipv4Address {
    fn from(arg: [u8; 4]) -> Self {
        Self::new(arg[0], arg[1], arg[2], arg[3])
    }
}

impl From<&str> for Ipv4Address {
    fn from(s: &str) -> Self {
        let res = s.parse().unwrap();
        Ipv4Address(res)
    }
}

impl From<u32> for Ipv4Address {
    fn from(u: u32) -> Self {
        Ipv4Address(Ipv4Addr::from(u))
    }
}

impl Distribution<Ipv4Address> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Ipv4Address {
        Ipv4Address::new(rng.gen(), rng.gen(), rng.gen(), rng.gen())
    }
}

#[macro_use]
extern crate scarust_derive;

pub trait FromStringHashmap<T>: Default {
    fn from_string_hashmap(hm: HashMap<String, String>) -> T;
}

pub fn parse_pair<T>(v: &str) -> T
where
    T: FromStr,
{
    let res = v.parse::<T>();
    match res {
        Ok(val) => val,
        Err(_) => panic!("unable to parse"),
    }
}

pub fn parse_pair_as_option<T>(v: &str) -> Option<T>
where
    T: FromStr,
{
    let res = v.parse::<T>();
    match res {
        Ok(val) => Some(val),
        Err(_) => panic!("unable to parse"),
    }
}

pub fn parse_pair_as_value<T>(v: &str) -> Value<T>
where
    T: FromStr,
{
    let res = v.parse::<T>();
    match res {
        Ok(val) => Value::Set(val),
        Err(_) => panic!("unable to parse"),
    }
}

pub fn parse_pair_as_vec<T>(v: &str) -> Vec<T>
where
    T: FromStr,
{
    let res = v.parse::<T>();
    match res {
        Ok(val) => vec![val],
        Err(_) => panic!("unable to parse"),
    }
}

#[derive(FromStringHashmap, Default)]
pub struct FunnyTest {
    pub foo: u32,
    pub bar: Option<u32>,
}

#[derive(Clone, Debug, Default)]
pub struct EncodingVecVec {
    data: Vec<Vec<u8>>,
    curr_idx: usize,
}

impl EncodingVecVec {
    fn len(&self) -> usize {
        // take into account the "phantom" layers
        self.data.len() + self.curr_idx + 1
    }
}
impl Index<usize> for EncodingVecVec {
    type Output = Vec<u8>;

    fn index(&self, idx: usize) -> &Self::Output {
        if idx > self.curr_idx {
            &self.data[idx - self.curr_idx - 1]
        } else {
            panic!("encoding data at layer {} not yet ready", idx);
        }
    }
}

#[derive(Clone)]
pub struct LayerStack {
    pub layers: Vec<Box<dyn Layer>>,
}

impl LayerStack {
    pub fn gg<T: Layer + Clone>(layer: Box<dyn Layer>) -> T {
        if layer.type_id() == TypeId::of::<T>() {
            (*layer.downcast_ref::<T>().unwrap()).clone()
        } else {
            panic!(
                " wrong typeid {:?} and {:?}",
                layer.type_id(),
                TypeId::of::<T>()
            );
        }
    }

    pub fn g<T: Layer>(&self, idx: T) -> &T {
        self[TypeId::of::<T>()].downcast_ref().unwrap()
    }

    pub fn item_at<T: Layer>(&self, item: T, idx: usize) -> Option<&T> {
        self.layers[idx].downcast_ref()
    }

    pub fn get_layer<T: Layer>(&mut self, item: T) -> Option<&T> {
        for ll in &self.layers {
            if ll.type_id_is(TypeId::of::<T>()) {
                return Some(ll.downcast_ref().unwrap());
            }
        }
        return None;
    }
    pub fn get_layer_mut<T: Layer>(&mut self, item: T) -> Option<&mut T> {
        for ll in &mut self.layers {
            if ll.type_id_is(TypeId::of::<T>()) {
                return Some(ll.downcast_mut().unwrap());
            }
        }
        return None;
    }

    pub fn items_of<T: Layer>(&self, item: T) -> Vec<&T> {
        let mut out = vec![];
        for ll in &self.layers {
            if ll.type_id_is(TypeId::of::<T>()) {
                out.push(ll.downcast_ref().unwrap())
            }
        }
        out
    }

    pub fn encode(self) -> Vec<u8> {
        let mut out = EncodingVecVec {
            data: vec![],
            curr_idx: self.layers.len(),
        };
        for (i, ll) in (&self.layers).into_iter().enumerate().rev() {
            out.curr_idx = i;
            println!("{}: {:?}", i, &ll);
            let ev = ll.encode(&self, i, &out);
            out.data.push(ev);
        }
        out.data.reverse();
        itertools::concat(out.data)
    }

    pub fn fill(&self) -> LayerStack {
        let mut out = LayerStack { layers: vec![] };
        for (i, ll) in (&self.layers).into_iter().enumerate() {
            ll.fill(&self, i, &mut out);
        }
        out
    }

    pub fn indices_of<T: Layer>(&self, typ: T) -> Vec<usize> {
        let mut out = vec![];
        for (i, ref layer) in (&self.layers).into_iter().enumerate() {
            if layer.type_id_is(typ.type_id()) {
                out.push(i)
            }
        }
        out
    }
}

impl Index<TypeId> for LayerStack {
    type Output = Box<dyn Layer>;

    fn index(&self, type_id: TypeId) -> &Self::Output {
        for ref layer in &self.layers {
            if layer.type_id_is(type_id) {
                return layer.clone();
            }
        }
        panic!("Layer not found");
    }
}

impl<T> Index<T> for LayerStack
where
    T: Layer,
{
    type Output = T;
    fn index(&self, typ: T) -> &Self::Output {
        for ref layer in &self.layers {
            if layer.type_id_is(typ.type_id()) {
                return layer.clone().downcast_ref().unwrap();
            }
        }
        panic!("Layer not found");
    }
}

impl fmt::Debug for LayerStack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.layers.iter()).finish()
    }
}

impl<T: Layer> Div<T> for LayerStack {
    type Output = LayerStack;
    fn div(mut self, rhs: T) -> Self::Output {
        self.layers.push(rhs.embox());
        self
    }
}

impl Div<LayerStack> for LayerStack {
    type Output = LayerStack;
    fn div(mut self, rhs: LayerStack) -> Self::Output {
        for x in rhs.layers {
            self.layers.push(x);
        }
        self
    }
}

pub trait New {
    fn new() -> Self
    where
        Self: Default;
}

impl<T: Default> New for T {
    fn new() -> Self {
        Self::default()
    }
}

pub trait Layer: Debug + mopa::Any + New {
    fn embox(self) -> Box<dyn Layer>;
    fn box_clone(&self) -> Box<dyn Layer>;
    fn to_stack(self) -> LayerStack
    where
        Self: Sized,
    {
        LayerStack {
            layers: vec![self.embox()],
        }
    }
    fn type_id_is(&self, x: TypeId) -> bool {
        self.type_id() == x
    }
    fn get_layer_type_id(&self) -> TypeId {
        self.type_id()
    }
    /* fill the unknown fields based on the entire stack contents */
    fn fill(&self, stack: &LayerStack, my_index: usize, out_stack: &mut LayerStack);

    /* default encode function encodes some dead beef */
    fn encode(
        &self,
        stack: &LayerStack,
        my_index: usize,
        encoded_layers: &EncodingVecVec,
    ) -> Vec<u8> {
        vec![0xde, 0xad, 0xbe, 0xef]
    }

    fn decode_as_raw(&self, buf: &[u8]) -> LayerStack {
        let mut layers = vec![];
        if buf.len() > 0 {
            let layer = raw {
                data: buf.clone().to_vec(),
            };
            layers.push(layer.embox());
        }
        LayerStack { layers }
    }
    fn decode(&self, buf: &[u8]) -> Option<(LayerStack, usize)> {
        let buflen = buf.len();
        Some((self.decode_as_raw(buf), buflen))
    }
}

mopafy!(Layer);

impl Clone for Box<dyn Layer> {
    fn clone(&self) -> Box<dyn Layer> {
        self.box_clone()
    }
}

/*
impl <'a> PartialEq for LayerStack<'a> {
    fn eq(&self, other: &Self) -> bool {
        true
    }
}

impl <'a> Eq for LayerStack<'a> {
}
*/

fn fill_dmac(layer: &dyn Layer, stack: &LayerStack, my_index: usize) -> MacAddr {
    MacAddr::from("ff:ff:ff:ff:ff:ff")
}
fn fill_crc(layer: &dyn Layer, stack: &LayerStack, my_index: usize) -> u32 {
    0x1234
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq)]
#[nproto(encoder(BinaryBigEndian))]
pub struct ether {
    #[nproto(fill = fill_dmac, default = "01:02:03:04:05:06")]
    // #[nproto(default = "01:02:03:04:05:06")]
    // #[nproto(fill = fill_dmac)]
    // #[nproto(default = Random)]
    pub dst: Value<MacAddr>,
    #[nproto(fill = "00:00:00:00:00:00")]
    pub src: Value<MacAddr>,
    #[nproto(next: ETHERTYPE_LAYERS => Ethertype)]
    pub etype: Value<u16>,
    //#[nproto(fill = fill_crc)]
    // pub crc: Value<u32>,
}

fn encode_csum(
    layer: &dyn Layer,
    stack: &LayerStack,
    my_index: usize,
    encoded_data: &EncodingVecVec,
) -> u16 {
    0xffff
}

fn fill_udp_sport(layer: &dyn Layer, stack: &LayerStack, my_index: usize) -> u16 {
    0xffff
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq)]
#[nproto(register(IANA_LAYERS, Proto = 17))]
pub struct Udp {
    #[nproto(fill = fill_udp_sport)]
    pub sport: Value<u16>,
    pub dport: Value<u16>,
    pub len: Value<u16>,
    #[nproto(auto = encode_csum)]
    pub chksum: Value<u16>,
}

fn fill_tcp_dport(layer: &dyn Layer, stack: &LayerStack, my_index: usize) -> u16 {
    80
}

fn encode_tcp_reserved<E: Encoder>(
    me: &Tcp,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let dataofs = me.dataofs.value() & 0xf;
    let reserved = me.reserved.value() & 0xf;
    E::encode_u8((dataofs << 4) | reserved)
}

fn decode_tcp_reserved<D: Decoder>(buf: &[u8], me: &mut Tcp) -> Option<(u8, usize)> {
    use std::convert::TryInto;

    let (x, delta) = u8::decode::<D>(buf)?;
    let dataofs: u8 = x >> 4;
    let reserved: u8 = x & 0xf;
    me.dataofs = Value::Set(dataofs);
    Some((reserved, delta))
}

pub fn update_inet_sum(sum: u32, data: &[u8]) -> u32 {
    let mut sum: u32 = sum;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += (data[i + 1] as u32) | ((data[i] as u32) << 8);
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    sum
}

pub fn get_inet_sum(data: &[u8]) -> u32 {
    update_inet_sum(0, data)
}

pub fn fold_u32(data: u32) -> u16 {
    0xffff ^ (((data >> 16) as u16) + ((data & 0xffff) as u16))
}

fn fill_tcp_chksum_auto(layer: &dyn Layer, stack: &LayerStack, my_index: usize) -> Value<u16> {
    Value::Auto
}

fn encode_tcp_chksum<E: Encoder>(
    me: &Tcp,
    stack: &LayerStack,
    my_index: usize,
    encoded_data: &EncodingVecVec,
) -> Vec<u8> {
    use std::convert::TryInto;
    if !me.chksum.is_auto() {
        return me.chksum.value().encode::<E>();
    }

    let encoded_tcp_header = if let Some(tcp) = stack.item_at(TCP!(), my_index) {
        tcp.clone().chksum(0).encode(stack, my_index, encoded_data)
    } else {
        vec![]
    };
    // println!("TCP HDR {}: {:02x?}", encoded_tcp_header.len(), &encoded_tcp_header);

    let mut sum: u32 = 0;
    let mut data_len: usize = 0;
    // fixme
    let mut tcp_hdr_len: u16 = 20;

    for i in my_index + 1..encoded_data.len() {
        data_len += encoded_data[i].len();
    }

    let total_len: u16 = u16::try_from(data_len).unwrap() + tcp_hdr_len;

    if my_index > 0 {
        if let Some(ip) = stack.item_at(IP!(), my_index - 1) {
            let mut ph: Vec<u8> = vec![];
            /*
            ph.extend_from_slice(&ip.src.value().encode::<E>());
            ph.extend_from_slice(&ip.dst.value().encode::<E>());
            ph.extend_from_slice(&((ip.proto.value() as u16).encode::<E>()));
            ph.extend_from_slice(&total_len.encode::<E>());
            eprintln!("Pseudoheader: {:02x?}", &ph);
            let sum = get_inet_sum(&ph);
            */
            let sum = get_inet_sum(&ip.src.value().encode::<E>());
            let sum = update_inet_sum(sum, &ip.dst.value().encode::<E>());
            let sum = update_inet_sum(sum, &((ip.proto.value() as u16).encode::<E>()));
            let sum = update_inet_sum(sum, &total_len.encode::<E>());

            let mut sum = update_inet_sum(sum, &encoded_tcp_header);
            // eprintln!("CHECKSUM B4 data: {:04x}", sum);
            for i in my_index + 1..encoded_data.len() {
                sum = update_inet_sum(sum, &encoded_data[i]);
            }
            let sum = fold_u32(sum);
            // eprintln!("CHECKSUM: {:04x}", sum);
            sum.encode::<E>()
        } else {
            vec![0xdd, 0xdd]
        }
    } else {
        vec![0xee, 0xea]
    }
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq)]
#[nproto(register(IANA_LAYERS, Proto = 6))]
pub struct Tcp {
    #[nproto(fill = fill_udp_sport)]
    pub sport: Value<u16>,
    #[nproto(fill = fill_tcp_dport)]
    pub dport: Value<u16>,
    #[nproto(default = 0)]
    pub seq: Value<u32>,
    #[nproto(default = 0)]
    pub ack: Value<u32>,
    // u4 really, encoded with "reserved"
    #[nproto(default = 5, encode = Skip, decode = Skip)]
    pub dataofs: Value<u8>,
    #[nproto(default = 0, encode = encode_tcp_reserved, decode = decode_tcp_reserved)]
    pub reserved: Value<u8>,
    #[nproto(default = 2)] // syn
    pub flags: Value<u8>,

    #[nproto(default = 8192)]
    pub window: Value<u16>,
    #[nproto(encode = encode_tcp_chksum, fill = fill_tcp_chksum_auto )]
    pub chksum: Value<u16>,
    #[nproto(default = 0)]
    pub urgptr: Value<u16>,
    // pub options: Vec<TcpOption>,
}

pub enum TcpOption {}

use std::num::ParseIntError;

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct IpFlags {
    // FIXME
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

#[derive(FromStringHashmap, NetworkProtocol, Clone, Debug, Eq, PartialEq)]
#[nproto(register(ETHERTYPE_LAYERS, Ethertype = 0x800))]
#[nproto(register(IANA_LAYERS, Proto = 4))]
pub struct Ip {
    #[nproto(default = 4, encode = Skip, decode = Skip)]
    pub version: Value<u8>,
    #[nproto(encode = encode_ver_ihl, decode = decode_ver_ihl, fill = fill_ihl_auto)]
    pub ihl: Value<u8>,
    pub tos: Value<u8>,
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
    pub chksum: Value<u16>,
    #[nproto(default = "127.0.0.1")]
    pub src: Value<Ipv4Address>,
    #[nproto(default = "127.0.0.1")]
    pub dst: Value<Ipv4Address>,
    #[nproto(decode = Skip)]
    pub options: Vec<IpOption>,
}

fn encode_dot1q_tci<E: Encoder>(
    me: &dot1Q,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let vlan: u16 = me.vlan.value() & 0xfff;
    let dei: u16 = ((me.id.value() as u16) & 1) << 12;
    let pcp: u16 = ((me.prio.value() as u16) & 7) << 13;
    E::encode_u16(vlan | dei | pcp)
}

fn decode_dot1q_tci<D: Decoder>(buf: &[u8], me: &mut dot1Q) -> Option<(u16, usize)> {
    use std::convert::TryInto;

    let (tci, delta) = u16::decode::<D>(buf)?;
    let vlan: u16 = tci & 0xfff;
    let dei: u8 = ((tci >> 12) & 1).try_into().unwrap();
    let pcp: u8 = ((tci >> 13) & 7).try_into().unwrap();
    me.id = Value::Set(dei);
    me.prio = Value::Set(pcp);
    Some((vlan, delta))
}

fn fill_tci_auto(layer: &dyn Layer, stack: &LayerStack, my_index: usize) -> Value<u8> {
    Value::Auto
}

#[derive(FromStringHashmap, NetworkProtocol, Clone, Debug, Eq, PartialEq)]
#[nproto(register(ETHERTYPE_LAYERS, Ethertype = 0x8100))]
pub struct dot1Q {
    #[nproto(default = 0, encode = Skip, decode = Skip)]
    pub prio: Value<u8>,
    #[nproto(default = 0, encode = Skip, decode = Skip)]
    pub id: Value<u8>,
    #[nproto(default = 1, encode = encode_dot1q_tci, decode = decode_dot1q_tci, fill = fill_tci_auto)]
    pub vlan: Value<u16>,
    #[nproto(next: ETHERTYPE_LAYERS => Ethertype)]
    pub etype: Value<u16>,
}

fn decode_arp_hwaddr<D: Decoder>(buf: &[u8], me: &mut Arp) -> Option<(ArpHardwareAddress, usize)> {
    use std::convert::TryInto;

    let (v, delta) = D::decode_vec(buf, me.hwlen.value() as usize)?;
    let vlen = v.len();
    match vlen {
        6 => ArpHardwareAddress::decode::<D>(&v),
        _ => Some((ArpHardwareAddress::Bytes(v), vlen)),
    }
}

fn decode_arp_paddr<D: Decoder>(buf: &[u8], me: &mut Arp) -> Option<(ArpProtocolAddress, usize)> {
    use std::convert::TryInto;

    let (v, delta) = D::decode_vec(buf, me.plen.value() as usize)?;
    let vlen = v.len();
    match vlen {
        4 => ArpProtocolAddress::decode::<D>(&v),
        _ => Some((ArpProtocolAddress::Bytes(v), vlen)),
    }
}

#[derive(FromStringHashmap, NetworkProtocol, Clone, Debug, Eq, PartialEq)]
#[nproto(register(ETHERTYPE_LAYERS, Ethertype = 0x0806))]
pub struct Arp {
    #[nproto(default = 1)]
    pub hwtype: Value<u16>,
    #[nproto(default = 0x0800)]
    pub ptype: Value<u16>,
    #[nproto(default = 6)]
    pub hwlen: Value<u8>,
    #[nproto(default = 4)]
    pub plen: Value<u8>,
    #[nproto(default = 1)]
    pub op: Value<u16>,
    #[nproto(decode = decode_arp_hwaddr)]
    pub hwsrc: Value<ArpHardwareAddress>,
    #[nproto(decode = decode_arp_paddr)]
    pub psrc: Value<ArpProtocolAddress>,
    #[nproto(decode = decode_arp_hwaddr)]
    pub hwdst: Value<ArpHardwareAddress>,
    #[nproto(decode = decode_arp_paddr)]
    pub pdst: Value<ArpProtocolAddress>,
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum ArpHardwareAddress {
    Ether(MacAddr),
    Bytes(Vec<u8>),
}

impl Default for ArpHardwareAddress {
    fn default() -> Self {
        Self::Ether(Default::default())
    }
}

// FIXME: take into account the hwlen from packet
impl Encode for ArpHardwareAddress {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        match self {
            Self::Ether(x) => x.0.bytes().to_vec(),
            Self::Bytes(b) => b.to_vec(),
        }
    }
}

// FIXME: take into account the hwlen from packet
impl Decode for ArpHardwareAddress {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        if let Some((mac_vec, count)) = D::decode_vec(buf, 6) {
            Some((Self::Ether(MacAddr::from(&mac_vec[..])), count))
        } else {
            None
        }
    }
}

impl Distribution<ArpHardwareAddress> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ArpHardwareAddress {
        ArpHardwareAddress::Ether(MacAddr::new(
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
        ))
    }
}

impl FromStr for ArpHardwareAddress {
    type Err = ValueParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match MacAddr::from_str(s) {
            Ok(res) => Ok(Self::Ether(res)),
            Err(e) => {
                panic!("Could not parse");
            }
        }
    }
}

impl From<&str> for ArpHardwareAddress {
    fn from(s: &str) -> Self {
        Self::from_str(s).unwrap()
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum ArpProtocolAddress {
    IP(Ipv4Address),
    Bytes(Vec<u8>),
}

impl Default for ArpProtocolAddress {
    fn default() -> Self {
        Self::IP(Default::default())
    }
}

// FIXME: take into account the plen from packet
impl Encode for ArpProtocolAddress {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        match self {
            Self::IP(x) => x.encode::<E>(),
            Self::Bytes(b) => b.to_vec(),
        }
    }
}

// FIXME: take into account the plen from packet
impl Decode for ArpProtocolAddress {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        if let Some((ip4, count)) = Ipv4Address::decode::<D>(buf) {
            Some((Self::IP(ip4), count))
        } else {
            None
        }
    }
}

impl Distribution<ArpProtocolAddress> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ArpProtocolAddress {
        ArpProtocolAddress::IP(Ipv4Address::new(rng.gen(), rng.gen(), rng.gen(), rng.gen()))
    }
}

impl FromStr for ArpProtocolAddress {
    type Err = ValueParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match Ipv4Address::from_str(s) {
            Ok(res) => Ok(Self::IP(res)),
            Err(e) => {
                panic!("Could not parse");
            }
        }
    }
}

impl From<&str> for ArpProtocolAddress {
    fn from(s: &str) -> Self {
        Self::from_str(s).unwrap()
    }
}

#[derive(FromStringHashmap, NetworkProtocol, Clone, Debug, Eq, PartialEq)]
#[nproto(decode_suppress)]
pub struct raw {
    data: Vec<u8>,
}

impl Layer for String {
    fn embox(self) -> Box<dyn Layer> {
        Box::new(self)
    }
    fn box_clone(&self) -> Box<dyn Layer> {
        Box::new(self.clone())
    }
    fn fill(&self, stack: &LayerStack, my_index: usize, out_stack: &mut LayerStack) {
        out_stack.layers.push(Box::new(self.clone()))
    }
    fn encode(
        &self,
        stack: &LayerStack,
        my_index: usize,
        encoded_layers: &EncodingVecVec,
    ) -> Vec<u8> {
        self.as_bytes().to_owned()
    }
}
