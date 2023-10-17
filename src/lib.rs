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

impl Decode for i32 {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        D::decode_u32(buf).map(|(n, s)| (n as i32, s))
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

impl Encode for i32 {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        E::encode_u32(*self as u32)
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

    pub fn layers_of<T: Layer>(&self, item: T) -> Vec<&T> {
        let mut out = vec![];
        for ll in &self.layers {
            if ll.type_id_is(TypeId::of::<T>()) {
                out.push(ll.downcast_ref().unwrap())
            }
        }
        out
    }
    pub fn items_of<T: Layer>(&self, typ: T) -> Vec<&T> {
        self.layers_of(typ)
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
        use crate::protocols::raw::*;
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

pub mod protocols;


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

