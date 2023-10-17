use crate::*;

pub struct BinaryLittleEndian;

impl Decoder for BinaryLittleEndian {
    fn decode_u8(buf: &[u8]) -> Option<(u8, usize)> {
        if buf.len() >= 1 {
            Some((buf[0], 1))
        } else {
            None
        }
    }
    fn decode_u16(buf: &[u8]) -> Option<(u16, usize)> {
        if buf.len() >= 2 {
            let v = buf[1] as u16;
            let v = (v << 8) + buf[0] as u16;
            Some((v, 2))
        } else {
            None
        }
    }
    fn decode_u32(buf: &[u8]) -> Option<(u32, usize)> {
        if buf.len() >= 4 {
            let v = buf[3] as u32;
            let v = (v << 8) + buf[2] as u32;
            let v = (v << 8) + buf[1] as u32;
            let v = (v << 8) + buf[0] as u32;
            Some((v, 4))
        } else {
            None
        }
    }
    fn decode_u64(buf: &[u8]) -> Option<(u64, usize)> {
        if buf.len() >= 8 {
            let v = buf[7] as u64;
            let v = (v << 8) + buf[6] as u64;
            let v = (v << 8) + buf[5] as u64;
            let v = (v << 8) + buf[4] as u64;
            let v = (v << 8) + buf[3] as u64;
            let v = (v << 8) + buf[2] as u64;
            let v = (v << 8) + buf[1] as u64;
            let v = (v << 8) + buf[0] as u64;
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

impl Encoder for BinaryLittleEndian {
    fn encode_u8(v1: u8) -> Vec<u8> {
        let o0 = v1;
        vec![o0]
    }
    fn encode_u16(v1: u16) -> Vec<u8> {
        let o1 = (v1 >> 8) as u8;
        let o0 = (v1 & 0xff) as u8;
        vec![o0, o1]
    }
    fn encode_u32(v1: u32) -> Vec<u8> {
        let o3 = ((v1 >> 24) & 0xff) as u8;
        let o2 = ((v1 >> 16) & 0xff) as u8;
        let o1 = ((v1 >> 8) & 0xff) as u8;
        let o0 = ((v1 >> 0) & 0xff) as u8;
        vec![o0, o1, o2, o3]
    }
    fn encode_u64(v1: u64) -> Vec<u8> {
        let o7 = ((v1 >> 56) & 0xff) as u8;
        let o6 = ((v1 >> 48) & 0xff) as u8;
        let o5 = ((v1 >> 40) & 0xff) as u8;
        let o4 = ((v1 >> 32) & 0xff) as u8;
        let o3 = ((v1 >> 24) & 0xff) as u8;
        let o2 = ((v1 >> 16) & 0xff) as u8;
        let o1 = ((v1 >> 8) & 0xff) as u8;
        let o0 = ((v1 >> 0) & 0xff) as u8;
        vec![o0, o1, o2, o3, o4, o5, o6, o7]
    }
    fn encode_vec(v1: &Vec<u8>) -> Vec<u8> {
        v1.clone()
    }
}
