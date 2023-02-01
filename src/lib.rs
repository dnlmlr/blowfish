#![feature(array_chunks)]

use std::{error::Error, fmt::Display, mem};

mod blowfish_consts;

pub struct Blowfish {
    pbox: Vec<u32>,
    sbox: [Vec<u32>; 4],
}

impl Blowfish {
    pub fn new(key: &[u8]) -> Result<Self, BlowfishError> {
        if key.len() < 4 || key.len() > 56 {
            return Err(BlowfishError::Keysize);
        }

        let bf = Blowfish {
            pbox: blowfish_consts::PBOX.to_vec(),
            sbox: [
                blowfish_consts::SBOX0.to_vec(),
                blowfish_consts::SBOX1.to_vec(),
                blowfish_consts::SBOX2.to_vec(),
                blowfish_consts::SBOX3.to_vec(),
            ],
        };

        Ok(bf.key_schedule(key))
    }

    #[inline(always)]
    fn round(&self, x: u32) -> u32 {
        let x: [u8; 4] = x.to_le_bytes();

        // The sboxes are hardcoded to be 256 values of type u32. Since x consists of 4 values with
        // type u8, the sbox accesses are limited to the range of u8 (0 to including 255). This
        // range is always valid for the hardcoded sboxes
        unsafe {
            let a = *self.sbox[0].get_unchecked(x[3] as usize);
            let b = *self.sbox[1].get_unchecked(x[2] as usize);
            let c = *self.sbox[2].get_unchecked(x[1] as usize);
            let d = *self.sbox[3].get_unchecked(x[0] as usize);

            d.wrapping_add(c ^ (b.wrapping_add(a)))
        }
    }
    
    #[inline(always)]
    pub fn encrypt_lr(&self, l: &mut u32, r: &mut u32) {
        self.pbox.array_chunks::<2>().take(8).for_each(|[pl, pr]| {
            *l ^= pl;
            *r ^= self.round(*l);
            *r ^= pr;
            *l ^= self.round(*r);
        });

        *l ^= self.pbox[16];
        *r ^= self.pbox[17];

        mem::swap(l, r);
    }

    #[inline(always)]
    pub fn decrypt_lr(&self, l: &mut u32, r: &mut u32) {
        self.pbox
            .array_chunks::<2>()
            .rev()
            .take(8)
            .for_each(|[pr, pl]| {
                *l ^= pl;
                *r ^= self.round(*l);
                *r ^= pr;
                *l ^= self.round(*r);
            });

        *l ^= self.pbox[1];
        *r ^= self.pbox[0];

        mem::swap(l, r);
    }

    pub fn encrypt_block(&self, block: &mut [u8; 8]) {
        let mut l = u32::from_be_bytes(block[..4].try_into().unwrap());
        let mut r = u32::from_be_bytes(block[4..].try_into().unwrap());

        self.encrypt_lr(&mut l, &mut r);

        block[..4].copy_from_slice(&l.to_be_bytes());
        block[4..].copy_from_slice(&r.to_be_bytes());
    }

    pub fn decrypt_block(&self, block: &mut [u8; 8]) {
        let mut l = u32::from_be_bytes(block[..4].try_into().unwrap());
        let mut r = u32::from_be_bytes(block[4..].try_into().unwrap());

        self.decrypt_lr(&mut l, &mut r);

        block[..4].copy_from_slice(&l.to_be_bytes());
        block[4..].copy_from_slice(&r.to_be_bytes());
    }

    fn key_schedule(mut self, key: &[u8]) -> Self {
        let mut rolling_key = std::iter::repeat(key).flatten().copied();

        self.pbox.iter_mut().for_each(|pb| {
            // Parse cycling key bytes as big endian u32
            let subkey = (&mut rolling_key)
                .take(4)
                .fold(0, |prev, curr| prev << 8 | curr as u32);
            *pb ^= subkey;
        });

        let mut l = 0;
        let mut r = 0;

        for i in (0..18).step_by(2) {
            self.encrypt_lr(&mut l, &mut r);
            self.pbox[i] = l;
            self.pbox[i + 1] = r;
        }

        for i in 0..4 {
            for j in (0..256).step_by(2) {
                self.encrypt_lr(&mut l, &mut r);
                self.sbox[i][j] = l;
                self.sbox[i][j + 1] = r;
            }
        }

        self
    }
}

#[derive(Debug)]
pub enum BlowfishError {
    Keysize,
}

impl Error for BlowfishError {}

impl Display for BlowfishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Keysize => write!(f, "Invalid keysize"),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::Blowfish;

    #[test]
    fn test_roundtrip_single_block_lr() {
        let bf = Blowfish::new(&[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ])
        .unwrap();

        let l_orig = 0x6518a1f5;
        let r_orig = 0xc8d9b63c;

        let mut l = l_orig;
        let mut r = r_orig;
        bf.encrypt_lr(&mut l, &mut r);

        assert_eq!(l, 0xdac63686);
        assert_eq!(r, 0x1d70bd8a);

        bf.decrypt_lr(&mut l, &mut r);

        assert_eq!(l, l_orig);
        assert_eq!(r, r_orig);
    }

    #[test]
    fn test_roundtrip_single_block() {
        let bf = Blowfish::new(&[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ])
        .unwrap();

        let plaintext_orig = [0x65, 0x18, 0xa1, 0xf5, 0xc8, 0xd9, 0xb6, 0x3c];

        let mut ciphertext = plaintext_orig.clone();
        bf.encrypt_block(&mut ciphertext);

        assert_eq!(ciphertext, [0xda, 0xc6, 0x36, 0x86, 0x1d, 0x70, 0xbd, 0x8a]);

        bf.decrypt_block(&mut ciphertext);

        assert_eq!(ciphertext, plaintext_orig);
    }
}
