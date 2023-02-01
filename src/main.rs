use blowfish::Blowfish;

fn main() {
    let bf = Blowfish::new(b"verysecretpasswd").unwrap();

    let mut txt = b"abcd1234".to_vec();

    bf.encrypt_block((&mut txt[..8]).try_into().unwrap());

    println!("{:02x?}", txt);
}
