use kybe_rs::{kyber768pke, ByteArray};

fn main() {
    let pke = kyber768pke();
    let m = ByteArray::random(32);
    let r = ByteArray::random(32);

    let (sk, pk) = pke.keygen().unwrap();
    let enc = pke.encrypt_block(&pk, &m, &r).unwrap();
    let dec = pke.decrypt_block(&sk, &enc).unwrap();

    println!("{:?}", dec);
}
