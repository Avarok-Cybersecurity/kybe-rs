use kybe_rs::kyber768kem;

fn main() {
    let kem = kyber768kem();

    let (sk, pk) = kem.keygen().unwrap();
    let (ctx, _shk) = kem.encaps(&pk).unwrap();
    let shk2 = kem.decaps(&ctx, &sk).unwrap();

    println!("{:?}", shk2);
}
