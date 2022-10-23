use kybe_rs::kyber1024kem;

fn main() {
    let kem = kyber1024kem();

    let (sk, pk) = kem.keygen().unwrap();
    let (ctx, _shk) = kem.encaps(&pk).unwrap();
    let shk2 = kem.decaps(&ctx, &sk).unwrap();

    println!("{:?}", shk2);
}
