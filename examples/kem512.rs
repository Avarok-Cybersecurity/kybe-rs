use kybe_rs::kyber512kem;

fn main() {
    let kem = kyber512kem();

    let (sk, pk) = kem.keygen().unwrap();
    let (ctx, _shk) = kem.encaps(&pk).unwrap();
    let shk2 = kem.decaps(&ctx, &sk).unwrap();

    println!("{:?}", shk2);
}
