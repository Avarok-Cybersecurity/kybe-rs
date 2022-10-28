#[cfg(test)]
mod tests {
    use kybe_rs::*;

    const MAX_LEN: usize = 100;
    const KEM_TEST_COUNT: usize = 100;

    #[test]
    fn test_pke_512() {
        for x in 0..10 {
            for len in 1..=MAX_LEN {
                let pke512 = kyber512pke();

                let (sk_pke_512, pk_pke_512) = pke512.keygen().unwrap();
                let random_message = ByteArray::random(len);
                let nonce = ByteArray::random(32);
                let pke_ct = pke512
                    .encrypt(&pk_pke_512, &random_message, &nonce)
                    .unwrap();
                let pke_decrypted_ct = pke512.decrypt(&sk_pke_512, &pke_ct).unwrap();
                //pke_decrypted_ct.data.truncate(len);
                assert_eq!(
                    random_message.as_ref(),
                    pke_decrypted_ct.as_ref(),
                    "Failed at len {} rep {}",
                    len,
                    x
                );
            }
        }
    }

    #[test]
    fn test_kem_512() {
        for _ in 0..KEM_TEST_COUNT {
            let kem = kyber512kem();
            let (sk_kem, pk_kem) = kem.keygen().unwrap();
            let (ct_kem, ss_kem) = kem.encaps(&pk_kem).unwrap();
            let ss_kem_alice = kem.decaps(&ct_kem, &sk_kem).unwrap();
            assert_eq!(ss_kem_alice, ss_kem);
        }
    }

    #[test]
    fn test_kem_768() {
        for _ in 0..KEM_TEST_COUNT {
            let kem = kyber768kem();
            let (sk_kem, pk_kem) = kem.keygen().unwrap();
            let (ct_kem, ss_kem) = kem.encaps(&pk_kem).unwrap();
            let ss_kem_alice = kem.decaps(&ct_kem, &sk_kem).unwrap();
            assert_eq!(ss_kem_alice, ss_kem);
        }
    }

    #[test]
    fn test_kem_1024() {
        for _ in 0..KEM_TEST_COUNT {
            let kem = kyber1024kem();
            let (sk_kem, pk_kem) = kem.keygen().unwrap();
            let (ct_kem, ss_kem) = kem.encaps(&pk_kem).unwrap();
            let ss_kem_alice = kem.decaps(&ct_kem, &sk_kem).unwrap();
            assert_eq!(ss_kem_alice, ss_kem);
        }
    }
}
