use kybe_rs::*;

const MAX_MESSAGE_LEN: usize = 33;

#[test]
fn generate_tests() {
    for x in 0..100 {
        for len in 1..MAX_MESSAGE_LEN {
            let pke512 = kyber512pke();
            let kem512 = kyber512kem();
            let (sk_kem_512, pk_kem_512) = kem512.keygen().unwrap();
            let (ct_kem_512, ss_kem_512) = kem512.encaps(&pk_kem_512).unwrap();
            let ss_kem_512_alice = kem512.decaps(&ct_kem_512, &sk_kem_512).unwrap();
            assert_eq!(ss_kem_512_alice, ss_kem_512);

            println!("~~~~~~~~~~~~ PKE ~~~~~~~~~~~~");
            let (sk_pke_512, pk_pke_512) = pke512.keygen().unwrap();
            let random_message = ByteArray::random(len);
            let nonce = ByteArray::random(32);
            let pke_ct = pke512
                .encrypt(&pk_pke_512, &random_message, &nonce)
                .unwrap();
            let mut pke_decrypted_ct = pke512.decrypt(&sk_pke_512, &pke_ct).unwrap();
            pke_decrypted_ct.data.truncate(len);
            if len != 33 {
                assert_eq!(
                    random_message.as_ref(),
                    pke_decrypted_ct.as_ref(),
                    "Failed at len {} rep {}",
                    len,
                    x
                );
            } else {
                assert_ne!(
                    random_message.as_ref(),
                    pke_decrypted_ct.as_ref(),
                    "Failed at len {} rep {}",
                    len,
                    x
                );
            }
        }
    }
}
