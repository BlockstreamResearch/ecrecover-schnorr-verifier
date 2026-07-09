use std::env;
use std::process;

use secp256k1_zkp::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};

const WORD_BYTES: usize = 32;
const ABI_SIGN_RESULT_BYTES: usize = WORD_BYTES * 5;
const USAGE: &str = "usage: schnorr-ffi sign <message32-hex> <secret-key32-hex> <aux-rand32-hex>";

fn main() {
    if let Err(error) = run(env::args().skip(1)) {
        eprintln!("{error}");
        process::exit(1);
    }
}

fn run<I>(args: I) -> Result<(), String>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();
    let Some(command) = args.next() else {
        return Err(USAGE.to_owned());
    };

    match command.as_str() {
        "sign" => {
            let message = parse_hex_32("message32-hex", &next_arg(&mut args, "message32-hex")?)?;
            let secret_key = parse_hex_32(
                "secret-key32-hex",
                &next_arg(&mut args, "secret-key32-hex")?,
            )?;
            let aux_rand = parse_hex_32("aux-rand32-hex", &next_arg(&mut args, "aux-rand32-hex")?)?;

            if args.next().is_some() {
                return Err(USAGE.to_owned());
            }

            let encoded = sign_payload(message, secret_key, aux_rand)?;
            print!("0x{}", encode_hex(&encoded));

            Ok(())
        }
        _ => Err(USAGE.to_owned()),
    }
}

fn next_arg<I>(args: &mut I, name: &str) -> Result<String, String>
where
    I: Iterator<Item = String>,
{
    args.next()
        .ok_or_else(|| format!("missing argument `{name}`\n{USAGE}"))
}

fn parse_hex_32(name: &str, value: &str) -> Result<[u8; WORD_BYTES], String> {
    let normalized = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);

    if normalized.len() != WORD_BYTES * 2 {
        return Err(format!("argument `{name}` must be exactly 32 bytes"));
    }

    let mut decoded = [0u8; WORD_BYTES];
    for (index, chunk) in normalized.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_nibble(name, chunk[0])?;
        let low = decode_nibble(name, chunk[1])?;
        decoded[index] = (high << 4) | low;
    }

    Ok(decoded)
}

fn decode_nibble(name: &str, value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(format!(
            "argument `{name}` contains a non-hex character: `{}`",
            char::from(value)
        )),
    }
}

fn sign_payload(
    message_digest: [u8; WORD_BYTES],
    secret_key_bytes: [u8; WORD_BYTES],
    aux_rand: [u8; WORD_BYTES],
) -> Result<[u8; ABI_SIGN_RESULT_BYTES], String> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&secret_key_bytes)
        .map_err(|_| "secret key is out of range".to_owned())?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let (public_key_x, _) = XOnlyPublicKey::from_keypair(&keypair);
    let signature = secp
        .sign_schnorr_with_aux_rand(&Message::from_digest(message_digest), &keypair, &aux_rand)
        .serialize();

    let mut encoded = [0u8; ABI_SIGN_RESULT_BYTES];

    encoded[0..WORD_BYTES].copy_from_slice(&public_key_x.serialize());
    encoded[WORD_BYTES * 2..WORD_BYTES * 3].copy_from_slice(&signature[WORD_BYTES..]);
    encoded[WORD_BYTES * 3..WORD_BYTES * 4].copy_from_slice(&message_digest);
    encoded[WORD_BYTES * 4..WORD_BYTES * 5].copy_from_slice(&signature[..WORD_BYTES]);

    Ok(encoded)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }

    encoded
}

#[cfg(test)]
mod tests {
    use super::{encode_hex, parse_hex_32, sign_payload, ABI_SIGN_RESULT_BYTES, WORD_BYTES};
    use secp256k1_zkp::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};

    const VECTOR_3_SECRET_KEY: &str =
        "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710";
    const VECTOR_3_AUX_RAND: &str =
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    const VECTOR_3_PUBLIC_KEY_X: &str =
        "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517";
    const VECTOR_3_MESSAGE_HASH: &str =
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    const VECTOR_3_SIGNATURE: &str =
        "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3";

    #[test]
    fn sign_payload_matches_bip340_vector_3() {
        let message = parse_hex_32("message", VECTOR_3_MESSAGE_HASH).unwrap();
        let secret_key = parse_hex_32("secret", VECTOR_3_SECRET_KEY).unwrap();
        let aux_rand = parse_hex_32("aux", VECTOR_3_AUX_RAND).unwrap();

        let encoded = sign_payload(message, secret_key, aux_rand).unwrap();

        assert_eq!(encoded.len(), ABI_SIGN_RESULT_BYTES);
        assert_eq!(
            encode_hex(&encoded[0..WORD_BYTES]).to_uppercase(),
            VECTOR_3_PUBLIC_KEY_X
        );
        assert_eq!(encoded[WORD_BYTES..WORD_BYTES * 2], [0u8; WORD_BYTES]);
        assert_eq!(
            encode_hex(&encoded[WORD_BYTES * 2..WORD_BYTES * 3]).to_uppercase(),
            &VECTOR_3_SIGNATURE[64..]
        );
        assert_eq!(
            encode_hex(&encoded[WORD_BYTES * 3..WORD_BYTES * 4]).to_uppercase(),
            VECTOR_3_MESSAGE_HASH
        );
        assert_eq!(
            encode_hex(&encoded[WORD_BYTES * 4..WORD_BYTES * 5]).to_uppercase(),
            &VECTOR_3_SIGNATURE[..64]
        );
    }

    #[test]
    fn sign_payload_produces_verifiable_signature() {
        let message = parse_hex_32("message", VECTOR_3_MESSAGE_HASH).unwrap();
        let secret_key =
            SecretKey::from_slice(&parse_hex_32("secret", VECTOR_3_SECRET_KEY).unwrap()).unwrap();
        let aux_rand = parse_hex_32("aux", VECTOR_3_AUX_RAND).unwrap();
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let (public_key, _) = XOnlyPublicKey::from_keypair(&keypair);

        let signature =
            secp.sign_schnorr_with_aux_rand(&Message::from_digest(message), &keypair, &aux_rand);

        assert_eq!(
            encode_hex(&signature.serialize()).to_uppercase(),
            VECTOR_3_SIGNATURE
        );
        assert_eq!(
            secp.verify_schnorr(&signature, &Message::from_digest(message), &public_key),
            Ok(())
        );
    }

    #[test]
    fn parse_hex_32_rejects_incorrect_length() {
        assert!(parse_hex_32("message", "0x1234").is_err());
    }

    #[test]
    fn sign_payload_rejects_zero_secret_key() {
        let error =
            sign_payload([0u8; WORD_BYTES], [0u8; WORD_BYTES], [0u8; WORD_BYTES]).unwrap_err();

        assert_eq!(error, "secret key is out of range");
    }
}
