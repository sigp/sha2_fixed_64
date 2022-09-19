pub mod safe;
pub mod sha_ni;

#[cfg(test)]
mod tests {
    use super::*;
    use digest::Digest;
    use sha2::Sha256;

    const MESSAGE_ALL_42: [u8; 64] = [42; 64];
    const MESSAGE_ALL_256: [u8; 64] = [255; 64];

    #[test]
    fn safe_message_all_256() {
        let mut digest = Sha256::new();
        digest.update(MESSAGE_ALL_256);
        let reference: [u8; 32] = digest.finalize().into();

        let tested = safe::sha256(&MESSAGE_ALL_256);
        assert_eq!(reference, tested);
    }

    #[test]
    fn sha_ni_message_all_256() {
        // The tests will always fail with a SIGILL if the CPU doesn't support sha instructions.
        if !sha_ni::cpu_is_supported() {
            return;
        }

        let mut digest = Sha256::new();
        digest.update(MESSAGE_ALL_256);
        let reference: [u8; 32] = digest.finalize().into();

        let tested = sha_ni::sha256(&MESSAGE_ALL_256);
        assert_eq!(reference, tested);
    }

    #[test]
    fn sha_ni_message_all_42() {
        // The tests will always fail with a SIGILL if the CPU doesn't support sha instructions.
        if !sha_ni::cpu_is_supported() {
            return;
        }

        let mut digest = Sha256::new();
        digest.update(MESSAGE_ALL_42);
        let reference: [u8; 32] = digest.finalize().into();

        let tested = sha_ni::sha256(&MESSAGE_ALL_42);
        assert_eq!(reference, tested);
    }
}
