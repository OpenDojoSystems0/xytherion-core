package selfupdate

// PublicKey is the base64 ed25519 public key that must have signed every
// release (checksums.txt.sig or the self-hosted manifest). The private key
// lives outside this repository — on the maintainer's machine and in the
// XYTHERION_SIGNING_KEY secret of the release workflow.
const PublicKey = "pzfJPJ/w8jUkk0CQE8LFDoGKssiCEiIO4wvqLjRQsgA="
