# sha2_fixed_64

A sha256 implementation optimised for 64 byte messages.

## Production Readiness

This module is **not production ready**, it still in experimental phases.

## Description

This library only supports hashing 64-byte messages. It uses an optimisation
described by [@potuz](https://github.com/potuz) in [this
document](https://hackmd.io/80mJ75A5QeeRcrNmqcuU-g).

The 64-byte message size makes this library perfect for computing the merkle
root of two 32-byte leaves.

This library only supports x86 and x86_64. It requires the following CPU
features:

- `sha`
- `sse2`
- `ssse3`
- `sse4.1`

The `x86::cpu_is_supported` function will return `true` if all these features
are advertised as supported by your system.

## License

Licensed under either of

- Apache License, Version 2.0
- MIT license

at your option.
