# libes
![Crates.io](https://img.shields.io/crates/l/libes?style=flat)
[![GitHub last commit](https://img.shields.io/github/last-commit/TJRoh01/libes?style=flat)](https://github.com/TJRoh01/libes)
[![Crates.io](https://img.shields.io/crates/v/libes?style=flat)](https://crates.io/crates/libes)
[![docs.rs](https://img.shields.io/docsrs/libes/latest?style=flat)](https://docs.rs/libes/latest/libes)
[![Libraries.io](https://img.shields.io/librariesio/release/cargo/libes?style=flat)](https://libraries.io/cargo/libes)

**lib**rary of **e**ncryption **s**cheme(s) is a collection of ECIES variants.

The goal of this is library is to become a one-stop shop for everything ECIES.

For code documentation, usage explanations, and examples please see [Docs.rs](https://docs.rs/libes/latest/libes/).

## ⚠️ Beta Release Track - Not Production Ready ⚠️
During beta development, versions 0.2+.Z, backwards compatibility for decryption is guaranteed.

This means that data encrypted using library version X.Y.Z can be decrypted using any superseding library version as
long as X is the same, even if the algorithm used for encryption was yanked it will still be available for decryption
until X is incremented.

The public API structure will not change, but algorithms that are potentially found to be broken for any reason will be
immediately removed and the library will be released with an incremented Y in X.Y.Z, and versions implementing that
algorithm will be yanked.

The private API is still under development, so make sure that you always use the latest version 0.Y.Z to receive
all patches that are released. An incremented Z in X.Y.Z will not require any modifications in your code, of course
with the exception for an algorithm being yanked.

## Why use libes?
The rust cryptography ecosystem is swarming with crates, with varying degrees of quality and documentation. I have taken
it onto myself to navigate this, and I want to share my findings with those who are trying to make sense of it like me.

In doing this I commit myself to:
- Maintaining a curated selection of relevant crates
  - Verifying that dependencies have not made mistakes in their implementations
  - Using dependencies with good performance and a high quality of code and documentation
- Providing a uniform and predictable API
  - Using shared constructors in the API to guarantee uniformity
  - Guaranteeing long-term support for all major releases
  - Striving for a high degree of clarity and detail in the documentation
- Keeping the library up to date & vulnerability-free
  - Automatically updating dependencies and testing code
  - Prioritizing issues & feedback on implementations

# Table of Contents
<!-- TOC -->
* [libes](#libes)
  * [Why use libes?](#why-use-libes)
* [Table of Contents](#table-of-contents)
* [FAQ](#faq)
* [About](#about)
  * [What is ECIES?](#what-is-ecies)
  * [ECIES Variants](#ecies-variants)
  * [ECIES-MAC Flowchart](#ecies-mac-flowchart)
  * [ECIES-AEAD Flowchart](#ecies-aead-flowchart)
  * [ECIES-SYN Flowchart](#ecies-syn-flowchart)
  * [SemVer](#semver)
  * [Release Tracks](#release-tracks)
  * [Conditional Compilation](#conditional-compilation)
* [Algorithm support](#algorithm-support)
  * [Support icon legend](#support-icon-legend)
  * [Elliptic Curve Support Matrix](#elliptic-curve-support-matrix)
  * [Encryption Support Matrix](#encryption-support-matrix)
  * [Authentication Support Matrix](#authentication-support-matrix)
* [License](#license)
* [Contributing](#contributing)
<!-- TOC -->

# FAQ
TBD

# About
## What is ECIES?
ECIES stands for **E**lliptic **C**urve **I**ntegrated **E**ncryption **S**cheme. It is a type of cryptographic
procedure which allows encrypting data for a specific recipient given only the data to be encrypted and the recipients
public key, everything else is derived from the input or generated using a
CSPRNG (**C**ryptographically **S**ecure **P**seudo-**R**andom **N**umber **G**enerator).

[Wikipedia](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme)  
[Crypto++](https://www.cryptopp.com/wiki/Elliptic_Curve_Integrated_Encryption_Scheme)  
[Practical Cryptography for Developers](https://cryptobook.nakov.com/asymmetric-key-ciphers/ecies-public-key-encryption)

## ECIES Variants
Cryptographic algorithms have evolved over time, and thus have grown into two distinct ECIES variants as of writing.

Originally, ECIES relied on a key exchange operation, an encryption operation, and a separate MAC operation.

A MAC (**M**essage **A**uthentication **C**ode) is necessary to provide **Authenticity** on top of **Confidentiality**.
By exploiting vulnerabilities and/or compromised parameters, encrypted data could potentially be manipulated to produce
a desired output, other than what the sender intended. A MAC can be used separately from the encrypted data to verify
that such manipulation did not take place.

More recently adopted encryption algorithms like AES256-GCM and ChaCha20-Poly1305 are
AEAD (**A**uthenticated **E**ncryption with **A**dditional **D**ata) algorithms which in addition to a ciphertext,
also produce an Authentication Tag which serves the same purpose that a MAC does in this case, but is integrated in the
encryption algorithm itself.

The library and documentation will refer to these two variants as:
- **ECIES-MAC** (Encryption with MAC)
- **ECIES-AEAD** (AEAD Encryption instead of MAC)

Iterating further on ECIES-AEAD, it could be further integrated by **synthesizing** the IV/Nonce rather than
**generating** it randomly. This would eliminate the need to store & transmit the IV/Nonce, as well as reduce the
overhead by one or two dozen bytes. Because there is already random data in the ephemeral key, the risk of deriving the
same IV/Nonce twice is about equivalent with generating it randomly, and thus it should be safe to do so.
This third variant will be referred to as **ECIES-SYN**.

**DISCLAIMER:** ECIES-SYN has not received a security audit! ECIES-SYN is my own idea, which I will only implement for
algorithms that I have done extensive research on to ensure that it is cryptographically secure to do so.
Regardless, I am not a cryptography researcher and I can not give a guarantee that issues will not arise in the future.
If ECIES-SYN turns out to be useful/popular and resources allow, I will make sure that it receives a security audit.

## ECIES-MAC Flowchart
See the README.md on [GitHub](https://github.com/TJRoh01/libes/blob/main/README.md#ecies-mac-flowchart).

## ECIES-AEAD Flowchart
See the README.md on [GitHub](https://github.com/TJRoh01/libes/blob/main/README.md#ecies-aead-flowchart).

## ECIES-SYN Flowchart
See the README.md on [GitHub](https://github.com/TJRoh01/libes/blob/main/README.md#ecies-syn-flowchart).

## SemVer
This library respects SemVer, and guarantees decryption backwards compatibility.

This means that data encrypted using library version X.Y.Z can be decrypted using any superseding library version as
long as X is the same.

For example, data encrypted using version 0.5.7 can be decrypted using version 0.5.7 or 0.11.1, but not using versions
1.2.3, 0.5.6, or 0.4.10.

Effort will be made to keep X, the major version, decryption backwards compatible as well, but no guarantee is given.

## Release Tracks
- v0.1.Z: alpha - initial strcuture
- v0.(2+).Z: beta - adding algorithms, memory zeroing, and other features
- v1.0.0-pre.W: pre-production - refactoring
- v1.0.0: initial production - potentially backwards-incompatible refactoring
- V1.(1+).Z: production - wasm support & more

## Conditional Compilation
All algorithm combinations are gated behind features, to reduce how much is being compiled. Features are named exactly
like the algorithm names in the support matrices (if there are alternative names like P-521 and secp521r1 then they are
aliases, so you can enable either). This library uses traits to implement appropriate functionality on valid
user-defined variants.

**NOTE:** No ECIES variants are available without activating any features,
at minimum one of each feature categories must be activated:
- Elliptic Curve (e.g. x25519)
- Encryption (e.g. AES256-GCM)
- Authentication (e.g. ECIES-AEAD or HMAC-SHA256)

**NOTE:** For a ECIES combination to be valid the Elliptic Curve, Encryption,
and Authentication algorithms must all support the same ECIES variant.
- To use ECIES-MAC, all three chosen algorithms need a "🚀" in their respective ECIES-MAC columns
- To use ECIES-AEAD or ECIES-SYN both first two algorithms need a "🚀" in the ECIES-variant column

# Algorithm support
Matrix entries are of form `Encryption & Decryption` or `Encryption`/`Decryption`

## Support icon legend
- 🚀 Completed
- 🏗️ Development
- 📅 Planned
- 🤔 Planning
- 🚫 Can/Will not implement

## Elliptic Curve Support Matrix
| Algorithm/ECIES Variant | ECIES-MAC | ECIES-AEAD | ECIES-SYN |
|:-----------------------:|:---------:|:----------:|:---------:|
|         x25519          |    🚀     |     🚀     |    🚀     |
|         ed25519         |    🚀     |     🚀     |    🚀     |
|    K-256 / secp256k1    |    🚀     |     🚀     |    🚀     |
|    P-256 / secp256r1    |    🚀     |     🚀     |    🚀     |
|    P-384 / secp384r1    |    🚀     |     🚀     |    🚀     |
|    P-521 / secp521r1    |    🤔     |     🤔     |    🤔     |

## Encryption Support Matrix
| Algorithm/ECIES Variant | ECIES-MAC | ECIES-AEAD | ECIES-SYN |
|:-----------------------:|:---------:|:----------:|:---------:|
|    ChaCha20-Poly1305    |    🚀     |     🚀     |    🚀     |
|   XChaCha20-Poly1305    |    🚀     |     🚀     |    🚀     |
|       AES128-GCM        |  🚫[^1]   |   🚫[^1]   |  🚫[^1]   |
|       AES256-GCM        |    🚀     |     🚀     |    🚀     |

## Authentication Support Matrix
| Algorithm/ECIES Variant | ECIES-MAC |
|:-----------------------:|:---------:|
|       HMAC-SHA256       |    🚀     |
|       HMAC-SHA512       |    🤔     |

[^1]: AES128-GCM uses a 128-bit key and a 96-bit nonce, and when using a CSPRNG as the de-facto source to generate them,
the collision risk in a 224-bit space is unsatisfactory. Due to this encryption is not implemented, along with decryption
in order to not encourage using this variant in other libraries. **Note:** like AES128-GCM, AES256-GCM and some other
encryption algorithms in this library also use a 96-bit nonce, but unlike AES256-GCM they have larger keys like 256 bits,
which when combined with a 96-bit nonce makes the collision risk acceptable.

# License
Licensed under either of:
- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

# Contributing
All contributions are very appreciated.

- If you spot a mistake or a vulnerability in this crate or any of its dependencies please open an issue with the
  **Fix algorithm** template
- If you want to suggest adding support for a new algorithm, please use the **Add algorithm** template
- If you believe support for an algorithm should be deprecated, please use the **Deprecate algorithm** template

For all other issues, please try to include enough information so that it is possible to determine what to do or plan
without having to ask too many follow-up questions.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you,
as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
