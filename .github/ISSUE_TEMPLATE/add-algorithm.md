---
name: Add algorithm
about: Suggest adding an algorithm implementation & dependency
title: "[ADD] ALGORITHM NAME"
labels: add algorithm
assignees: ''

---

**What is the name of the algorithm you would like to see added?**
_Single line algorithm name, same as in title_
e.g. x25519

**What type of algorithm is this?**
_Elliptic Curve (e.g. P-521) **OR** Encryption without Authentication Tag (e.g. AES-CBC) **OR** Encryption with Authentication Tag / AEAD (e.g. AES-GCM) **OR** Authentication (e.g. HMAC-SHA256)_
e.g. AEAD

**What rust libraries provide this algorithm?**
_One or more rust crate names_
e.g. x25519-dalek

**Are there any caveats with using this algorithm and/or library that you know of?**
_No **OR** free text_
e.g. ChaCha20-Poly1305 uses a nonce length of 96 bits, which when randomly generated could have a collision. This does not apply to XChaCha20-Poly1305.

**Any additional information that you wish to provide:**
_Free text_
e.g. I am working on a rust app in my free time where I want to use ECIES with algorithm X.
