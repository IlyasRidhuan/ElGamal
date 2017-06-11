# ElGamal

##### What's included
- [x] ElGamal (Multiplicative)
- [x] Modified ElGamal (Additive)
- [x] Threshold Encryption (m-of-n)
- [x] Zero Knowledge Proof of Correct Decryption (Honest Verfier)
- [ ]  Zero Knowledge Proof of Correct Encryption (For binary decisions)


### Introduction
The [ElGamal Cryptosystem](https://en.wikipedia.org/wiki/ElGamal_encryption) is an asymmetric public key encryption scheme based on the Diffie-Hellman key exchange. Its security is based on the intractability of computing discrete logarithms for a large prime modulus. While ElGamal is naturally multiplicatively homomorphic, a modification to the message structure can be made to result in an additively homomorphic scheme (modified ElGamal).

### Implementation
#### Key Generation
- Generate a [safe prime](https://en.wikipedia.org/wiki/Safe_prime) p, alternatively generate a [Sophie Germain](https://en.wikipedia.org/wiki/Sophie_Germain_prime) q such that p = 2q + 1 and both p & q primes.
- Find a generator, g such that it will generate the cyclic group G with order q and not any other subgroup of <img alt="$Z_q^*$" src="svgs/bad65ca5b95ca10bebf387ce7d2f3c39.png?2043995847&invert_in_darkmode" align=middle width="19.06542pt" height="22.59873pt"/> where <img alt="$Z_q^*$" src="svgs/bad65ca5b95ca10bebf387ce7d2f3c39.png?222c9bcdc4&invert_in_darkmode" align=middle width="19.06542pt" height="22.59873pt"/> is the list of invertible elements less than q, i.e (1,..,q-1). [Helpful link](https://crypto.stackexchange.com/questions/1451/elgamal-multiplicative-cyclic-group-and-key-generation)
- Calculate <img alt="$y = g^x mod p$" src="svgs/f04fec5cb9b012a4fb0e909f4ec33ee6.png?3660614278&invert_in_darkmode" align=middle width="86.24748pt" height="22.74591pt"/>
- The public key is < p,q,g,y >
- The private key is <img alt="$x \in Z_q$" src="svgs/e9e624fcf41c4630a0164aeb9ba07a8b.png?1dd87a1972&invert_in_darkmode" align=middle width="47.00355pt" height="22.38192pt"/>

#### Encryption
- Randomly select an <img alt="$r \in_R Z_q$" src="svgs/8a541791da5db32a5be6a9a36ab43181.png?b3b99e26ab&invert_in_darkmode" align=middle width="56.27259pt" height="22.38192pt"/>
- Encrypt a plaintext <img alt="$ s \in Z_p^*$" src="svgs/7bf830a510b4311ade60ac4e65222c2a.png?a6a1fdc2f9&invert_in_darkmode" align=middle width="46.79235pt" height="22.59873pt"/> to a corresponding ciphertext <img alt="$ c \;=\; (\alpha,\beta)$" src="svgs/efa2c23e7c6ab7c7bc464a540128e7a5.png?af5b59eb57&invert_in_darkmode" align=middle width="78.78387pt" height="24.56553pt"/> where <img alt="$\alpha \;=\; g^r mod\;p$" src="svgs/73402890045bee25e8e330bbc1cb0be6.png?d27503c3f0&invert_in_darkmode" align=middle width="100.866975pt" height="22.74591pt"/> and <img alt="$\beta \;=\; sy^r mod p$" src="svgs/d50eb462570e80e2f547e3abc09365d6.png?d5474e35b4&invert_in_darkmode" align=middle width="103.789125pt" height="22.74591pt"/>

##### Modified Elgamal
- In the modified ElGamal <img alt="$\beta \;=\; g^sy^r mod\;p$" src="svgs/460d2c67cd7bd7693deb154c6752b5aa.png?bbf239da2a&invert_in_darkmode" align=middle width="116.10588pt" height="22.74591pt"/>

#### Decryption
- Decrypt some ciphertext <img alt="$ c\;=\; (\alpha,\beta)$" src="svgs/26c2ec4740177ec18525a733f2f1259e.png?7076d10e27&invert_in_darkmode" align=middle width="78.78387pt" height="24.56553pt"/> using the private key x and computing <img alt="$ s \;=\; \beta \alpha^{-x} \; mod \; p$" src="svgs/0458aea0d44725e81cc893bfd971c49f.png?899c2f1012&invert_in_darkmode" align=middle width="126.110325pt" height="26.12412pt"/> where <img alt="$\alpha^{-1}$" src="svgs/7ff57a80eaf78a5fcde21518bc960ecf.png?85fcc91b4b&invert_in_darkmode" align=middle width="27.3009pt" height="26.70657pt"/> indicates the modular multiplicative inverse
