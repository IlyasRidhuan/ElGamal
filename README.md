# ElGamal

##### What's included
- [x] ElGamal (Multiplicative)
- [x] Modified ElGamal (Additive)
- [x] Threshold Encryption (m-of-n)
- [x] Elliptic Curve El Gamal 
- [ ] Zero Knowledge Proof of Correct Encryption (Honest Verfier)



### Introduction
The [ElGamal Cryptosystem](https://en.wikipedia.org/wiki/ElGamal_encryption) is an asymmetric public key encryption scheme based on the Diffie-Hellman key exchange. Its security is based on the intractability of computing discrete logarithms for a large prime modulus. While ElGamal is naturally multiplicatively homomorphic, a modification to the message structure can be made to result in an additively homomorphic scheme (modified ElGamal).

### Implementation
#### Key Generation
- Generate a [safe prime](https://en.wikipedia.org/wiki/Safe_prime) p, alternatively generate a [Sophie Germain](https://en.wikipedia.org/wiki/Sophie_Germain_prime) q such that p = 2q + 1 and both p & q primes.
- Find a generator, g such that it will generate the cyclic group G with order q and not any other subgroup of <img alt="$Z_q^*$" src="svgs/bad65ca5b95ca10bebf387ce7d2f3c39.png?invert_in_darkmode" align=middle width="19.06542pt" height="22.59873pt"/> where <img alt="$Z_q^*$" src="svgs/bad65ca5b95ca10bebf387ce7d2f3c39.png?invert_in_darkmode" align=middle width="19.06542pt" height="22.59873pt"/> is the list of invertible elements less than q, i.e (1,..,q-1). [Helpful link](https://crypto.stackexchange.com/questions/1451/elgamal-multiplicative-cyclic-group-and-key-generation)
- Calculate <img alt="$y \;=\; g^x \;mod ;p$" src="svgs/5c8686f0d14d2a752a913fb747764440.png?invert_in_darkmode" align=middle width="107.234655pt" height="22.74591pt"/>
- The public key is < p,q,g,y >
- The private key is <img alt="$x \in Z_q$" src="svgs/e9e624fcf41c4630a0164aeb9ba07a8b.png?invert_in_darkmode" align=middle width="47.00355pt" height="22.38192pt"/>

#### Encryption
- Randomly select an <img alt="$r \in_R Z_q$" src="svgs/8a541791da5db32a5be6a9a36ab43181.png?invert_in_darkmode" align=middle width="56.27259pt" height="22.38192pt"/>
- Encrypt a plaintext <img alt="$ s \in Z_p^*$" src="svgs/7bf830a510b4311ade60ac4e65222c2a.png?invert_in_darkmode" align=middle width="46.79235pt" height="22.59873pt"/> to a corresponding ciphertext <img alt="$ c \;=\; (\alpha,\beta)$" src="svgs/efa2c23e7c6ab7c7bc464a540128e7a5.png?invert_in_darkmode" align=middle width="78.78387pt" height="24.56553pt"/> where <img alt="$\alpha \;=\; g^r mod\;p$" src="svgs/73402890045bee25e8e330bbc1cb0be6.png?invert_in_darkmode" align=middle width="100.866975pt" height="22.74591pt"/> and <img alt="$\beta \;=\; sy^r\;mod\;p$" src="svgs/52eaf4d2393cb449b8e8d7fcd419d09a.png?invert_in_darkmode" align=middle width="112.92138pt" height="22.74591pt"/>

##### Modified ElGamal
- In the modified ElGamal <img alt="$\beta \;=\; g^sy^r mod\;p$" src="svgs/460d2c67cd7bd7693deb154c6752b5aa.png?invert_in_darkmode" align=middle width="116.10588pt" height="22.74591pt"/>

#### Decryption
- Decrypt some ciphertext <img alt="$ c\;=\; (\alpha,\beta)$" src="svgs/26c2ec4740177ec18525a733f2f1259e.png?invert_in_darkmode" align=middle width="78.78387pt" height="24.56553pt"/> using the private key x and computing <img alt="$ s \;=\; \beta \alpha^{-x} \; mod \; p$" src="svgs/0458aea0d44725e81cc893bfd971c49f.png?invert_in_darkmode" align=middle width="126.110325pt" height="26.12412pt"/> where <img alt="$\alpha^{-1}$" src="svgs/7ff57a80eaf78a5fcde21518bc960ecf.png?invert_in_darkmode" align=middle width="27.3009pt" height="26.70657pt"/> indicates the modular multiplicative inverse

##### Modified ElGamal
- In the modified ElGamal, decryption involves solving for the discrete log <img alt="$y\;=\; g^m$" src="svgs/9f4b7f5706fd802c78c8f88fe55dfad0.png?invert_in_darkmode" align=middle width="59.64354pt" height="21.80244pt"/>. While normally intractable the discrete log is feasible for small values of m <img alt="$(\approx \;&lt; \; 2^30)$" src="svgs/cab0ffe5a6bbe0ef0bd4cff48e6ca350.png?invert_in_darkmode" align=middle width="75.66273pt" height="26.70657pt"/>. Current implementation is a brute force search although will probably move to [Pollard's kangaroo algorithm](https://en.wikipedia.org/wiki/Pollard%27s_kangaroo_algorithm) when I find the time.

#### Threshold Encryption
##### Shamir Secret Sharing (SSS)
- The basic idea of SSS is a polynomial of degree n can be uniquely identified by (n-1) distinct points. By using [Lagrange polynomials](https://en.wikipedia.org/wiki/Lagrange_polynomial) we can guarantee that the for a set of points the lowest degree polynomial is in fact unique.

##### Threshold Decryption
- To use threshold encryption, each owner of a key split calculates the partial decryption <img alt="$z_j \; = \; \alpha^{x_j}$" src="svgs/0535f065cfccddd43dbfeee2f43dbde8.png?invert_in_darkmode" align=middle width="68.807805pt" height="21.80244pt"/> where <img alt="$x_j$" src="svgs/4d8443b72a1de913b4a3995119296c90.png?invert_in_darkmode" align=middle width="15.44169pt" height="14.10255pt"/> is the private key of their split
- The plaintext message can then be recovered from the partial decryption using <img alt="$ s \; = \; \frac{\beta}{\prod_{j \in S}z_j^{\mu_j}}$" src="svgs/fc80fbbc42cbb586b919a15f8eeee298.png?invert_in_darkmode" align=middle width="97.351815pt" height="30.58869pt"/> where S is the set of sufficient partial decryptions and <img alt="$\mu_j\;=\;\prod_{j' \in S \backslash j} \frac {j'} {j'-j}$" src="svgs/3ac4414b0f24b75d2334f8d1f357fee2.png?invert_in_darkmode" align=middle width="136.735005pt" height="33.6864pt"/>

#### Incorporating Zero Knowledge Proofs
##### Non Interactive Proof of Knowledge of Discrete logarithms
- Each owner of a key,<img alt="${x_j}$" src="svgs/ad9c7069b33d0fa6574a685243433ec2.png?invert_in_darkmode" align=middle width="15.44169pt" height="14.10255pt"/>, also calculates a verification key <img alt="$v_j \; = \; g ^{x_j} \;mod\;p$" src="svgs/224de9b621e581092a8ef264e7941fbf.png?invert_in_darkmode" align=middle width="116.89854pt" height="22.74591pt"/>
- Based on the [<img alt="$\Sigma$" src="svgs/813cd865c037c89fcdc609b25c465a05.png?invert_in_darkmode" align=middle width="11.82786pt" height="22.38192pt"/> Protocol](http://www.cs.au.dk/~ivan/Sigma.pdf) but extended for two logarithms, each partial decryption is accompanied by a proof of correct decryption using a zero-knowledge proof of equality of discrete logarithms (<img alt="$\log_g(v_j) = \log_\alpha (z_j)$" src="svgs/74c9150e8cc56bfd8f604194573c1db8.png?invert_in_darkmode" align=middle width="136.2339pt" height="24.56553pt"/>)
- The normally interactive proof is made non-interactive using the [Fiat-Shamir](https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic) heurtistic where the collision-resistant hashing function used in this case is SHA256
