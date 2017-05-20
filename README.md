# ElGamal

El Gamal implementation. 

QuickCheck Tests currently passing sporadically, multiplicative homomorphism test fails when the product of the cipher texts results in a message that is  > Z\*p because that is the upper limit of decryption and is therefore intended behaviour. Usually this isn't a problem because the chosen primes are very large, test needs to be changed to more accurately reflect this.
