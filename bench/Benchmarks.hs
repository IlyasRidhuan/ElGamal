module Main where

import Gauge.Main
-- import Gauge.Main.Options
-- import Test.QuickCheck
import ElGamalComponents
import ElGamal


main :: IO ()
main = do
    (pp,prv) <- genKeys 64
    let bit8 = modifiedEncryptWithR pp 10 $ PlainText  (2^(7 :: Integer))
    let bit16 = modifiedEncryptWithR pp 10 $ PlainText (2^(15 :: Integer))
        bit32 = modifiedEncryptWithR pp 10 $ PlainText (2^(31 :: Integer))
        bit64 = modifiedEncryptWithR pp 10 $ PlainText (2^(63 :: Integer))
        curriedDecrypt = modifiedDecrypt prv pp
        curriedDecrypt' = modifiedDecrypt' prv pp

    defaultMain [
        bgroup "Naive Decryption" [
            bench "Decrypting 8bit number" $ nf curriedDecrypt bit8,
            bench "Decrypting 16bit number" $ nf curriedDecrypt bit16
            ],
        bgroup "Rho Decryption" [
            bench "Decrypting 8bit number" $ nfIO $ curriedDecrypt' bit8,
            bench "Decrypting 16bit number" $ nfIO $ curriedDecrypt' bit16,
            bench "Decrypting 32bit number" $ nfIO $ curriedDecrypt' bit32,
            bench "Decrypting 64bit number" $ nfIO $ curriedDecrypt' bit64
            ]
        ]
