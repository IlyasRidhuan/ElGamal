{-# LANGUAGE RecordWildCards #-}
module Main where
import ElGamal
import ZKP
import ShamirSecretSharing
import ThresholdElGamal
import Components

import Crypto.Number.ModArithmetic
import Crypto.Number.Generate
import Crypto.Random.Types


main :: IO ()
main = do
    -- Generate a 64 bit key pair
    (pub,prv) <- genKeys 64

    threshKeys <- genThresholdKeys prv 3 5
    let verKeys = genVerificationKeys pub threshKeys

    ct@(CipherText (α,β)) <- standardEncrypt pub (PlainText 20)
    let part = (\x -> partialDecrypt x pub ct) <$> threshKeys
    (ay,bz,z) <- nonInteractiveEqofDL pub ct (head threshKeys) (head verKeys) (head part)
    print $ verifyZKPofDL pub ct ay bz z
    print $ thresholdDecrypt pub ct (take 4 part)
