module Main where
import ElGamal
import ZKP
import ShamirSecretSharing
import ThresholdElGamal
import Components

main :: IO ()
main = do
    -- Generate a 64 bit key pair
    (pub,prv) <- genKeys 64
    -- Generate split keys for 3 of 5 threshold encryption
    threshKeys <- genThresholdKeys pub prv 3 5
    -- Calculate verification keys for the threshold keys
    let verKeys = genVerificationKeys pub threshKeys
    -- Encrypt the number 20 with standard ElGamal
    ct@(CipherText (α,β)) <- standardEncrypt pub (PlainText 20)
    -- Calculate partial decryptions with all the threshold keys
    let part = (\x -> partialDecrypt x pub ct) <$> threshKeys
    -- Calculate the non interactive zero knowledge proofs associated with each decryption
    arr <- traverse (uncurry3 (nonInteractiveEqofDL pub ct)) $ zip3 threshKeys verKeys part
    -- Verify that the NIZKP are true
    let boolArr = uncurry3 (verifyZKPofDL pub ct) <$> zip3 arr verKeys part
    print boolArr
    -- Combine sufficient partial decryptions (4) to decrypt original cipher text (Outputs 20)
    print $ thresholdDecrypt pub ct (take 4 part)
