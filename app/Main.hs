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

    threshKeys <- genThresholdKeys prv 3 5
    let verKeys = genVerificationKeys pub threshKeys

    ct@(CipherText (α,β)) <- standardEncrypt pub (PlainText 20)
    let part = (\x -> partialDecrypt x pub ct) <$> threshKeys
    nizkpdl <- nonInteractiveEqofDL pub ct (head threshKeys) (head verKeys) (head part)
    print $ verifyZKPofDL pub ct nizkpdl (head verKeys) (head part)
    arr <- traverse (uncurry3 (nonInteractiveEqofDL pub ct)) $ zip3 threshKeys verKeys part
    let boolArr = uncurry3 (verifyZKPofDL pub ct) <$> zip3 arr verKeys part
    print boolArr
    print $ thresholdDecrypt pub ct (take 4 part)
