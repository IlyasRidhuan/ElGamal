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
    (ay,bz,z,e) <- nonInteractiveEqofDL pub ct (head threshKeys) (head verKeys) (head part)
    arr <- traverse (uncurry3 (nonInteractiveEqofDL pub ct)) $ zip3 threshKeys verKeys part
    let boolArr = uncurry3 (uncurry4 (verifyZKPofDL pub ct)) <$> zip3 arr verKeys part
    print $ verifyZKPofDL pub ct ay bz z e (head verKeys) (head part)
    print $ thresholdDecrypt pub ct (take 4 part)

uncurry3 :: (a -> b -> c -> d) -> ((a,b,c) -> d)
uncurry3 f (x,y,z)  = f x y z

uncurry4 :: (a -> b -> c -> d -> e) -> ((a,b,c,d) -> e)
uncurry4 f (w,x,y,z)  = f w x y z
