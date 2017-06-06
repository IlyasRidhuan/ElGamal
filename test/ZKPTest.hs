module ZKPTest where

import Test.QuickCheck
import Test.QuickCheck.Monadic
import ZKP
import ShamirSecretSharing
import ThresholdElGamal hiding (run)
import Components
import ElGamal
import Crypto.Number.Generate
import Crypto.Number.ModArithmetic


instance Arbitrary PlainText where
    arbitrary = do
        pt <- (arbitrary :: Gen Integer) `suchThat` (> 0)
        return $ PlainText pt

testZKP :: IO ()
testZKP = do
    quickCheckWith stdArgs { maxSuccess = 100 } prop_SingleInteractiveZKP
    quickCheckWith stdArgs { maxSuccess = 100 } prop_EqofDLZKP

prop_SingleInteractiveZKP :: Property
prop_SingleInteractiveZKP = monadicIO $ do
    bits <- Test.QuickCheck.Monadic.run $ generate $ abs <$> (arbitrary :: Gen Int) `suchThat` (> 10)
    (pub,prv) <- Test.QuickCheck.Monadic.run $ genKeys bits
    run (sigmaProtocol prv pub) >>= assert
    verifyZKP pub <$> run (nonInteractiveZKP prv pub)  >>= assert

genPos :: Gen Integer
genPos = abs <$> (arbitrary :: Gen Integer) `suchThat` ( > 0)

prop_EqofDLZKP :: PlainText -> Property
prop_EqofDLZKP pt = monadicIO $ do
    bits <- run $ generate $ abs <$> (arbitrary :: Gen Int) `suchThat` (> 10)
    (pub,prv) <- run $ genKeys bits
    -- ub <- run $ generate (genPos `suchThat` ( < 5))
    -- lb <- run $ generate $ (genPos `suchThat` ( < ub))
    threshKeys <- run $ genThresholdKeys prv 9 10
    let verKeys = genVerificationKeys pub threshKeys

    ct@(CipherText (α,β)) <- run $ standardEncrypt pub pt
    let part = (\x -> partialDecrypt x pub ct) <$> threshKeys
    run (checkEqualityOfDL pub ct (head threshKeys) (head verKeys) (head part)) >>= assert
