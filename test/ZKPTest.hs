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
    quickCheckWith stdArgs { maxSuccess = 100 } prop_SingleNonInteractiveZKP
    quickCheckWith stdArgs { maxSuccess = 100 } prop_EqualityOfDL

prop_SingleNonInteractiveZKP :: Property
prop_SingleNonInteractiveZKP = monadicIO $ do
    bits <- Test.QuickCheck.Monadic.run $ generate $ abs <$> (arbitrary :: Gen Int) `suchThat` (> 10)
    (pub,prv) <- Test.QuickCheck.Monadic.run $ genKeys bits
    run (sigmaProtocol prv pub) >>= assert
    verifyZKP pub <$> run (nonInteractiveZKP prv pub)  >>= assert

prop_EqualityOfDL :: PlainText -> Property
prop_EqualityOfDL pt = monadicIO $ do
    bits <- run $ generate $ abs <$> (arbitrary :: Gen Int) `suchThat` (> 10)
    (pub,prv) <- run $ genKeys bits
    ub <- run $ generate ( choose (5,20) :: Gen Integer)
    lb <- run $ generate ( choose (3,ub) :: Gen Integer)
    threshKeys <- run $ genThresholdKeys prv lb ub
    let verKeys = genVerificationKeys pub threshKeys
    ct@(CipherText (α,β)) <- run $ standardEncrypt pub pt
    let part = (\x -> partialDecrypt x pub ct) <$> threshKeys
    run (checkEqualityOfDL pub ct (head threshKeys) (head verKeys) (head part)) >>= assert
    (ay,bz,z,e) <- run $ nonInteractiveEqofDL pub ct (head threshKeys) (head verKeys) (head part)
    assert $ verifyZKPofDL pub ct ay bz z e (head verKeys) (head part)

genPos :: Gen Integer
genPos = abs <$> (arbitrary :: Gen Integer) `suchThat` ( > 0)
