module ZKPSpec where

import Test.QuickCheck
import Test.QuickCheck.Monadic
import ZKP
import ShamirSecretSharing
import ThresholdElGamal
import ElGamalComponents
import ElGamal
import Test.Hspec
import Test.Hspec.Core.QuickCheck (modifyMaxSuccess)

instance Arbitrary PlainText where
    arbitrary = do
        pt <- (arbitrary :: Gen Integer) `suchThat` (> 0)
        return $ PlainText (pt `mod` 10)
        
spec :: Spec
spec = do
    describe "Checking ZKP Implementation" $ do
        modifyMaxSuccess (const 100) $ it "Checking Single Non Interactive ZKP for El Gamal" $ do
            property prop_SingleNonInteractiveZKP
        modifyMaxSuccess (const 100) $ it "Check Zk equality of discrete log" $ do
            property prop_EqualityOfDL

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
    threshKeys <- run $ genThresholdKeys pub prv lb ub
    let verKeys = genVerificationKeys pub threshKeys
    ct <- run $ standardEncrypt pub pt
    let part = (\key -> partialDecrypt key pub ct) <$> threshKeys
    arr <- run $ traverse (uncurry3 (nonInteractiveEqofDL pub ct)) $ zip3 threshKeys verKeys part
    let boolArr = uncurry3 (verifyZKPofDL pub ct) <$> zip3 arr verKeys part
    assert $ condenseTruths boolArr
    run (checkEqualityOfDL pub ct (head threshKeys) (head verKeys) (head part)) >>= assert
    nizkpdl <- run $ nonInteractiveEqofDL pub ct (head threshKeys) (head verKeys) (head part)
    assert $ verifyZKPofDL pub ct nizkpdl (head verKeys) (head part)

condenseTruths :: [Bool] -> Bool
condenseTruths []   = False
condenseTruths xs
    | not (null fls) = False
    | otherwise = True
    where
        fls = filter (== False) xs
