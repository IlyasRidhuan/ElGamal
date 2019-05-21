{-# OPTIONS_GHC -fno-warn-orphans #-}

module ElGamalSpec where

import Test.QuickCheck
import Test.QuickCheck.Monadic
import ElGamal
import ElGamalComponents
import Data.Bits
import Crypto.Number.Generate
import Test.Hspec
import Test.Hspec.Core.QuickCheck (modifyMaxSuccess)


newtype ValidBits = ValidBits {unValidBits :: Int} deriving Show

instance Arbitrary PlainText where
    arbitrary = do
        pt <- (arbitrary :: Gen Integer) `suchThat` (> 0)
        return $ PlainText (pt `mod` 10)

instance Arbitrary ValidBits where
    arbitrary = (arbitrary :: Gen Int) `suchThat` (\x_ -> ((>0) x_) && ((<58) . countLeadingZeros) x_) >>= return . ValidBits

spec :: Spec
spec = do
    describe "Check Correctness of El Gamal Commitment" $ do
        modifyMaxSuccess (const 1000) $ it "Check that decrypt . encrypt is an identity" $ do
            property prop_EncryptDecrypt
        modifyMaxSuccess (const 1000) $ it "Check additive homomorphism works" $ do
            property prop_AdditiveHomomorphism
        modifyMaxSuccess (const 1000) $ it "Check multiplicative homomorphism works" $ do
            property prop_MultiplicativeHomomorphism




prop_EncryptDecrypt :: ValidBits -> PlainText -> Property
prop_EncryptDecrypt bits pt@(PlainText plain) = monadicIO $ do
    (pub,prv) <- run $ genKeys (unValidBits bits)
    r <- run $ generateMax (q pub)
    Just (PlainText decryptedP) <- return $ modifiedDecrypt prv pub $ (modifiedEncryptWithR pub r pt)
    assert $ plain == decryptedP

prop_MultiplicativeHomomorphism :: ValidBits -> PlainText -> PlainText -> Property
prop_MultiplicativeHomomorphism bits pt1@(PlainText plain1) pt2@(PlainText plain2) = monadicIO $ do
    (pub,prv) <- run $ genKeys (unValidBits bits)
    ct <- run $ standardEncrypt pub pt1
    ct' <- run $ standardEncrypt pub pt2
    let rt = binOp pub ct ct'
    Just (PlainText decryptedMultiple) <- return $ standardDecrypt prv pub rt
    assert $ decryptedMultiple == (plain1*plain2)

prop_AdditiveHomomorphism :: ValidBits -> PlainText -> PlainText -> Property
prop_AdditiveHomomorphism bits pt1@(PlainText plain1) pt2@(PlainText plain2) = monadicIO $ do
    (pub,prv) <- run $ genKeys (unValidBits bits)
    ct <- run $ modifiedEncrypt pub pt1
    ct' <- run $ modifiedEncrypt pub pt2
    let rt = binOp pub ct ct'
    Just (PlainText decryptedAddition) <- return $ modifiedDecrypt prv pub rt
    assert $ decryptedAddition == (plain1 + plain2)

-- prop_CheckPollardRho :: ValidBits -> PlainText -> Property
-- prop_CheckPollardRho bits pt = monadicIO $ do
--     (pub,prv) <- run $ genKeys (unValidBits bits)
--     ct <- run $ modifiedEncrypt pub pt
--     Just (PlainText p1) <- run $ return $ modifiedDecrypt prv pub ct 
--     (PlainText p2) <- run $ modifiedDecrypt' prv pub ct
--     assert $ p1 == p2

prop_CheckExponentiation :: ValidBits -> PlainText -> Property
prop_CheckExponentiation bits pt@(PlainText plain) = monadicIO $ do
    (pub,prv) <- run $ genKeys (unValidBits bits)
    r <- run $ generateMax (q pub)
    let ct = modifiedEncryptWithR pub r pt
        ct' = expOp pub ct 2
    Just (PlainText p2) <- run $ return $ modifiedDecrypt prv pub ct'
    assert $ p2 == (plain*2)

