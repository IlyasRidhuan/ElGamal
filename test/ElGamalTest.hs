{-# OPTIONS_GHC -fno-warn-orphans #-}

module ElGamalTest where

import Test.QuickCheck
import Test.QuickCheck.Monadic
import ElGamal
import ElGamalComponents
import Data.Bits

newtype ValidBits = ValidBits {unValidBits :: Int} deriving Show

instance Arbitrary PlainText where
    arbitrary = do
        pt <- (arbitrary :: Gen Integer) `suchThat` (> 0)
        return $ PlainText pt

instance Arbitrary ValidBits where
    arbitrary = (arbitrary :: Gen Int) `suchThat` (\x_ -> ((>0) x_) && ((<58) . countLeadingZeros) x_) >>= return . ValidBits

prop_EncryptDecrypt :: ValidBits -> PlainText -> Property
prop_EncryptDecrypt bits pt@(PlainText plain) = monadicIO $ do
    (pub,prv) <- run $ genKeys (unValidBits bits)
    Just (PlainText decryptedP) <- run $ standardDecrypt prv pub <$> standardEncrypt pub pt
    assert $ plain == decryptedP

prop_MultiplicativeHomomorphism :: ValidBits -> PlainText -> PlainText -> Property
prop_MultiplicativeHomomorphism bits pt1@(PlainText plain1) pt2@(PlainText plain2) = monadicIO $ do
    (pub,prv) <- run $ genKeys (unValidBits bits)
    ct <- run $ standardEncrypt pub pt1
    ct' <- run $ standardEncrypt pub pt2
    let rt = ct * ct'
    Just (PlainText decryptedMultiple) <- return $ standardDecrypt prv pub rt
    assert $ decryptedMultiple == (plain1*plain2)

prop_AdditiveHomomorphism :: ValidBits -> PlainText -> PlainText -> Property
prop_AdditiveHomomorphism bits pt1@(PlainText plain1) pt2@(PlainText plain2) = monadicIO $ do
    (pub,prv) <- run $ genKeys (unValidBits bits)
    ct <- run $ modifiedEncrypt pub pt1
    ct' <- run $ modifiedEncrypt pub pt2
    let rt = ct * ct'
    Just (PlainText decryptedAddition) <- return $ modifiedDecrypt prv pub rt
    assert $ decryptedAddition == (plain1 + plain2)
