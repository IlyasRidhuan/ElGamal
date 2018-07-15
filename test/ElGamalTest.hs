module ElGamalTest where

import Test.QuickCheck
import Test.QuickCheck.Monadic
import Data.Maybe
import ElGamal
import Control.Monad.IO.Class
import ElGamalComponents

-- monadic fromJust $
instance Arbitrary PlainText where
    arbitrary = do
        pt <- (arbitrary :: Gen Integer) `suchThat` (> 0)
        return $ PlainText pt

newpropEncryptDecrypt :: PlainText -> Property
newpropEncryptDecrypt pt@(PlainText plain) =  monadicIO $ do
    bits <- run $ generate $ abs <$> (arbitrary :: Gen Int) `suchThat` (> 10)
    -- run $ print bits
    (pub,prv) <- run $ genKeys bits
    Just (PlainText p) <- run $ standardDecrypt prv pub <$> standardEncrypt pub pt
    assert $ plain == p

prop_EncryptDecrypt :: PublicKey -> PrivateKey -> PlainText -> Property
prop_EncryptDecrypt pub prv pt@(PlainText plain) = monadicIO $ do
    -- let ct = CipherText (10,10)
    Just (PlainText p) <- run $ standardDecrypt prv pub <$> standardEncrypt pub pt
    assert $ plain == p

prop_MultiplicativeHomomorphism :: PlainText -> PlainText -> Property
prop_MultiplicativeHomomorphism pt1@(PlainText plain1) pt2@(PlainText plain2) = monadicIO $ do
    bits <- run $ generate $ abs <$> (arbitrary :: Gen Int) `suchThat` (> 32)
    -- run $ print bits
    (pub,prv) <- run $ genKeys bits
    ct <- run $ standardEncrypt pub pt1
    ct' <- run $ standardEncrypt pub pt2

    let rt = ct * ct'
    Just (PlainText p) <- return $ standardDecrypt prv pub rt
    assert $ p == (plain1*plain2)

prop_AdditiveHomomorphism :: PlainText -> PlainText -> Property
prop_AdditiveHomomorphism pt1@(PlainText plain1) pt2@(PlainText plain2) = monadicIO $ do
    bits <- run $ generate $ abs <$> (arbitrary :: Gen Int) `suchThat` (> 32)
    (pub,prv) <- run $ genKeys bits
    ct <- run $ modifiedEncrypt pub pt1
    ct' <- run $ modifiedEncrypt pub pt2

    let rt = ct * ct'
    Just (PlainText p) <- return $ modifiedDecrypt prv pub rt
    assert $ p == (plain1 + plain2)
