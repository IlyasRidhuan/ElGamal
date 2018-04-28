module ElGamalTest where

import Test.QuickCheck
import Test.QuickCheck.Monadic
import Data.Maybe
import ElGamal
import Control.Monad.IO.Class
import ElGamalComponents

testElGamal :: IO ()
testElGamal = do
    -- bits <- generate $ abs <$> (arbitrary :: Gen Int) `suchThat` (> 10)
    -- (pub,prv) <- genKeys bits
    -- print pub
    -- print prv
    quickCheckWith stdArgs { maxSuccess = 5000 } $ prop_MultiplicativeHomomorphism
    quickCheckWith stdArgs { maxSuccess = 1000 } $ newpropEncryptDecrypt


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

    let CipherText(α,β) = ct * ct'
    Just (PlainText p) <- return $ standardDecrypt prv pub (CipherText (α `mod` (p pub),β `mod` (p pub)))
    assert $ p == (plain1*plain2)
