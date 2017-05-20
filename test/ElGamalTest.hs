module ElGamalTest where

import Test.QuickCheck
import Test.QuickCheck.Monadic
import Data.Maybe
import ElGamal
import Control.Monad.IO.Class

testElGamal :: IO ()
testElGamal = do
    bits <- generate $ abs <$> (arbitrary :: Gen Int) `suchThat` (> 10)
    (pub,prv) <- genKeys bits
    print pub
    print prv
    verboseCheckWithResult stdArgs { maxSuccess = 500 } $ prop_MultiplicativeHomomorphism pub prv
    quickCheckWith stdArgs { maxSuccess = 500 } $ prop_EncryptDecrypt pub prv


-- monadic fromJust $
instance Arbitrary PlainText where
    arbitrary = do
        pt <- (arbitrary :: Gen Integer) `suchThat` (> 0)
        return $ PlainText pt

prop_EncryptDecrypt :: PublicKey -> PrivateKey -> PlainText -> Property
prop_EncryptDecrypt pub prv pt@(PlainText plain) = monadicIO $ do
    -- let ct = CipherText (10,10)
    Just (PlainText p) <- run $ decrypt prv pub <$> encrypt pub pt
    assert $ plain == p

prop_MultiplicativeHomomorphism :: PublicKey -> PrivateKey -> PlainText -> PlainText -> Property
prop_MultiplicativeHomomorphism pub prv pt1@(PlainText plain1) pt2@(PlainText plain2) = monadicIO $ do
    ct <- run $ encrypt pub pt1
    ct' <- run $ encrypt pub pt2

    let ct'' = ct * ct'
    Just (PlainText p) <- return $ decrypt prv pub ct''
    assert $ p == (plain1*plain2)
