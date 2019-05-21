module ECElGamalSpec where

import Test.QuickCheck
import Test.QuickCheck.Monadic
import Test.Hspec
import Test.Hspec.Core.QuickCheck (modifyMaxSuccess)

import ECElGamal
import ElGamalComponents

instance Arbitrary PlainText where
    arbitrary = do
        pt <- (arbitrary :: Gen Integer) `suchThat` (> 0)
        return $ PlainText (pt `mod` 10)
        
spec :: Spec
spec = do
    describe "Check Correcteness of EC El Gamal Commitment" $ do
        modifyMaxSuccess (const 1000) $ it "Check that decrypt . encrypt is an identity" $ do
            property prop_CheckEncryptDecryptEC
        modifyMaxSuccess (const 1000) $ it "Check additive homomorphism works" $ do
            property prop_CheckAdditiveEC


prop_CheckEncryptDecryptEC :: PlainText -> Property
prop_CheckEncryptDecryptEC pt = monadicIO $ do
    (pub,prv) <- run $ genECKeys
    commit <- run $ ecElGamalCommit ec_g pub pt
    assert $ pt == ecDecrypt prv commit

prop_CheckAdditiveEC :: PlainText -> PlainText -> Property
prop_CheckAdditiveEC pt1@(PlainText p1) pt2@(PlainText p2) = monadicIO $ do
    (pub,prv) <- run $ genECKeys
    commit1 <- run $ ecElGamalCommit ec_g pub pt1
    commit2 <- run $ ecElGamalCommit ec_g pub pt2
    let commit3 = commit1 <> commit2
        (PlainText p3) = ecDecrypt prv commit3
    assert $ (p1 + p2) == p3

