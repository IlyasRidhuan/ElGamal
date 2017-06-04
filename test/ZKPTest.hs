module ZKPTest where

import Test.QuickCheck
import Test.QuickCheck.Monadic
import ZKP
import Components
import ElGamal
import Crypto.Number.Generate
import Crypto.Number.ModArithmetic

testZKP :: IO ()
testZKP = do
    quickCheckWith stdArgs { maxSuccess = 100000 } $ prop_SingleInteractiveZKP

prop_SingleInteractiveZKP :: Property
prop_SingleInteractiveZKP = monadicIO $ do
    bits <- Test.QuickCheck.Monadic.run $ generate $ abs <$> (arbitrary :: Gen Int) `suchThat` (> 10)
    (pub,prv) <- Test.QuickCheck.Monadic.run $ genKeys bits
    let q' = (q pub)
    let p' = (p pub)
    let g' = (g pub)
    let w = (q pub)
    let h = expFast g' w p'
    r <- run $ generateMax q'
    let a = expFast g' r p'
    let t = floor $ logBase 2 (fromInteger q')
    e <- run $ generateMax (2 ^ t)
    let z = r + expFast (e * w) 1 q'
    let gz = expFast g' z p'
    let he = expFast h e p'
    let test = expFast (a*he) 1 p'
    assert $ gz == test

prop_EqofDLZKP :: Property
prop_EqofDLZKP = monadicIO $ do
    bits <- run $ generate $ abs <$> (arbitrary :: Gen Int) `suchThat` (> 10)
    (pub,prv) <- run $ genKeys bits
