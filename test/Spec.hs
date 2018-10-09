module Main where

import ElGamalTest
import ZKPTest
import Test.QuickCheck

main :: IO ()
main = do
    quickCheckWith stdArgs { maxSuccess = 1000 } prop_MultiplicativeHomomorphism
    quickCheckWith stdArgs { maxSuccess = 1000 } prop_EncryptDecrypt
    quickCheckWith stdArgs { maxSuccess = 1000 } prop_AdditiveHomomorphism
    quickCheckWith stdArgs { maxSuccess = 100 } prop_SingleNonInteractiveZKP
    quickCheckWith stdArgs { maxSuccess = 100 } prop_EqualityOfDL
