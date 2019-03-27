module Main where

import ElGamalTest
import ZKPTest
import Test.QuickCheck

main :: IO ()
main = do
    quickCheckWith stdArgs { maxSuccess = 100 } prop_MultiplicativeHomomorphism
    quickCheckWith stdArgs { maxSuccess = 100 } prop_EncryptDecrypt
    quickCheckWith stdArgs { maxSuccess = 100 } prop_AdditiveHomomorphism
    quickCheckWith stdArgs { maxSuccess = 100 } prop_SingleNonInteractiveZKP
    quickCheckWith stdArgs { maxSuccess = 100 } prop_EqualityOfDL
    quickCheckWith stdArgs { maxSuccess = 10} prop_CheckExponentiation
    -- quickCheckWith stdArgs { maxSuccess = 5} prop_CheckPollardRho