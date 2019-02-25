{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DuplicateRecordFields #-}
module ElGamalComponents where

import Crypto.Hash
import Data.Char
import Data.Semigroup()

data PublicParams = PublicParams {
    q :: Integer,
    p :: Integer,
    g :: Integer,
    y :: Integer
} deriving (Show)

newtype PrivateKey = PrivateKey {x :: Integer} deriving (Show)
newtype PlainText = PlainText Integer deriving (Show,Num,Enum,Integral,Real,Ord,Eq)
data CipherText = CipherText {
    α :: Integer,
    β :: Integer,
    modulo :: Integer
} deriving (Show,Ord,Eq)

instance Semigroup CipherText where
    (CipherText α β n) <> (CipherText α' β' _) = CipherText ((α * α') `mod` n) ((β * β') `mod` n) n


type SplitKey = (Integer,PrivateKey)
type Coefficients = [Double]
type Hash   = Digest SHA256

data NIZKP = NIZKP {
    γ    :: Integer,
    fiatShamir :: Hash,
    w    :: Integer
} deriving (Show)

data NIZKPDL = NIZKPDL {
    a :: Integer,
    b :: Integer,
    z :: Integer,
    fsHash :: Hash
} deriving (Show)

------------- HELPER FUNCTIONS -------------------------

uncurry3 :: (a -> b -> c -> d) -> ((a,b,c) -> d)
uncurry3 f (x1,x2,x3)  = f x1 x2 x3

uncurry4 :: (a -> b -> c -> d -> e) -> ((a,b,c,d) -> e)
uncurry4 f (w1,w2,w3,w4)  = f w1 w2 w3 w4

checkCongruence:: Integer -> Integer -> Integer -> Bool
checkCongruence a_1 b_1 modm
    | (a_1-b_1) `mod` modm == 0 = True
    | otherwise = False

parseHex :: String -> Integer
parseHex str = toInteger $ parser $ reverse str
    where
        parser []     = 0
        parser (h:hs) = digitToInt h + 16 * parser hs


