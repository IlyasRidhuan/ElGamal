{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module ElGamalComponents where

import Crypto.Hash
import Data.Char

data PublicKey = PublicKey {
    q :: Integer,
    p :: Integer,
    g :: Integer,
    y :: Integer
} deriving (Show)

newtype PrivateKey = PrivateKey {x :: Integer} deriving (Show)
newtype PlainText = PlainText Integer deriving (Show,Num,Enum,Integral,Real,Ord,Eq)
newtype CipherText = CipherText (Integer,Integer) deriving (Show,Ord,Eq,Num)


instance (Num a, Num b) => Num (a,b) where
        fromInteger x = (fromInteger x, fromInteger x)
        (a,b) + (a',b') = (a + a', b + b')
        (a,b) - (a',b') = (a - a', b - b')
        (a,b) * (a',b') = (a * a', b * b')
        negate (a,b) = (negate a, negate b)
        abs (a,b) = (abs a, abs b)
        signum (a,b) = (signum a, signum b)

type SplitKey = (Integer,PrivateKey)
type Coefficients = [Double]
type Hash   = Digest SHA256

data NIZKP = NIZKP {
    γ    :: Integer,
    fiatShamir :: Hash,
    w    :: Integer
}

data NIZKPDL = NIZKPDL {
    a :: Integer,
    b :: Integer,
    z :: Integer,
    fsHash :: Hash
}


------------- HELPER FUNCTIONS -------------------------

uncurry3 :: (a -> b -> c -> d) -> ((a,b,c) -> d)
uncurry3 f (x,y,z)  = f x y z

uncurry4 :: (a -> b -> c -> d -> e) -> ((a,b,c,d) -> e)
uncurry4 f (w,x,y,z)  = f w x y z

checkCongruence:: Integer -> Integer -> Integer -> Bool
checkCongruence a b modm
    | (a-b) `mod` modm == 0 = True
    | otherwise = False

parseHex :: String -> Integer
parseHex str = toInteger $ parser $ reverse str
    where
        parser []     = 0
        parser (x:xs) = digitToInt x + 16 * parser xs
