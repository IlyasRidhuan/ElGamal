{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module ElGamalComponents where

import Crypto.Hash
import Data.Char
import Data.Semigroup

data PublicKey = PublicKey {
    q :: Integer,
    p :: Integer,
    g :: Integer,
    y :: Integer
} deriving (Show)

newtype PrivateKey = PrivateKey {x :: Integer} deriving (Show)
newtype PlainText = PlainText Integer deriving (Show,Num,Enum,Integral,Real,Ord,Eq)
newtype CipherText = CipherText (Integer,Integer,Integer) deriving (Show,Ord,Eq)

instance Semigroup CipherText where
    CipherText (a,b,n) <> CipherText(a',b',_) = CipherText ((a * a' `mod` n),(b * b' `mod` n),n)


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


