{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Components (PublicKey(..),PrivateKey(..),PlainText(..),CipherText(..),
SplitKey, Coefficients) where


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
