{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE NamedFieldPuns             #-}

module ElGamal where

import Crypto.Random
import Crypto.Number.Prime
import Crypto.Number.ModArithmetic
import Crypto.Number.Generate

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

genKeys :: Int -> IO (PublicKey,PrivateKey)
genKeys bits = do
    q <- generateSafePrime bits
    let p = (q - 1) `div` 2
    g <- generateBetween 1 q >>= findGenerator q
    x <- generateMax q
    let y = expSafe g x p

    let pubKey = PublicKey {p,q,g,y}
    let prvKey = PrivateKey {x}

    return (pubKey,prvKey)

encrypt :: PublicKey -> PlainText -> IO CipherText
encrypt PublicKey{..} (PlainText msg) = do
    r <- generateMax q
    let α = expSafe g r p
    let β = msg * expSafe y r p
    return $ CipherText (α,β)

decrypt :: PrivateKey -> PublicKey -> CipherText -> Maybe PlainText
decrypt PrivateKey{..} PublicKey {..} (CipherText (α,β)) = do
    let ax = expSafe α x p
    invAX <- inverse ax p
    let pt = expSafe (β * invAX) 1 p
    return $ PlainText pt


findGenerator :: Integer -> Integer -> IO Integer
findGenerator order gCand
    | gcd gCand order == 1 = return gCand
    | otherwise = generateBetween 1 order >>= findGenerator order
