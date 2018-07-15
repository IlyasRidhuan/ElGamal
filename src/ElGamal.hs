{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE NamedFieldPuns             #-}

module ElGamal where

import Crypto.Random
import Crypto.Number.Prime
import Crypto.Number.ModArithmetic
import Crypto.Number.Generate
import Data.List.Split
import ElGamalComponents


genKeys :: Int -> IO (PublicKey,PrivateKey)
genKeys bits = do
    p <- generateSafePrime bits
    let q = (p - 1) `div` 2
    g <- generateBetween 1 (p-1) >>= newGenerator q p
    x <- generateMax q
    let y = expSafe g x p

    let pubKey = PublicKey {q,p,g,y}
    let prvKey = PrivateKey {x}

    return (pubKey,prvKey)

modifiedEncrypt :: MonadRandom m => PublicKey -> PlainText -> m CipherText
modifiedEncrypt PublicKey{..} (PlainText msg) = do
    r <- generateMax q
    let α = expSafe g r p
    let β = expSafe g msg p * expSafe y r p
    return $ CipherText (α,β)

modifiedDecrypt :: PrivateKey -> PublicKey -> CipherText -> Maybe PlainText
modifiedDecrypt prv pk ct = do
    gm <- standardDecrypt prv pk ct
    return $ findGM gm pk 0

standardEncrypt :: MonadRandom m => PublicKey -> PlainText -> m CipherText
standardEncrypt PublicKey{..} (PlainText msg) = do
    r <- generateMax q
    let α = expSafe g r p
    let β = msg * expSafe y r p
    return $ CipherText (α,β)

standardDecrypt :: PrivateKey -> PublicKey -> CipherText -> Maybe PlainText
standardDecrypt PrivateKey{..} PublicKey {..} (CipherText (α,β)) = do
    let ax = expSafe α x p
    invAX <- inverse ax p
    let pt = expSafe (β * invAX) 1 p
    return $ PlainText pt

newGenerator :: MonadRandom m => Integer -> Integer -> Integer -> m Integer
newGenerator q p gCand
    | expSafe gCand q p == 1 && gCand ^ 2 /= 1 = return gCand
    | otherwise = generateBetween 1 (p-1) >>= newGenerator q p

findGM :: PlainText -> PublicKey -> Integer -> PlainText
findGM pt@(PlainText plain) pk@PublicKey{..} n
    | expSafe g n p == plain = PlainText n
    | otherwise = findGM pt pk (n+1)
