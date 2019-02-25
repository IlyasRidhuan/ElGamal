{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE NamedFieldPuns             #-}

module ElGamal where

import Crypto.Random
import Crypto.Number.Prime
import Crypto.Number.ModArithmetic
import Crypto.Number.Generate
import ElGamalComponents


genKeys :: MonadRandom m => Int -> m (PublicParams,PrivateKey)
genKeys bits = do
    p <- generateSafePrime bits
    let q = (p - 1) `div` 2
    g <- generateBetween 1 (p-1) >>= newGenerator q p
    x <- generateMax q
    let y = expSafe g x p

    let pubParams = PublicParams {q,p,g,y}
    let prvKey = PrivateKey {x}

    return (pubParams,prvKey)

modifiedEncrypt :: MonadRandom m => PublicParams -> PlainText -> m CipherText
modifiedEncrypt PublicParams{..} (PlainText msg) = do
    r <- generateMax q
    let α = expSafe g r p
    let β = (expSafe g msg p * expSafe y r p) `mod` p
    return $ CipherText α β p


-- Useful when you care about the r being used, e.g. Verifiable Encryption ---
modifiedEncryptWithR :: PublicParams -> Integer -> PlainText -> CipherText
modifiedEncryptWithR PublicParams{..} r (PlainText msg) = CipherText α β p
    where
        α = expSafe g r p
        β = (expSafe g msg p * expSafe y r p) `mod` p
    

modifiedDecrypt :: PrivateKey -> PublicParams -> CipherText -> Maybe PlainText
modifiedDecrypt prv pk ct = do
    gm <- standardDecrypt prv ct
    return $ findGM gm pk 0

standardEncrypt :: MonadRandom m => PublicParams -> PlainText -> m CipherText
standardEncrypt PublicParams{..} (PlainText msg) = do
    r <- generateMax q
    let α = expSafe g r p
    let β = (msg * expSafe y r p) `mod` p
    return $ CipherText α β p

standardDecrypt :: PrivateKey -> CipherText -> Maybe PlainText
standardDecrypt PrivateKey{..} CipherText {..} = do
    let ax = expSafe α x modulo
    invAX <- inverse ax modulo
    let pt = expSafe (β * invAX) 1 modulo
    return $ PlainText pt

newGenerator :: MonadRandom m => Integer -> Integer -> Integer -> m Integer
newGenerator q p gCand
    | expSafe gCand q p == 1 && gCand ^ (2 :: Integer) /= (1 :: Integer) = return gCand
    | otherwise = generateBetween 1 (p-1) >>= newGenerator q p

findGM :: PlainText -> PublicParams -> Integer -> PlainText
findGM pt@(PlainText plain) pk@PublicParams{..} n
    | expSafe g n p == plain = PlainText n
    | otherwise = findGM pt pk (n+1)
