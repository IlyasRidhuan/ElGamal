{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE NamedFieldPuns             #-}
{-# LANGUAGE StrictData #-}

module ElGamal (
  genKeys,
  modifiedEncrypt,
  modifiedEncryptWithR,
  standardEncrypt,

  modifiedDecrypt,
  standardDecrypt,
  
  binOp,
  expOp
) where

import Crypto.Random
import Crypto.Number.Prime
import Crypto.Number.ModArithmetic
import Crypto.Number.Generate
import ElGamalComponents
import Data.Maybe
import Control.Concurrent.Async
import Control.Parallel

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
    where
        newGenerator :: MonadRandom m => Integer -> Integer -> Integer -> m Integer
        newGenerator q p gCand
            | expSafe gCand q p == 1 && gCand ^ (2 :: Integer) /= (1 :: Integer) = return gCand
            | otherwise = generateBetween 1 (p-1) >>= newGenerator q p

modifiedEncrypt :: MonadRandom m => PublicParams -> PlainText -> m CipherText
modifiedEncrypt PublicParams{..} (PlainText msg) = do
    r <- generateMax q
    let α = expSafe g r p
    let β = (expSafe g msg p * expSafe y r p) `mod` p
    return $ CipherText α β


-- Useful when you care about the r being used, e.g. Verifiable Encryption ---
modifiedEncryptWithR :: PublicParams -> Integer -> PlainText -> CipherText
modifiedEncryptWithR PublicParams{..} r (PlainText msg) = CipherText α β
    where
        α = expSafe g r p
        β = (expSafe g msg p * expSafe y r p) `mod` p
      
-- ElGamal Binary operator, note homomorphism type (multiplicate/additive) depends on construction --       
binOp :: PublicParams -> CipherText -> CipherText -> CipherText
binOp pp ct1 ct2 = let ct3 = ct1 <> ct2  in 
        CipherText (α ct3 `mod` (p pp)) (β ct3 `mod` (p pp))        

expOp :: PublicParams -> CipherText -> Integer -> CipherText
expOp PublicParams{..} CipherText{..} x = CipherText α2 β2
    where
        α2 = expFast α x p
        β2 = expFast β x p

modifiedDecrypt :: PrivateKey -> PublicParams -> CipherText -> Maybe PlainText
modifiedDecrypt prv pp ct = do
    gm <- standardDecrypt prv pp ct
    return $ findGM gm pp 0
    where
        findGM :: PlainText -> PublicParams -> Integer -> PlainText
        findGM pt@(PlainText plain) pk@PublicParams{..} n
            | expSafe g n p == plain = PlainText n
            | otherwise = findGM pt pk (n+1)

standardEncrypt :: MonadRandom m => PublicParams -> PlainText -> m CipherText
standardEncrypt PublicParams{..} (PlainText msg) = do
    r <- generateMax q
    let α = expSafe g r p
    let β = (msg * expSafe y r p) `mod` p
    return $ CipherText α β

standardDecrypt :: PrivateKey -> PublicParams -> CipherText -> Maybe PlainText
standardDecrypt PrivateKey{..} PublicParams{..} CipherText {..} = do
    let ax = expSafe α x p
    invAX <- inverse ax p
    let pt = expSafe (β * invAX) 1 p
    return $ PlainText pt

-- Prove that a CipherText is the correct Exponential ElGamal Encryption ** note this is not Zk as requires blinding factor,r
proveCorrectExpEncryption :: PublicParams -> CipherText -> PlainText -> Integer -> Bool
proveCorrectExpEncryption PublicParams{..} CipherText{..} (PlainText m) r = (checkAlpha == checkBeta) && ( checkAlpha == r)
    where
        checkAlpha = (floor . logBase (fromIntegral g) . fromIntegral) α
        checkBeta = (floor . logBase (fromIntegral y) . fromIntegral) $ (expSafe g (-m) p * β)

proveCorrectMulEncryption :: PublicParams -> CipherText -> PlainText -> Integer -> Bool
proveCorrectMulEncryption PublicParams{..} CipherText{..} (PlainText m) r = checkAlpha == checkBeta
    where
        checkAlpha = (floor . logBase (fromIntegral g) . fromIntegral) α
        checkBeta = (floor . logBase (fromIntegral y) . fromIntegral) $ (β `div` m)
