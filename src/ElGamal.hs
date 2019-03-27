{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE NamedFieldPuns             #-}
{-# LANGUAGE StrictData #-}

module ElGamal (
  genKeys,
  modifiedEncrypt,
  modifiedEncryptWithR,
  standardEncrypt,

  modifiedDecrypt,
--   modifiedDecrypt',
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

-- modifiedDecrypt' :: PrivateKey -> PublicParams -> CipherText -> IO PlainText
-- modifiedDecrypt' prv pp ct = do
--     case standardDecrypt prv pp ct of 
--         Just p@(PlainText gm) -> traverse async ((const $ parallelPollardSearch pp p) <$> [1..10]) >>= waitAnyCancel >>= return . snd
--         otherwise -> error "Decrypt Failed"

-- parallelPollardSearch :: PublicParams -> PlainText -> IO PlainText
-- parallelPollardSearch pp@PublicParams{..} pt@(PlainText gm) = flip (pollardsSearch pp) pt <$> ((\x -> PollardCandidate (g * gm) x x) <$> generateBetween 1 q)

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

newGenerator :: MonadRandom m => Integer -> Integer -> Integer -> m Integer
newGenerator q p gCand
    | expSafe gCand q p == 1 && gCand ^ (2 :: Integer) /= (1 :: Integer) = return gCand
    | otherwise = generateBetween 1 (p-1) >>= newGenerator q p

findGM :: PlainText -> PublicParams -> Integer -> PlainText
findGM pt@(PlainText plain) pk@PublicParams{..} n
    | expSafe g n p == plain = PlainText n
    | otherwise = findGM pt pk (n+1)


-- data PollardCandidate = PollardCandidate{
--     candX :: Integer,
--     candA :: Integer,
--     candB :: Integer
-- } deriving (Show)

-- pollardsSearch :: PublicParams -> PollardCandidate -> PlainText -> PlainText
-- pollardsSearch pp@PublicParams{..} pc  (PlainText gm )= tpc `par` hpc `pseq` pollardsSearch' tpc hpc 0
--     where
--         hpc = hare pc
--         tpc = tortoise pc
--         hare = new_xab . new_xab
--         tortoise = new_xab
--         new_xab :: PollardCandidate -> PollardCandidate
--         new_xab PollardCandidate{..} = case candX `mod` 3 of
--             0 -> PollardCandidate (expFast (candX* g) 1 p)      (expFast (candA + 1 ) 1 q) $ candB
--             1 -> PollardCandidate (expFast (candX* gm) 1 p)      candA                 $ expFast (candB + 1) 1 q
--             2 -> PollardCandidate (expFast (candX*candX) 1 p)   (expFast (candA*2) 1 q)    $ expFast (candB * 2) 1 q

--         pollardsSearch' :: PollardCandidate -> PollardCandidate -> Integer -> PlainText
--         pollardsSearch' tpc hpc n
--             | n > p = error "Cannot decrypt"
--             | candX (hpc) == candX (tpc) = PlainText result
--             | otherwise = pollardsSearch' (tortoise tpc) (hare hpc) (n+1)
--             where
--                 result = ((nom * invD) `mod` q)
--                 nom = (candA tpc - candA hpc)
--                 denom = (candB hpc - candB tpc)
--                 invD = fromMaybe (error "dead") $ inverse denom q