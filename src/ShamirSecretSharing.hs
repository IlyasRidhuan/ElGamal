{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE NamedFieldPuns             #-}

module ShamirSecretSharing where

import Crypto.Number.Generate
import Crypto.Number.ModArithmetic
import Data.List.Split
import ElGamalComponents (SplitKey,PublicParams(..),PrivateKey(..))
import Data.Ratio

genThresholdKeys :: PublicParams -> PrivateKey -> Integer -> Integer -> IO [SplitKey]
genThresholdKeys PublicParams{..} PrivateKey{..} t m = do
    polyArray <- traverse (const $ generateBetween 0 x) [1..(t-1)]
    let polynomial = zip [1..] polyArray
    let polyConstituents = (\base key_shard -> expSafe base (fst key_shard) p * snd key_shard ) <$> [1..m] <*> polynomial
    let chunked = chunksOf (fromInteger t-1) polyConstituents
    return $ zip [1..] $ PrivateKey . foldr (+) x <$> chunked

reconstructKey :: [SplitKey] -> PrivateKey
reconstructKey skeys = PrivateKey $ sum lagrangeParts
    where
        fxs = x . snd <$> skeys
        prodArr = prodList $ (fromIntegral . fst <$>) skeys
        lagrangeParts = zipWith (*) fxs $ numerator <$> prodArr

prodList :: [Integer] -> [Ratio Integer]
prodList dbls = prodList' dbls (length dbls)

prodList' :: [Integer] -> Int -> [Ratio Integer]
prodList' _      0 = []
prodList' []     _ = []
prodList' dbls@(i:is) n =
    product ((\x  -> x % (x - i)) <$> filter (/= i) dbls) : prodList' (is ++ [i]) (n-1)

genVerificationKeys :: PublicParams -> [SplitKey] -> [(Integer,Integer)]
genVerificationKeys _                   []                    = []
genVerificationKeys pub@PublicParams{..} ((n,PrivateKey{..}):ss) =
    (n, expSafe g x p) : genVerificationKeys pub ss
