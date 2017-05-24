{-# LANGUAGE RecordWildCards            #-}

module ShamirSecretSharing where

import ElGamal
import Crypto.Number.Generate
import Data.List.Split

type SplitKey = (Integer,PrivateKey)
type Coefficients = [Double]

genThresholdKeys :: PrivateKey -> Int -> Integer -> IO [SplitKey]
genThresholdKeys PrivateKey{..} t m = do
    polyArray <- traverse (const $ generateBetween 0 x) [1..(t-1)]
    let polynomial = zip [1..] polyArray
    let polyConstituents = (\y x -> y ^ fst x * snd x ) <$> [1..m] <*> polynomial
    let chunked = chunksOf (t-1) polyConstituents
    return $ zip [1..] $ PrivateKey . foldr (+) x <$> chunked

reconstructKey :: [SplitKey] -> PrivateKey
reconstructKey skeys = PrivateKey $ (floor . sum) lagrangeParts
    where
        fxs = fromIntegral. x . snd <$> skeys :: [Double]
        prodArr = prodList $ (fromIntegral . fst <$>) skeys
        lagrangeParts = zipWith (*) fxs prodArr

prodList :: [Double] -> Coefficients
prodList dbls = prodList' dbls (length dbls)

prodList' :: [Double] -> Int -> Coefficients
prodList' _      0 = []
prodList' []     _ = []
prodList' dbls@(i:is) n =
    product ((\x  -> x / (x - i)) <$> filter (/= i) dbls) : prodList' (is ++ [i]) (n-1)
