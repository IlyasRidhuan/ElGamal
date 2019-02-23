{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE NamedFieldPuns             #-}
module ThresholdElGamal where

import ElGamalComponents
import Crypto.Number.ModArithmetic
import Crypto.Number.Prime

data LagrangePolynomial = LP {
    num :: Integer,
    denom :: Integer
} deriving (Show,Eq,Ord)

instance Num LagrangePolynomial where
    fromInteger x = LP {num=fromInteger x, denom=fromInteger x}
    LP{num=n1,denom=d1} + LP{num=n2,denom=d2} = LP {num = n1+n2,denom = d1+d2}
    LP{num=n1,denom=d1} - LP{num=n2,denom=d2} = LP {num = n1-n2,denom = d1-d2}
    LP{num=n1,denom=d1} * LP{num=n2,denom=d2} = LP {num = n1*n2,denom = d1*d2}
    negate LP{..} = LP {num = negate num,denom = negate denom}
    abs LP{..} = LP {num = abs num, denom = abs num}
    signum LP{..} = LP {num = signum num, denom = signum denom}

coeffList :: PublicKey -> [Integer] -> Maybe [Integer]
coeffList pk ints = computeList pk . mkCoprimeList $ coeffList' ints (length ints)

coeffList' :: [Integer] -> Int -> [LagrangePolynomial]
coeffList' _      0 = []
coeffList' []     _ = []
coeffList' ints@(i:is) n =
    product ((\x -> LP{num=x, denom = x-i}) <$> filter (/= i) ints) : coeffList' (is ++ [i]) (n-1)


mkCoprimeList :: [LagrangePolynomial] -> [LagrangePolynomial]
mkCoprimeList []          = []
mkCoprimeList (l@LP{..}:lp)
    | isCoprime num (abs denom) = l: mkCoprimeList lp
    | otherwise = LP{num=gcdNum,denom=gcdDenom}: mkCoprimeList lp
    where
        gCD = gcd num denom
        gcdNum = num `div` gCD
        gcdDenom = denom `div` gCD

computeList :: PublicKey -> [LagrangePolynomial] -> Maybe [Integer]
computeList PublicKey{..} =
    traverse (\x -> fmap (flip (`expSafe` 1) q . (num x *)) (inverse (denom x) q))

partialDecrypt :: SplitKey -> PublicKey -> CipherText -> (Integer,Integer)
partialDecrypt (i,PrivateKey{..}) PublicKey {..} (CipherText α _ _) = (i,expSafe α x p)

thresholdDecrypt :: PublicKey -> CipherText -> [(Integer,Integer)] -> Maybe PlainText
thresholdDecrypt pk@PublicKey{..} (CipherText _ β _) partialDec = do
    coeffs <- coeffList pk $ fst <$> partialDec
    let lgProduct = product $ (\x -> uncurry expSafe x p) <$> zip (snd <$> partialDec) coeffs
    inv <- inverse lgProduct p
    let pt = (inv * β) `mod` p
    return (PlainText pt)
