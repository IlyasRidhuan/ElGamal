{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE NamedFieldPuns             #-}
module ThresholdElGamal where

import ElGamal
import ShamirSecretSharing
import Crypto.Number.ModArithmetic
import Crypto.Number.Prime
import Control.Applicative
import Data.Maybe

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

-- calculateLP :: [SplitKey] -> [Integer]
-- calculateLP skeys =

coeffList :: [Integer] -> [LagrangePolynomial]
coeffList ints = coeffList' ints (length ints)
--
coeffList' :: [Integer] -> Int -> [LagrangePolynomial]
coeffList' _      0 = []
coeffList' []     _ = []
coeffList' ints@(i:is) n =
    product ((\x -> LP{num=x, denom = x-i}) <$> filter (/= i) ints) : coeffList' (is ++ [i]) (n-1)
    -- product ((\x  -> x / (x - i)) <$> filter (/= i) ints) : coeffList' (is ++ [i]) (n-1)


prepareList :: [LagrangePolynomial] -> [LagrangePolynomial]
prepareList []          = []
prepareList (l@LP{..}:lp)
    | isCoprime num (abs denom) = l: prepareList lp
    | otherwise = LP{num=gcdNum,denom=gcdDenom}: prepareList lp
    where
        gCD = gcd num denom
        gcdNum = num `div` gCD
        gcdDenom = denom `div` gCD

computeList :: PublicKey -> [LagrangePolynomial] -> Maybe [Integer]
computeList pk@PublicKey{..} =
    traverse (\x -> fmap (flip (`expSafe` 1) q . (num x *)) (inverse (denom x) q))
    -- expSafe (num * inv) 1 p: computeList
    -- where
    --     inv = inverse denom p
-- simplify :: PublicKey -> LagrangePolynomial -> Maybe Integer
-- simplify PublicKey{..} LP{..} = do
--     inv <- inverse denom p
--     remainder = num `mod` (abs denom)
--     if isCoprime num (abs denom)
--     then return $ expSafe (num * inv) 1 p
--     else

-- applllly :: PublicKey -> [LagrangePolynomial] -> Maybe [LagrangePolynomial]
-- applllly pk lp = do
--     applyF pk lp

applyF :: PublicKey -> [LagrangePolynomial] -> Maybe [LagrangePolynomial]
applyF pk = traverse (\x -> f1 pk x <|> (return $ f2 pk x :: Maybe LagrangePolynomial))

f1 :: PublicKey -> LagrangePolynomial -> Maybe LagrangePolynomial
f1 PublicKey{..} LP{..} =
    if num < 0
        then do
            let inv = ((abs num `div` p) + 1) * p + num
            return LP {num=expSafe inv 1 p,denom=1}
        else do
            inv <- inverse denom p
            return LP {num=expSafe (num * inv) 1 p,denom=1}

f2 :: PublicKey -> LagrangePolynomial -> LagrangePolynomial
f2 PublicKey{..} LP{..}
    | remainder == 0 = LP {num=num `div` denom, denom=denom `div` denom}
    | otherwise = LP {num=num `div` remainder, denom=denom `div` remainder}
    where
        remainder = num `mod` abs denom

    -- | num `mod` denom == 0 = num `div` denom : simplify lps
    -- | isCoprime num (abs denom) = expSafe (num * (inverse denom p)) 1 p
    -- | otherwise = remainder

    -- where

partialDecrypt :: SplitKey -> PublicKey -> CipherText -> (Integer,Integer)
partialDecrypt (i,PrivateKey{..}) PublicKey {..} (CipherText (α,β)) = (i,expSafe α x p)

-- thresholdDecrypt :: PublicKey -> CipherText -> [(Integer,Integer)] -> Maybe PlainText
-- thresholdDecrypt PublicKey{..} (CipherText (α,β)) partialDec = do
--     let coeff = prodList $ (fromIntegral . fst <$>) partialDec
--     -- let testarr = (\x -> uncurry expSafe x p) <$> zip ((fromIntegral . snd <$>) partialDec) (floor <$> coeff)
--
--     let prod = product $ zipWith (**) ((fromIntegral . snd <$>) partialDec) coeff
--     -- prodIntArr <- inverse (floor prod) p
--     return $ PlainText ( expSafe β 1 p `div` floor prod)

-- thresholdDecrypt :: PublicKey -> CipherText -> [(Integer,Integer)] ->  -> Maybe PlainText

run :: IO ()
run = do
    (pub,prv) <- genKeys 16
    threshKeys <- genThresholdKeys prv 2 5
    ct@(CipherText (α,β)) <- standardEncrypt pub (PlainText 10)
    let part = (\x -> partialDecrypt x pub ct) <$> threshKeys
    let coeffs = fromJust $ computeList pub $ (prepareList . coeffList) [1,2,3,4,5]
    let denom = product $ (\x -> uncurry expSafe x (p pub)) <$> zip (snd <$> part) coeffs
    let inv = fromJust $ inverse denom (p pub)
    print $ (inv * β) `mod` (p pub)


testRun :: IO()
testRun = do
    let pub = PublicKey{q=34,p=23,g=5,y=8}
    let prv =  PrivateKey{x=6}
    let skeys = [(1,PrivateKey {x =9}),(2,PrivateKey {x =14}),(3,PrivateKey {x =21}),(4,PrivateKey {x =8}),(5,PrivateKey {x =19})]
    let ct = CipherText (10,3)
    let part = (\x -> partialDecrypt x pub ct) <$> skeys
    -- print parts
    let coeffs = fromJust $ computeList pub $ (prepareList . coeffList) [2,4,5]
    print coeffs
    let partKeys = (\x -> part !! x) <$> [1,3,4]
    print partKeys
    let denom = product $ (\x -> uncurry expSafe x (p pub)) <$> zip (snd <$> partKeys) coeffs
    print denom
    let inv = fromJust $ inverse denom (p pub)
    print inv
    let pt = (inv * 3) `mod` (p pub)
    print pt
    print ct
    print $ fromJust $ standardDecrypt prv pub ct
