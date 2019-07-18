{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE OverloadedStrings #-}
module ElGamalComponents where

import Crypto.Hash
import Data.Char
import GHC.Generics
import Data.Semigroup()
import Crypto.Number.Serialize(i2osp,os2ip)
import qualified Data.ByteString as B
import qualified Data.ByteArray as BA
import qualified Data.ByteArray.Encoding as BA
import Control.DeepSeq
import qualified Data.Serialize as S
import Crypto.PubKey.ECC.Types
import Crypto.PubKey.ECC.Prim
import Data.Word (Word8)
import Crypto.Random
import Crypto.Number.Generate
import Crypto.Number.ModArithmetic
import Data.LargeWord (LargeKey(..),Word256)


------------- Helpful Instances -------------------------

data PublicParams = PublicParams {
    q :: Integer,
    p :: Integer,
    g :: Integer,
    y :: Integer
} deriving (Show,Generic)

instance S.Serialize PublicParams where
    put (PublicParams q p g y) = do
        S.putWord16le $ fromIntegral $ B.length $ i2osp q
        S.putByteString $ i2osp q
        S.putWord16le $ fromIntegral $ B.length $ i2osp p
        S.putByteString $ i2osp p
        S.putWord16le $ fromIntegral $ B.length $ i2osp g
        S.putByteString $ i2osp g
        S.putWord16le $ fromIntegral $ B.length $ i2osp y
        S.putByteString $ i2osp y
    
    get = do
        length_q <- S.getWord16le
        q <- S.getByteString $ fromIntegral length_q
        length_p <- S.getWord16le
        p <- S.getByteString $ fromIntegral length_p
        length_g <- S.getWord16le
        g <- S.getByteString $ fromIntegral length_g
        length_y <- S.getWord16le
        y <- S.getByteString $ fromIntegral length_y
        return $ PublicParams (os2ip q) (os2ip p) (os2ip g) (os2ip y)
    

newtype PrivateKey = PrivateKey {x :: Integer} deriving (Show)
newtype PlainText = PlainText Integer deriving (Show,Ord,Eq,Generic,NFData)

instance S.Serialize PlainText where
    put (PlainText i) = do
        S.putWord16le $ fromIntegral $ B.length $ i2osp i
        S.putByteString $ i2osp i
    get = do
        length_i <- S.getWord16le
        i <- S.getByteString $ fromIntegral length_i
        return (PlainText $ os2ip i)

data CipherText = CipherText {
    α :: Integer,
    β :: Integer
} deriving (Show,Ord,Eq,Generic,NFData)

instance S.Serialize CipherText where
    put (CipherText α β) = do
        S.putWord16le $ fromIntegral $ B.length $ i2osp α
        S.putByteString $ i2osp α
        S.putWord16le $ fromIntegral $ B.length $ i2osp β
        S.putByteString $ i2osp β
    
    get = do
        length_α <- S.getWord16le
        α <- S.getByteString $ fromIntegral length_α
        length_β <- S.getWord16le
        β <- S.getByteString $ fromIntegral length_β
        return $ CipherText (os2ip α) (os2ip β)
        

instance Semigroup CipherText where
    (CipherText α β) <> (CipherText α' β') = CipherText (α * α') (β * β')

type SplitKey = (Integer,PrivateKey)
type Coefficients = [Double]
type Hash   = Digest SHA256

data NIZKP = NIZKP {
    γ    :: Integer,
    fiatShamir :: Hash,
    w    :: Integer
} deriving (Show)

data NIZKPDL = NIZKPDL {
    a :: Integer,
    b :: Integer,
    z :: Integer,
    fsHash :: Hash
} deriving (Show)

data ECCipherText = ECCipherText {
    ec_alpha :: Point,
    ec_beta :: Point
} deriving (Show,Eq,Generic,NFData)

instance Semigroup ECCipherText where
    (ECCipherText a b) <> (ECCipherText a' b') = ECCipherText (pointAdd crv a a') (pointAdd crv b b')

instance (S.Serialize a , S.Serialize b) => S.Serialize (LargeKey a b) where
    put (LargeKey lo hi) = S.put hi >> S.put lo
    get = flip LargeKey <$> S.get <*> S.get
    
instance S.Serialize Point where
    put p = 
        S.putByteString $ compressPoint p
    get = do
        p' <- S.getByteString 33
        return $ decompressPoint crv p'

instance S.Serialize ECCipherText where
    put (ECCipherText a b) = S.put a >> S.put b

    get = ECCipherText <$> S.get <*> S.get

------------- HELPER FUNCTIONS -------------------------

crv :: Curve
crv = getCurveByName SEC_p256k1

ec_g :: Point
ec_g = ecc_g $ common_curve crv

-- Based on SECP_256k1 Bitcoin Compression --
compressPoint :: Point -> B.ByteString
compressPoint PointO = error "O point cannot be compressed"
compressPoint (Point x y) 
    | y `mod` 2 == 0 = B.cons (2 :: Word8) $ S.encode (fromIntegral x :: Word256)
    | otherwise      = B.cons (3 :: Word8) $ S.encode (fromIntegral x :: Word256)


decompressPoint :: Curve -> B.ByteString -> Point
decompressPoint (CurveF2m _) _ = error "Curve must be prime of type Fp"
decompressPoint (CurveFP  (CurvePrime p _)) bs = do
    let parityBit = BA.convertToBase BA.Base16 $ B.take 1 bs :: B.ByteString
        xCoord = os2ip $ (B.drop 1 bs :: B.ByteString)
        root = cipolla_sqrt p $ (xCoord^3 + 7) `mod` p
    if (parityBit == "02") then
        if (root `mod` 2 == 0 ) then
            Point xCoord root
        else
            Point xCoord $ (root * (-1)) `mod` p
    else
        if (root `mod` 2 /= 0 ) then
            Point xCoord root
        else
            Point xCoord $ (root * (-1)) `mod` p

cipolla_sqrt :: Integer -> Integer -> Integer
cipolla_sqrt p n 
    | checkCongruence (expFast n ((p-1) `div` 2) p) 1 p = collapseMul
    | otherwise = error "Solution to y^2 is not a square"
    where
        a = find_valid_a n p 0
        omegaSquared = (a ^2 -n) `mod` p
        power = ((p+1) `div` 2) `mod` p
        (collapseMul,_) = fold_powers power omegaSquared p (1,0) (a,1)

        fold_powers :: Integer -> Integer -> Integer -> (Integer,Integer) -> (Integer,Integer) -> (Integer,Integer)
        fold_powers 0 _ _ x _ = x
        fold_powers n omegaSquared p r s
            | n `mod` 2 == 1 = fold_powers (n `div` 2) omegaSquared p (cipolla_mul omegaSquared p r s) (cipolla_mul omegaSquared p s s)
            | otherwise = fold_powers (n `div` 2) omegaSquared p r $ cipolla_mul omegaSquared p s s

        find_valid_a :: Integer -> Integer -> Integer -> Integer
        find_valid_a n p a
            | checkCongruence base (-1) p = a
            | otherwise = find_valid_a n p (a+1)
            where
                base = expFast (a^2 - n) ((p-1) `div` 2) p

        cipolla_mul :: Integer -> Integer -> (Integer,Integer) -> (Integer,Integer) -> (Integer,Integer)
        cipolla_mul omegaSquared p (a,b) (c,d) = (omega_sum ,i_sum)
            where
                omega_sum = (a * c + b * d * omegaSquared) `mod` p
                i_sum = (a * d + c * b ) `mod` p

uncurry3 :: (a -> b -> c -> d) -> ((a,b,c) -> d)
uncurry3 f (x1,x2,x3)  = f x1 x2 x3

checkCongruence:: Integer -> Integer -> Integer -> Bool
checkCongruence a_1 b_1 modm
    | (a_1-b_1) `mod` modm == 0 = True
    | otherwise = False

parseHex :: String -> Integer
parseHex str = toInteger $ parser $ reverse str
    where
        parser []     = 0
        parser (h:hs) = toInteger (digitToInt h)  + 16 * parser hs


