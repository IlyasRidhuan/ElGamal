{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveAnyClass #-}
module ElGamalComponents where

import Crypto.Hash
import Data.Char
import GHC.Generics
import Data.Semigroup()
import Crypto.Number.Serialize(i2osp,os2ip)
import qualified Data.ByteString as B
import Control.DeepSeq
import qualified Data.Serialize as S

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
newtype PlainText = PlainText Integer deriving (Show,Num,Real,Ord,Eq,Generic,NFData)

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

------------- HELPER FUNCTIONS -------------------------

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
        parser (h:hs) = digitToInt h + 16 * parser hs


