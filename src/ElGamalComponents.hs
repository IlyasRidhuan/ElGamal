{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveAnyClass #-}
module ElGamalComponents where

import Crypto.Hash
import Data.Char
import GHC.Generics
import Data.Semigroup()
import Control.DeepSeq
import qualified Data.Serialize as S

data PublicParams = PublicParams {
    q :: Integer,
    p :: Integer,
    g :: Integer,
    y :: Integer
} deriving (Show,Generic,S.Serialize)

newtype PrivateKey = PrivateKey {x :: Integer} deriving (Show)
newtype PlainText = PlainText Integer deriving (Show,Num,Real,Ord,Eq,Generic,NFData,S.Serialize)

data CipherText = CipherText {
    α :: Integer,
    β :: Integer
} deriving (Show,Ord,Eq,Generic,NFData,S.Serialize)

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


