{-# LANGUAGE RecordWildCards #-}
module ECElGamal where

import Crypto.PubKey.ECC.Generate
import Crypto.PubKey.ECC.Types
import Crypto.PubKey.ECC.Prim

import ElGamalComponents




genECKeys :: IO (Point,PrivateKey)
genECKeys = do
    prv <- scalarGenerate crv
    let public = pointBaseMul crv prv
    return (public,PrivateKey prv)

ecElGamalCommit :: Point -> PlainText -> IO ECCipherText
ecElGamalCommit h (PlainText msg) = do
    r <- scalarGenerate crv 
    let alpha = pointBaseMul crv r
        beta = pointAddTwoMuls crv msg ec_g r h
    return $ ECCipherText alpha beta

ecDecrypt :: PrivateKey -> ECCipherText -> PlainText
ecDecrypt PrivateKey{..} ECCipherText{..} = PlainText $ grindPoint point 0
    where
        invA = pointNegate crv $ pointMul crv x ec_alpha
        point = pointAdd crv ec_beta invA
        
        grindPoint :: Point -> Integer -> Integer
        grindPoint pt n
            | pointBaseMul crv n == pt = n
            | otherwise = grindPoint pt (n+1)

ecElGamalwR :: Point -> Integer -> PlainText -> ECCipherText
ecElGamalwR h blind (PlainText msg) = ECCipherText alpha beta
    where
        alpha = pointBaseMul crv blind
        beta = pointAddTwoMuls crv msg ec_g blind h