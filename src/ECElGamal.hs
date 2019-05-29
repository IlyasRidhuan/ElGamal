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

ecElGamalCommit :: ECPublicPoints -> PlainText -> IO ECCipherText
ecElGamalCommit ECPublicPoints{..} (PlainText msg) = do
    r <- scalarGenerate crv 
    let alpha = pointMul crv r g
        beta = pointAddTwoMuls crv msg g r h
    return $ ECCipherText alpha beta

ecDecrypt :: PrivateKey -> ECPublicPoints -> ECCipherText -> PlainText
ecDecrypt PrivateKey{..} ECPublicPoints{..} ECCipherText{..} = PlainText $ grindPoint point 0
    where
        invA = pointNegate crv $ pointMul crv x ec_alpha
        point = pointAdd crv ec_beta invA
        
        grindPoint :: Point -> Integer -> Integer
        grindPoint pt n
            | pointMul crv n g == pt = n
            | otherwise = grindPoint pt (n+1)

ecElGamalwR :: Point -> Point -> Integer -> PlainText -> ECCipherText
ecElGamalwR g y blind (PlainText msg) = ECCipherText alpha beta
    where
        alpha = pointMul crv blind g
        beta = pointAddTwoMuls crv msg g blind y