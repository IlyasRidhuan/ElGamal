{-# LANGUAGE RecordWildCards #-}
module ZKP where

import Components
import Crypto.Number.ModArithmetic
import Crypto.Number.Generate
import Crypto.Random.Types
import Crypto.Hash
import Data.Char
import qualified Data.ByteString.Char8 as B8
import ElGamal


initialCommit :: MonadRandom m => PublicKey -> CipherText -> m (Integer,Integer,Integer)
initialCommit PublicKey{..} (CipherText (α,_)) = do
    τ <- generateMax q
    return (expSafe g τ p, expSafe α τ p,τ)

verifierChallenge :: MonadRandom m => PublicKey -> m Integer
verifierChallenge PublicKey{..} = do
    let maxi = floor $ logBase 2 (fromInteger q)
    generateMax (2 ^ maxi)

challengeResponse :: PrivateKey -> PublicKey -> Integer -> Integer -> Integer
challengeResponse PrivateKey{..} PublicKey{..} τ u =
    -- τ - expSafe (u * x) 1 q
    τ + expSafe (u * x) 1 q

verifierResponse :: PublicKey -> Integer -> Integer -> Integer -> Integer -> Integer -> (Integer,Integer)
verifierResponse PublicKey{..} γ1 γ2 v z u =
    (expSafe (γ1 * vu ) 1 p, expSafe (γ2 * zu) 1 p)
    where
        vu = expFast v u p
        zu = expFast z u p

checkEqualityOfDL :: PublicKey -> CipherText -> SplitKey -> (Integer,Integer) -> (Integer, Integer) -> IO Bool
checkEqualityOfDL pub@PublicKey{..} ct@(CipherText (α,_)) (_,prv) vk pd  = do
    (a,b,τ) <- initialCommit pub ct
    u <- verifierChallenge pub
    let z = challengeResponse prv pub τ u
    let (ay,bz) = verifierResponse pub a b (snd vk) (snd pd) u
    let gz = expFast g z p
    let αz = expFast α z p
    return $ checkCongruence gz ay p && checkCongruence αz bz p


nonInteractiveEqofDL :: PublicKey -> CipherText -> SplitKey -> (Integer,Integer) -> (Integer, Integer) -> IO (Integer,Integer,Integer)
nonInteractiveEqofDL pub@PublicKey{..} ct@(CipherText (α,_)) (_,prv) vk pd  = do
    (a,b,τ) <- initialCommit pub ct
    let hsh = hash $ B8.pack $ show g ++ show (snd vk) ++ show α ++ show (snd pd) ++ show a ++ show b :: Hash
    let e = parseHex (show hsh )`mod` q
    let (ay,bz) = verifierResponse pub a b (snd vk) (snd pd) e
    let z = challengeResponse prv pub τ e
    return $ (ay,bz,z)

verifyZKPofDL :: PublicKey -> CipherText -> Integer -> Integer -> Integer -> Bool
verifyZKPofDL PublicKey{..} (CipherText (α,_)) ay bz z = checkCongruence gz ay p && checkCongruence αz bz p
    where
        gz = expFast g z p
        αz = expFast α z p

parseHex :: String -> Integer
parseHex str = toInteger $ parser $ reverse str
    where
        parser []     = 0
        parser (x:xs) = digitToInt x + 16 * parser xs


sigmaProtocol :: PrivateKey -> PublicKey -> IO Bool
sigmaProtocol PrivateKey{..} pub@PublicKey{..} = do
    let h = expFast g x p
    r <- generateMax q
    let a = expFast g r p
    let t = floor $ logBase 2 (fromInteger q)
    e <- generateMax (2 ^ t)
    let z = r + expFast (e * x) 1 q
    let gz = expFast g z p
    let he = expFast h e p
    let test = expFast (a*he) 1 p
    return $ checkCongruence gz test p

nonInteractiveZKP :: PrivateKey -> PublicKey -> IO NIZKP
nonInteractiveZKP PrivateKey{..} pub@PublicKey{..} = do
    -- let h = expFast g x p
    r <- generateMax q
    let a = expFast g r p
    let hsh = hash $ B8.pack $ show g ++ show y ++ show a :: Hash
    let e = parseHex (show hsh )`mod` q
    let z = r + expFast (e * x) 1 q
    -- let gz = expFast g z p
    -- let he = expFast h e p
    -- let test = expFast (a*he) 1 p
    return $ NIZKP a hsh z
    -- return $ checkCongruence gz test p

verifyZKP :: PublicKey -> NIZKP -> Bool
verifyZKP PublicKey{..} NIZKP{..} = checkCongruence gz test p
    where
        gz = expFast g z p
        e = parseHex (show fsHash) `mod` q
        he = expFast y e p
        test = expFast (a * he) 1 p

runFS :: IO ()
runFS = do
    (pub,prv) <- genKeys 6
    nizkp <- nonInteractiveZKP prv pub
    print $ verifyZKP pub nizkp

checkCongruence:: Integer -> Integer -> Integer -> Bool
checkCongruence a b modm
    | (a-b) `mod` modm == 0 = True
    | otherwise = False
