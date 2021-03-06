{-# LANGUAGE RecordWildCards #-}
module ZKP where

import ElGamalComponents
import Crypto.Number.ModArithmetic
import Crypto.Number.Generate
import Crypto.Random.Types
import Crypto.Hash
import qualified Data.ByteString.Char8 as B8


-- Sets up the initial commit if a^τ & b^τ by the prover of some random τ
initialCommit :: MonadRandom m => PublicParams -> CipherText -> m (Integer,Integer,Integer)
initialCommit PublicParams{..} (CipherText α _) = do
    τ <- generateMax q
    return (expSafe g τ p, expSafe α τ p,τ)

-- For interactive ZKP only. Generates some random integer e < 2^t where 2^t < q
verifierChallenge :: MonadRandom m => PublicParams -> m Integer
verifierChallenge PublicParams{..} = do
    let maxi = floor (logBase 2 (fromInteger q) :: Double) :: Integer
    generateMax (2 ^ maxi)

challengeResponse :: PrivateKey -> PublicParams -> Integer -> Integer -> Integer
challengeResponse PrivateKey{..} PublicParams{..} τ u =
    τ + expSafe (u * x) 1 q

-- compute discrete logs to be proven against initial commits
verifierResponse :: PublicParams -> Integer -> Integer -> Integer -> Integer -> Integer -> (Integer,Integer)
verifierResponse PublicParams{..} γ1 γ2 v z u =
    (expSafe (γ1 * vu ) 1 p, expSafe (γ2 * zu) 1 p)
    where
        vu = expFast v u p
        zu = expFast z u p

-- Interactive equality of discrete logs for interactive ZKP
checkEqualityOfDL :: PublicParams -> CipherText -> SplitKey -> (Integer,Integer) -> (Integer, Integer) -> IO Bool
checkEqualityOfDL pub@PublicParams{..} ct@(CipherText α _) (_,prv) vk pd  = do
    (a,b,τ) <- initialCommit pub ct
    u <- verifierChallenge pub
    let z = challengeResponse prv pub τ u
    let (ay,bz) = verifierResponse pub a b (snd vk) (snd pd) u
    let gz = expFast g z p
    let αz = expFast α z p
    return $ checkCongruence gz ay p && checkCongruence αz bz p

-- Non interactive equality of discrete logs using the fiat shamir heuristic
nonInteractiveEqofDL :: PublicParams -> CipherText -> SplitKey -> (Integer,Integer) -> (Integer, Integer) -> IO NIZKPDL
nonInteractiveEqofDL pub@PublicParams{..} ct@(CipherText α _) (_,prv) vk pd  = do
    (a,b,τ) <- initialCommit pub ct
    let hsh = hash $ B8.pack $ show g ++ show (snd vk) ++ show α ++ show (snd pd) ++ show a ++ show b :: Hash
    let e = parseHex (show hsh )`mod` q
    let z = challengeResponse prv pub τ e
    return $ NIZKPDL a b z hsh

-- Verifying the ZKP of discrete logs by check the congruence between gz_1 === ay_1 (mod p) && gz_2 === ay_2 (mod p)
verifyZKPofDL :: PublicParams -> CipherText -> NIZKPDL -> (Integer,Integer) -> (Integer, Integer) -> Bool
verifyZKPofDL pub@PublicParams{..} (CipherText α _) NIZKPDL{..} vk pd = checkCongruence gz ay p && checkCongruence αz bz p
    where
        e = parseHex (show fsHash )`mod` q
        (ay,bz) = verifierResponse pub a b (snd vk) (snd pd) e
        gz = expFast g z p
        αz = expFast α z p

-- Basic Sigma Protocol for proving knowledge of the discrete logarithm of some y = g^x
sigmaProtocol :: PrivateKey -> PublicParams -> IO Bool
sigmaProtocol PrivateKey{..} PublicParams{..} = do
    let h = expFast g x p
    r <- generateMax q
    let a = expFast g r p
    let t = floor (logBase 2 (fromInteger q) :: Double) :: Integer
    e <- generateMax ( 2^t )
    let z = r + expFast (e * x) 1 q
    let gz = expFast g z p
    let he = expFast h e p
    let test = expFast (a*he) 1 p
    return $ checkCongruence gz test p

-- NonInteractive Sigma Protocol using the fiat Shamir heuristic
nonInteractiveZKP :: PrivateKey -> PublicParams -> IO NIZKP
nonInteractiveZKP PrivateKey{..} PublicParams{..} = do
    r <- generateMax q
    let a = expFast g r p
    let hsh = hash $ B8.pack $ show g ++ show y ++ show a :: Hash
    let e = parseHex (show hsh )`mod` q
    let z = r + expFast (e * x) 1 q
    return $ NIZKP a hsh z

-- Verifying the zkp of the discrete log of a non interactive ZKP
verifyZKP :: PublicParams -> NIZKP -> Bool
verifyZKP PublicParams{..} NIZKP{..} = checkCongruence gz test p
    where
        gz = expFast g w p
        e = parseHex (show fiatShamir) `mod` q
        he = expFast y e p
        test = expFast (γ * he) 1 p
