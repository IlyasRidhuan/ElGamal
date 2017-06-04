{-# LANGUAGE RecordWildCards #-}
module ZKP where

import Components
import Crypto.Number.ModArithmetic
import Crypto.Number.Generate
import Crypto.Random.Types

interactiveProof :: MonadRandom m => PublicKey -> CipherText -> m (Integer,Integer,Integer)
interactiveProof PublicKey{..} (CipherText (α,_)) = do
    τ <- generateMax q
    return (expSafe g τ p, expSafe α τ p,τ)

challengeProof :: MonadRandom m => PublicKey -> m Integer
challengeProof PublicKey{..} = do
    let maxi = floor $ logBase 2 (fromInteger q)
    generateMax (2 ^ maxi)

challengeRespond :: PrivateKey -> PublicKey -> Integer -> Integer -> Integer
challengeRespond PrivateKey{..} PublicKey{..} τ u =
    -- τ - expSafe (u * x) 1 q
    τ + expSafe (u * x) 1 q

verifyResponse :: PublicKey -> Integer -> Integer -> Integer -> Integer -> Integer -> (Integer,Integer)
verifyResponse PublicKey{..} γ1 γ2 v z u =
    (expSafe (γ1 * vu ) 1 p, expSafe (γ2 * zu) 1 p)
    where
        vu = expFast v u p
        zu = expFast z u p

checkEqualityOfDL :: PrivateKey -> PublicKey -> (Integer, Integer) -> (Integer,Integer) -> CipherText -> IO Bool
checkEqualityOfDL prv pub@PublicKey{..} vk pd ct@(CipherText (α,_)) = do
    (γ1,γ2,τ) <- interactiveProof pub ct
    u <- challengeProof pub
    let w = challengeRespond prv pub τ u
    print w
    let (γ3,γ4) = verifyResponse pub γ1 γ2 (snd vk) (snd pd) u
    let gw = expFast g w p
    let αw = expFast α w p
    return $ gw == γ3 && αw == γ4
    -- if gw == γ3 && αw == γ4
    -- then putStrLn "True"
    -- else putStrLn "False"



singleInteractiveProof :: PrivateKey -> PublicKey -> IO Bool
singleInteractiveProof PrivateKey{..} pub@PublicKey{..} = do
    w <- generateMax q
    let h = expFast g w p
    r <- generateMax q
    let a = expFast g r p
    let t = floor $ logBase 2 (fromInteger q)
    e <- generateMax (2 ^ t)
    let z = r + expFast (e * w) 1 q
    let gz = expFast g z p
    let he = expFast h e p
    let test = expFast (a*he) 1 p
    print gz
    print test
    return $ gz == test
