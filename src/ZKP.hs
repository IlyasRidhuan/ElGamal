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
challengeProof PublicKey{..} = generateMax q

challengeRespond :: PrivateKey -> PublicKey -> Integer -> Integer -> Integer
challengeRespond PrivateKey{..} PublicKey{..} τ u =
    τ - expSafe (u * x) 1 q

verifyResponse :: PublicKey -> CipherText  -> Integer -> Integer -> Integer -> Integer -> (Integer,Integer)
verifyResponse PublicKey{..} (CipherText (α,_)) u v w z =
    (expSafe (gw * vu) 1 p, expSafe (αw * zu) 1 p)
    where
        gw = expSafe g w p
        vu = expSafe v u p
        αw = expSafe α w p
        zu = expSafe z u p

checkEqualityOfDL :: PrivateKey -> PublicKey -> (Integer, Integer) -> (Integer,Integer) -> CipherText -> IO ()
checkEqualityOfDL prv pub vk pd ct = do
    (γ1,γ2,τ) <- interactiveProof pub ct
    print $ "tau is : " ++ show τ
    print $ "l1 is  : " ++ (show γ1)
    print $ "l2 is  : " ++ (show γ2)
    u <- challengeProof pub
    let w = challengeRespond prv pub τ u
    print w
    let (γ3,γ4) = verifyResponse pub ct u (snd vk) w (snd pd)
    print $ "l3 is  : " ++ (show γ3)
    print $ "l4 is  : " ++ (show γ4)
    if γ1 == γ3 && γ2 == γ4
    then putStrLn "True"
    else putStrLn "False"
