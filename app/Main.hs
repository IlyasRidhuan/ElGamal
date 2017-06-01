module Main where
import ElGamal
import ZKP
import ShamirSecretSharing
import ThresholdElGamal
import Components

main :: IO ()
main = do
    -- Generate a 64 bit key pair
    (pub,prv) <- genKeys 64

    threshKeys <- genThresholdKeys prv 3 5
    let verKeys = genVerificationKeys pub threshKeys

    ct@(CipherText (α,β)) <- standardEncrypt pub (PlainText 20)
    let part = (\x -> partialDecrypt x pub ct) <$> threshKeys
    putStrLn "Waiting"
    checkEqualityOfDL (snd . head $ threshKeys) pub (head verKeys) (head part) ct

    print $ thresholdDecrypt pub ct (take 4 part)

    -- -- Encrypt 10 & 20
    -- ct <- standardEncrypt pub (PlainText 10)
    -- ct' <- standardEncrypt pub (PlainText 20)
    -- -- Multiply them together
    -- let ct'' = ct * ct'
    --
    -- -- Should print out 200
    -- print $ standardDecrypt prv pub ct''
