module Main where
import ElGamal

main :: IO ()
main = do
    -- Generate a 64 bit key pair
    (pub,prv) <- genKeys 64

    -- Encrypt 10 & 20
    ct <- encrypt pub (PlainText 10)
    ct' <- encrypt pub (PlainText 20)
    -- Multiply them together
    let ct'' = ct * ct'

    -- Should print out 200
    print $ decrypt prv pub ct''
