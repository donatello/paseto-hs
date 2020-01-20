module Main (main) where

import Test.Tasty
import Test.Tasty.HUnit

import Crypto.Paseto

unitTestV1Encryption :: TestTree
unitTestV1Encryption =
  testCase "V1 Encryption/Decryption" $ do
    key <- newV1EncryptionKey

    let msg = "mymsg"
        footer = "myfooter"
    tokenWithFooter <- v1Encrypt msg key (Just footer)
    tokenWoFooter <- v1Encrypt msg key Nothing

    let resWithExpFooter = v1Decrypt tokenWithFooter key (Just footer)
    assertBool "Decryption failed with expected footer" $ resWithExpFooter == Right msg

    let resWoExpFooter = v1Decrypt tokenWithFooter key Nothing
    assertBool "Decryption failed without expected footer" $ resWoExpFooter == Right msg

    let resWoFooter = v1Decrypt tokenWoFooter key Nothing
    assertBool "Decryption failed without footer" $ resWoFooter == Right msg

unitTestV1Sign :: TestTree
unitTestV1Sign =
  testCase "V1 Sign/Verify" $ do
    (pub, pvt) <- newV1KeyPair

    let msg = "mymsg"
        footer = "myfooter"

    tokenWithFooter <- v1Sign msg pvt (Just footer)
    tokenWoFooter <- v1Sign msg pvt Nothing

    let resWithExpFooter = v1Verify tokenWithFooter pub (Just footer)
    assertBool "Verification failed with expected footer" $ resWithExpFooter == Right msg

    let resWoExpFooter = v1Verify tokenWithFooter pub Nothing
    assertBool "Verification failed without expected footer" $ resWoExpFooter == Right msg

    let resWoFooter = v1Verify tokenWoFooter pub Nothing
    assertBool "Verification failed without footer" $ resWoFooter == Right msg

main :: IO ()
main = defaultMain $ testGroup "V1" [unitTestV1Encryption, unitTestV1Sign]
