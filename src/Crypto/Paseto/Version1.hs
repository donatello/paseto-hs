module Crypto.Paseto.Version1
    ( V1EncryptionKey
    , newV1EncryptionKey
    , v1Encrypt
    , v1Decrypt

    , V1PublicKey
    , V1PrivateKey
    , newV1KeyPair
    , v1Sign
    , v1Verify

    , PasetoError(..)
    ) where

import qualified Data.ByteArray as BA
import qualified Crypto.Cipher.Types as Cct
import qualified Crypto.Error as Cerr
import qualified Crypto.KDF.HKDF as Hkdf
import qualified Crypto.PubKey.RSA as Rsa
import qualified Crypto.PubKey.RSA.PSS as Pss
import qualified Data.ByteString as B

import           Crypto.Paseto.Common

v1LocalHeader :: ByteString
v1LocalHeader = "v1.local."

newtype V1EncryptionKey = V1EncryptionKey ByteString

newV1EncryptionKey :: IO V1EncryptionKey
newV1EncryptionKey =
  V1EncryptionKey <$> getRandomBytes 32

getNonce
  :: ( ByteArrayAccess msg
     , ByteArrayAccess nonce
     )
  => msg
  -> nonce
  -> ByteString
getNonce msg nonce =
  let nonceSize = 32
  in BA.convert $ BA.takeView (hmacSHA384 nonce msg) nonceSize

-- Encryption Key and Authentication Key computation
splitKey
  :: ( ByteArrayAccess key
     , ByteArrayAccess nonce
     )
  => key
  -> nonce
  -> (BA.Bytes, BA.Bytes)
splitKey key nonce =
  let salt = BA.takeView nonce 16
      prk :: Hkdf.PRK SHA384 = Hkdf.extract salt key
      encryptionKeyInfo = "paseto-encryption-key" :: ByteString
      outLen = 32
      encryptionKey = Hkdf.expand prk encryptionKeyInfo outLen
      authenticationKeyInfo = "paseto-auth-key-for-aead" :: ByteString
      authenticationKey = Hkdf.expand prk authenticationKeyInfo outLen
  in (encryptionKey, authenticationKey)

v1Encrypt
  :: ByteString
  -> V1EncryptionKey
  -> Maybe ByteString
  -> IO ByteString
v1Encrypt message (V1EncryptionKey key) footerMay = do
  randBytes <- getRandomBytes 32
  let h = v1LocalHeader

      nonce = getNonce message randBytes

      (encryptionKey, authenticationKey) = splitKey key nonce
      cipherR = Cct.cipherInit encryptionKey

  cipherKey :: AES256 <- Cerr.throwCryptoErrorIO cipherR

  let encryptionNonce = BA.dropView nonce 16
      ivMaybe :: Maybe (Cct.IV AES256) = Cct.makeIV encryptionNonce

  iv <- maybe
        (throwIO Cerr.CryptoError_IvSizeInvalid)
        return
        ivMaybe

  let c = BA.convert $ Cct.ctrCombine cipherKey iv message

      preAuth =
        preAuthEncode [h, nonce, c,
                       maybe BA.empty BA.convert footerMay]
  let t = BA.convert $ hmacSHA384 authenticationKey preAuth
      nct = base64UrlEncode $ BA.concat [nonce, c, t]
  return $ case footerMay of
    Just footer -> B.concat [h, nct, dot, base64UrlEncode $ BA.convert footer]
    Nothing -> B.concat [h, nct]

v1Decrypt
  :: ByteString
  -> V1EncryptionKey
  -> Maybe ByteString
  -> Either PasetoError ByteString
v1Decrypt message (V1EncryptionKey key) footerMay = do
  let
    parseRes = parseToken message

  (h, body, recFooterMay) <- maybe (Left InvalidTokenFormat) return parseRes

  recFooterDecMay <- footerCheck footerMay recFooterMay

  when (BA.convert h /= v1LocalHeader) $ Left InvalidHeader

  binMsg <- base64UrlDecode $ BA.convert body
  let (nonce, rest1) = BA.splitAt 32 binMsg
      cipherLen = BA.length rest1 - 48
      (cipher, tag) = BA.splitAt cipherLen rest1
      (encryptionKey, authenticationKey) = splitKey key nonce

      preAuth =
        preAuthEncode [BA.convert h, nonce, cipher,
                       maybe BA.empty BA.convert recFooterDecMay]

  let t2 :: BA.Bytes = BA.convert $ hmacSHA384 authenticationKey preAuth

  -- Authenticate the tag
  unless (BA.constEq t2 tag) $ Left AuthTagMismatch

  -- Decrypt
  let cipherR = Cct.cipherInit encryptionKey
  cipherKey :: AES256 <- either (Left . CryptoErr) return $
                         Cerr.eitherCryptoError cipherR
  let encryptionNonce = BA.dropView nonce 16
      ivMaybe :: Maybe (Cct.IV AES256) = Cct.makeIV encryptionNonce

  iv <- maybe
        (Left InvalidV1LocalIV)
        return
        ivMaybe

  let plainText = BA.convert $ Cct.ctrCombine cipherKey iv cipher
  return plainText

rsaPublicExponent :: Integer
rsaPublicExponent = 65537

rsaKeySizeBytes :: Int
rsaKeySizeBytes = 2048 `div` 8

newtype V1PrivateKey = V1PrivateKey Rsa.PrivateKey

newtype V1PublicKey = V1PublicKey Rsa.PublicKey

newV1KeyPair :: IO (V1PublicKey, V1PrivateKey)
newV1KeyPair = do
  (pub, sec) <- Rsa.generate rsaKeySizeBytes rsaPublicExponent
  return (V1PublicKey pub, V1PrivateKey sec)

v1PublicHeader :: BA.Bytes
v1PublicHeader = BA.convert ("v1.public." :: ByteString)

v1Sign
  :: ByteString
  -> V1PrivateKey
  -> Maybe ByteString
  -> IO ByteString
v1Sign message (V1PrivateKey key) footerMay = do
  let h = v1PublicHeader
      m2 = preAuthEncode
           [h, BA.convert message,
            maybe BA.empty BA.convert footerMay]

      pssParams = Pss.defaultPSSParams SHA384

  result <- Pss.signSafer pssParams
            key m2
  sign <- either (throwIO . RSAError) return result
  let resPart = B.concat [ BA.convert h
                         , BA.convert $ base64UrlEncode $
                           BA.convert $ message <> sign
                         ]

  case footerMay of
    Nothing -> return resPart
    Just footer -> return $ resPart <> "." <> BA.convert (base64UrlEncode $ BA.convert footer)

v1Verify
  :: ByteString
  -> V1PublicKey
  -> Maybe ByteString
  -> Either PasetoError ByteString
v1Verify signedMessage (V1PublicKey pubKey) footerMay = do
  let
    parseRes = parseToken signedMessage

  (h, body, recFooterMay) <- maybe (Left InvalidTokenFormat) return parseRes

  recFooterDecMay <- footerCheck footerMay recFooterMay

  when (BA.convert h /= v1PublicHeader) $
    Left InvalidHeader

  decodedMsg <- base64UrlDecode $ BA.convert body
  let pos = BA.length decodedMsg - 256
      (msg, sig) = BA.splitAt pos decodedMsg
      m2 = preAuthEncode
           [h, BA.convert msg,
            maybe BA.empty
            BA.convert  recFooterDecMay]
      pssParams = Pss.defaultPSSParams SHA384

      verified = Pss.verify pssParams pubKey m2 $ BA.convert sig

  if verified
    then return $ BA.convert msg
    else Left SignatureInvalid
