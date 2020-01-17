module Crypto.Paseto
       ( v1Encrypt
       , v1Decrypt
       )
where

import qualified Crypto.Random as R
import qualified Crypto.MAC.HMAC as Hmac
import qualified Data.ByteArray as BA
import qualified Crypto.KDF.HKDF as Hkdf
import qualified Crypto.Cipher.Types as Cct
import qualified Crypto.Error as Cerr
import qualified Data.ByteArray.Pack as Bap
import           Data.Memory.Endian (toLE)
import qualified Data.ByteArray.Encoding as Bae
import           Data.Char (ord)

data PasetoError = PreAuthError String
                 | FooterMismatch
                 | InvalidHeader
                 | DecodingErr String
                 | AuthTagMismatch
                 | InvalidV1LocalIV
                 | CryptoErr Cerr.CryptoError
                 deriving (Show)

instance Exception PasetoError

hmacSHA384
  :: ( ByteArrayAccess message
     , ByteArrayAccess key
     )
  => key
  -> message
  -> Digest SHA384
hmacSHA384 key message =
  Hmac.hmacGetDigest $ Hmac.hmac key message

base64UrlEncode
  :: BA.Bytes
  -> BA.Bytes
base64UrlEncode = Bae.convertToBase Bae.Base64URLUnpadded

base64UrlDecode
  :: BA.Bytes
  -> Either PasetoError BA.Bytes
base64UrlDecode b =
  first DecodingErr $ Bae.convertFromBase Bae.Base64URLUnpadded b

getNonce
  :: ( ByteArrayAccess msg
     , ByteArrayAccess nonce
     )
  => msg
  -> nonce
  -> BA.Bytes
getNonce msg nonce =
  let nonceSize = 32
  in BA.convert $ BA.takeView (hmacSHA384 nonce msg) nonceSize

preAuthEncode
  :: ( ByteArrayAccess bin
     , ByteArray bout
     )
  => [bin]
  -> bout
preAuthEncode pieces =
  let n = toW64 $ length pieces
      toW64 n1 = fromIntegral n1 :: Word64
      packSize = fromIntegral $ 8 + 8 * n + toW64 (sum $ map BA.length pieces)
      packer = do
        Bap.putStorable $ toLE n
        forM pieces $ \p -> do
          Bap.putStorable $ toLE $ toW64 $ BA.length p
          Bap.putBytes p
  in case Bap.fill packSize packer of
       Left err -> bug $ PreAuthError err
       Right b -> b

v1LocalHeader :: BA.Bytes
v1LocalHeader = BA.convert ("v1.local." :: ByteString)

dot :: BA.Bytes
dot = BA.convert ("." :: ByteString)

getRandomBytes :: Int -> IO BA.Bytes
getRandomBytes = R.getRandomBytes

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
  :: ( ByteArray msg
     , ByteArrayAccess key
     , ByteArrayAccess footer
     , ByteArray out
     )
  => msg
  -> key
  -> Maybe footer
  -> IO out
v1Encrypt message key footerMay = do
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

      preAuth :: BA.Bytes =
        preAuthEncode [h, nonce, c,
                       maybe BA.empty BA.convert footerMay]
  let t = BA.convert $ hmacSHA384 authenticationKey preAuth
      nct = base64UrlEncode $ BA.concat [nonce, c, t]
  return $ case footerMay of
    Just footer -> BA.concat [h, nct, dot, base64UrlEncode $ BA.convert footer]
    Nothing -> BA.concat [h, nct]

isDot :: Word8 -> Bool
isDot w = let o = ord '.'
              n = fromIntegral o :: Word8
          in n == w

v1Decrypt
  :: ( ByteArray msg
     , ByteArrayAccess key
     , ByteArrayAccess footer
     , ByteArray out
     )
  => msg
  -> key
  -> Maybe footer
  -> Either PasetoError out
v1Decrypt message key footerMay = do
  let (h, rest) = BA.splitAt (BA.length v1LocalHeader) message
      (m, f') = BA.span (not . isDot) rest
      fEncoded = BA.drop 1 f'

  f <- base64UrlDecode $ BA.convert fEncoded

  let
    -- Footer check uses constant time equality check
    footerCheck v = when (not $ BA.constEq v f) $ Left FooterMismatch

  maybe (return ()) footerCheck footerMay

  when (BA.convert h /= v1LocalHeader) $ Left InvalidHeader

  binMsg <- base64UrlDecode $ BA.convert m
  let (nonce, rest1) = BA.splitAt 32 binMsg
      cipherLen = BA.length rest1 - 48
      (cipher, tag) = BA.splitAt cipherLen rest1
      (encryptionKey, authenticationKey) = splitKey key nonce

      preAuth :: BA.Bytes =
        preAuthEncode [BA.convert h, nonce, cipher,
                       maybe BA.empty BA.convert footerMay]

  let t2 :: BA.Bytes = BA.convert $ hmacSHA384 authenticationKey preAuth

  -- Authenticate the tag
  when (not $ BA.constEq t2 tag) $ Left AuthTagMismatch

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
