module Crypto.Paseto
       ( v1Encrypt
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

data PasetoError = PreAuthError String
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
base64UrlEncode bin = Bae.convertToBase Bae.Base64URLUnpadded bin

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
  -> Either String bout
preAuthEncode pieces =
  let n = toW64 $ length pieces
      toW64 n1 = fromIntegral n1 :: Word64
      packSize = fromIntegral $ 8 + 8 * n + (toW64 $ sum $ map BA.length pieces)
      packer = do
        Bap.putStorable $ toLE n
        forM pieces $ \p -> do
          Bap.putStorable $ toLE $ toW64 $ BA.length p
          Bap.putBytes p
  in Bap.fill packSize packer

mustPreAuthEncode
  :: ( ByteArrayAccess bin
     , ByteArray bout
     )
  => [bin]
  -> IO bout
mustPreAuthEncode ps =
  case preAuthEncode ps of
    Left err -> throwIO $ PreAuthError err
    Right b -> return b

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

  preAuth :: BA.Bytes <- mustPreAuthEncode [h, nonce, c, maybe BA.empty BA.convert footerMay]
  let t = BA.convert $ hmacSHA384 authenticationKey preAuth
      nct = base64UrlEncode $ BA.concat [nonce, c, t]
  return $ case footerMay of
    Just footer -> BA.concat [h, nct, dot, base64UrlEncode $ BA.convert footer]
    Nothing -> BA.concat [h, nct]
