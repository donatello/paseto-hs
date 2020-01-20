module Crypto.Paseto.Common
    ( PasetoError(..)
    , hmacSHA384
    , base64UrlEncode
    , base64UrlDecode
    , preAuthEncode
    , dot
    , getRandomBytes
    , footerCheck
    , parseToken
    ) where

import qualified Crypto.Random as R
import qualified Crypto.MAC.HMAC as Hmac
import qualified Data.ByteArray as BA
import qualified Data.ByteArray.Pack as Bap
import           Data.Memory.Endian (toLE)
import qualified Data.ByteArray.Encoding as Bae
import qualified Crypto.Error as Cerr
import qualified Crypto.PubKey.RSA.Types as RsaTypes
import           Data.Char (ord)

data PasetoError = PreAuthError String
                 | FooterMismatch
                 | InvalidHeader
                 | InvalidKeySize
                 | DecodingErr String
                 | AuthTagMismatch
                 | InvalidV1LocalIV
                 | CryptoErr Cerr.CryptoError
                 | RSAError RsaTypes.Error
                 | InvalidTokenFormat
                 | SignatureInvalid
                 deriving (Eq, Show)

instance Exception PasetoError

dotW :: Word8
dotW = fromIntegral $ ord '.'

dot :: ByteString
dot = "."

getRandomBytes :: Int -> IO ByteString
getRandomBytes = R.getRandomBytes

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
  :: ByteString
  -> ByteString
base64UrlEncode =
  Bae.convertToBase Bae.Base64URLUnpadded

base64UrlDecode
  :: ByteString
  -> Either PasetoError ByteString
base64UrlDecode b =
  first DecodingErr $
  Bae.convertFromBase Bae.Base64URLUnpadded b

preAuthEncode
  :: ByteArrayAccess bin
  => [bin]
  -> ByteString
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

-- Compare footer. Assumes received footer is base64 encoded (but not the
-- expected footer).
footerCheck
  :: Maybe ByteString
  -> Maybe ByteString
  -> Either PasetoError (Maybe ByteString)
footerCheck expectedFooterMaybe receivedFooterMaybe = do
  let receivedDecFooterMaybe =
        maybe (Right Nothing) (fmap Just . base64UrlDecode) receivedFooterMaybe
  case expectedFooterMaybe of
    Nothing -> receivedDecFooterMaybe
    Just expectedFooter -> do
      receivedEncFooter <- maybe (Left FooterMismatch) return receivedFooterMaybe
      receivedFooter <- base64UrlDecode receivedEncFooter
      let expFooter :: ByteString = BA.convert expectedFooter
          recFooter :: ByteString = BA.convert receivedFooter
      unless (BA.constEq expFooter recFooter) $
        Left FooterMismatch
      return $ Just receivedFooter

-- Parse a Paseto token into its components
parseToken
  :: ByteArrayAccess m
  => m
  -> Maybe (ByteString, ByteString, Maybe ByteString)
parseToken m = do
  let
    splitFunc b = let (p, q) = BA.span (/= dotW) b
                  in (p, BA.drop 1 q)
    r = BA.convert m
    (p1, r1) = splitFunc r
    (p2, r2) = splitFunc r1
    (p3, p4) = splitFunc r2
    isEmpty b = if BA.null b then Nothing else Just b

  hp1 <- isEmpty p1
  hp2 <- isEmpty p2
  body <- isEmpty p3
  let footerMay = isEmpty p4
  return (hp1 <> "." <> hp2 <> ".", body, footerMay)
