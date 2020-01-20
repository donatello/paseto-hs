-- | Uses [relude](https://hackage.haskell.org/package/relude) as default Prelude.

module Prelude
       ( module Relude

       , ByteArrayAccess
       , ByteArray

       , SHA384(SHA384)
       , AES256
       , Digest

       , throwIO
       )
where

import Relude

import Data.ByteArray
import Crypto.Hash
import Crypto.Cipher.AES

import Control.Exception
