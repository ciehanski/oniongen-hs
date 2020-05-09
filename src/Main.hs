{-# LANGUAGE OverloadedStrings #-}
module Main where

import Crypto.Sign.Ed25519 as Ed
import Crypto.Hash
import System.IO as Sys
import qualified Data.ByteString as B
import Data.ByteString.Char8
import Data.ByteString.Base32 as Base32
import Data.Byteable
import System.Environment   

main :: IO ()
main = do
  -- Get arguments
  args <- getArgs
  mapM_ Sys.putStrLn args

  -- Create an Ed25519 keypair, but only retain the public key
  (pk, _) <- Ed.createKeypair
  
  -- Generate an onion checksum with public key
  let chksum = genChecksum pk

  -- Generate onion address from public key and cheksum
  let onionAddress = genOnionAddress pk chksum

  Sys.putStrLn onionAddress

genChecksum :: PublicKey -> ByteString
genChecksum pk = do
  -- checksum = H(".onion checksum" || pubkey || version)
  let onion = ".onion checksum" :: ByteString
  let pub = unPublicKey pk
  let ver = "0x03" :: ByteString
  let chkStr = B.concat [onion, pub, ver]
  let chksum = hash chkStr :: Digest SHA3_256 
  toBytes chksum

genOnionAddress :: PublicKey -> ByteString -> Base32
genOnionAddress pk chksum = do
  -- onion_address = base32(pubkey || checksum || version)
  let pub = unPublicKey pk
  let ver = "0x03" :: ByteString
  let addr = B.concat [pub, chksum, ver]
  let onionAddr = B.unpack addr
  Base32.encode onionAddr
