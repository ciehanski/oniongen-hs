-- Copyright (C) 2020 Ryan Ciehanski. All Rights Reserved.
module Main where

import           Control.Concurrent
import qualified Crypto.Hash            as H (Digest, SHA3_256, hash)
import           Crypto.Sign.Ed25519
import           Data.Binary.Put
import           Data.ByteArray         (convert)
import qualified Data.ByteString        as B
import           Data.ByteString.Base32 (encodeBase32')
import qualified Data.ByteString.Char8  as C
import qualified Data.ByteString.Lazy   as BL
import           Data.Char              (toLower)
import           System.Directory       (createDirectoryIfMissing,
                                         getHomeDirectory)
import           System.Environment     (getArgs)
import           System.TimeIt          (timeIt)
import           Text.Regex.TDFA

main :: IO ()
main = do
  -- Compile regex from 1st argument provided
  args <- getArgs
  let rgx = args !! 1 :: String

  -- Check if regex argument was provided and fail if otherwise
  if null args || null rgx then
    putStrLn "Regex argument must be provided. Exiting..."
  else do
    -- MVar of valid onion address found
    onionAddress <- newEmptyMVar

    -- Run this bad boy in another thread
    putStrLn "Generating..."
    forkIO $ generate onionAddress rgx

    -- Wait 'til generate is complete then print the result
    timeIt $ C.putStrLn =<< takeMVar onionAddress

generate :: MVar B.ByteString -> String -> IO ()
generate addr rgx = do
  -- Create an Ed25519 keypair
  (pk, sk) <- createKeypair

  -- Generate onion address from public key and checksum
  let onionAddress = genOnionAddress pk $ genChecksum pk

  -- If regex doesn't match the generated onion address, recursively
  -- call the generate function
  if onionAddress =~ rgx then do
    saveKeypairs onionAddress rgx pk sk
    putMVar addr onionAddress
  else
    generate addr rgx

saveKeypairs :: B.ByteString -> String -> PublicKey -> SecretKey -> IO ()
saveKeypairs onionAddress rgx pk sk = do
  homeDir <- getHomeDirectory
  let oniongenDir = homeDir ++ "/oniongen/"
  createDirectoryIfMissing True oniongenDir
  B.writeFile (oniongenDir ++ rgx ++ ".pub") $ unPublicKey pk
  B.writeFile (oniongenDir ++ rgx) $ unSecretKey sk
  B.writeFile (oniongenDir ++ rgx ++ "_hostname.txt") onionAddress

serializeChecksum :: PublicKey -> Put
serializeChecksum pk = do
  -- checksum = SHA3_256(".onion checksum" || pubkey || version)
  putStringUtf8 ".onion checksum"
  putByteString $ unPublicKey pk
  putInt8 3

genChecksum :: PublicKey -> B.ByteString
genChecksum pk =
  let
    chksum = B.concat $ BL.toChunks $ runPut $ serializeChecksum pk
    hashedChksum = H.hash chksum :: H.Digest H.SHA3_256
  in convert hashedChksum

serializeAddress :: PublicKey -> B.ByteString -> Put
serializeAddress pk chksum = do
  -- onion_address = base32(pubkey || checksum || version)
  putByteString $ unPublicKey pk
  putByteString $ B.take 2 chksum
  putInt8 3

genOnionAddress :: PublicKey -> B.ByteString -> B.ByteString
genOnionAddress pk chksum =
  let addr = B.concat $ BL.toChunks $ runPut $ serializeAddress pk chksum
   in C.map toLower $ B.concat [encodeBase32' addr, C.pack ".onion"]
