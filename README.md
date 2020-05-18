# oniongen-hs

oniongen-hs is a vanity URL generator for Tor version 3 .onion addresses, lovingly written in Haskell.

Heavily inspired by [oniongen-go](https://github.com/rdkr/oniongen-go).

## Usage

```bash
oniongen <regex>

    regex: regular expression pattern addresses should match, consisiting of: a-z, 2-7
```

## Example

```bash
> oniongen "^ryan"
> Generating...
> ryane5ngexawoklpkitekx6u5n4kokynwz6zdxiivusjtq2o246dryqd.onion
> CPU Time: 44.78s
```

The public key, private key, and generated onion address are then saved in the current user's homepath "~/oniongen" where they can be utilized to host your newly created vanity URL over the Tor network.
