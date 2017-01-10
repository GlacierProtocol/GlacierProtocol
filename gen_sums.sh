#!/bin/sh

rm SHA256SUMS SHA256SUMS.sig
shasum -a 256 -b xor.py >> SHA256SUMS
shasum -a 256 -b README.md >> SHA256SUMS
shasum -a 256 -b BitcoinHighSecurityStorageProtocolv0.1AlphaWORKINGCOPY.pdf >> SHA256SUMS
gpg --output SHA256SUMS.sig --armor --detach-sig SHA256SUMS
