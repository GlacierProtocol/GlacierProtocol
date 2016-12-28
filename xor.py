#!/usr/bin/env python

# todo: convert string comprehensions to for-loops where they are easier to read. 

import argparse
import sys
import hashlib
from hashlib import sha256
import random
import subprocess
import json

#### Begin portion copyrighted by David Keijser #####

# Copyright (c) 2015 David Keijser

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


# 58 character alphabet used
alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


if bytes == str:  # python2
    iseq = lambda s: map(ord, s)
    bseq = lambda s: ''.join(map(chr, s))
    buffer = lambda s: s
else:  # python3
    iseq = lambda s: s
    bseq = bytes
    buffer = lambda s: s.buffer


def b58encode(v):
  '''Encode a string using Base58'''

  if not isinstance(v, bytes):
      raise TypeError("a bytes-like object is required, not '%s'" %
                      type(v).__name__)

  origlen = len(v)
  v = v.lstrip(b'\0')
  newlen = len(v)

  p, acc = 1, 0
  for c in iseq(v[::-1]):
      acc += p * c
      p = p << 8

  result = ''
  while acc > 0:
      acc, mod = divmod(acc, 58)
      result += alphabet[mod]

  return (result + alphabet[0] * (origlen - newlen))[::-1]


def b58decode(v):
  '''Decode a Base58 encoded string'''

  if not isinstance(v, str):
      v = v.decode('ascii')

  origlen = len(v)
  v = v.lstrip(alphabet[0])
  newlen = len(v)

  p, acc = 1, 0
  for c in v[::-1]:
      acc += p * alphabet.index(c)
      p *= 58

  result = []
  while acc > 0:
      acc, mod = divmod(acc, 256)
      result.append(mod)

  return (bseq(result) + b'\0' * (origlen - newlen))[::-1]


def b58encode_check(v):
  '''Encode a string using Base58 with a 4 character checksum'''

  digest = sha256(sha256(v).digest()).digest()
  return b58encode(v + digest[:4])


def b58decode_check(v):
  '''Decode and verify the checksum of a Base58 encoded string'''

  result = b58decode(v)
  result, check = result[:-4], result[-4:]
  digest = sha256(sha256(result).digest()).digest()

  if check != digest[:4]:
      raise ValueError("Invalid checksum")

  return result


#### end portion copyrighted by David Keijser #####

#### Dice handling functions ####

def check_dice(dices):
    
  for dice in dices:
    try:
      i = int(dice)
      if i < 1 or i > 6:
        print "Error: dice rolls must be between 1 and 6"
        return False
    except ValueError:
      print "Error: dice values should be numbers between 1 and 6"
      return False

  return True

def read_dice_interactive(min_length):
  """reads min_length dice from standard in and returns a string representing the dice rolls"""
  
  def ask_for_dice_rolls(x):
    print "enter {0} dice rolls:".format(x)


  results = ""
  
  while len(results) < min_length:
    ask_for_dice_rolls(min_length - len(results))
    dices = raw_input()

    if check_dice(dices):
      results += dices

  return results


#### Random Seed functions ####

def check_seed(seed, min_length):
  if len(seed) < min_length:
    print "Error: seed must be at least {0} hex characters long".format(min_length)
    return False
  
  if len(seed) % 2 != 0:
    print "Error: seed must contain even number of characters"
    return False
  
  try:
    int(seed, 16)
  except ValueError:
    print "Error: Illegal character. Seed must be composed of hex characters"
    return False
  
  return True


def read_seed_interactive(min_length):
  """Reads random seed of at least min_length characters and returns it as string"""

  def ask_for_random_seed(length):
    print "enter random seed as a hex string with at least {0} characters".format(length)

  ask_for_random_seed(min_length)
  seed = raw_input()

  while not check_seed(seed, min_length):
    ask_for_random_seed(min_length)
    seed = raw_input()

  return seed


#### main private key creation functions #####

def seed_to_WIF(seed):
  seed_80 = "80" + seed

  key = seed_80 + checksum(seed_80)
  print key

  key_58 = b58encode(key.decode("hex"))
  print key_58
  return key_58
  

def hashSha256(s):
  """A thin wrapper around the hashlib sha 256 library to provide a more functional interface"""
  m = sha256()
  m.update(s)
  return m.hexdigest()

def checksum(s):
  h1 = hashSha256(s.decode("hex"))
  print h1
  h2 = hashSha256(h1.decode("hex"))
  print h2[0:8]
  return h2[0:8]


def wif_interactive(dice_length = 62, seed_length = 20):
  # dice_string = read_dice_interactive(dice_length)
  dice_string = "223425362526352316253516215216351525112515236121213423423412312"
  
  dice_hash = hashSha256(dice_string)

  # seed_string = read_seed_interactive(seed_length)
  seed_string = "fbbc1ebe258b549f32bbff7adabb4cb3d1a1321935345a5eddc157bef20fb7d0"
  seed_hash = hashSha256(seed_string)

  # get decimal numbers and bitwise or them
  dice_dec = int(dice_hash, 16)
  seed_dec = int(seed_hash, 16)

  xored = seed_dec ^ dice_dec

  # print xored
  combined_seed = "{:02x}".format(xored)
  print "combined seed:", combined_seed
  
  return seed_to_WIF(combined_seed)


#### multisig creation functions #####

def get_address_for_privkey(privkey):
  """A method for retrieving the address associated with a private key from bitcoin core
     <privkey> - a bitcoin private key in WIF format"""

  # Arbitrary label. A unique label ensures that we will get back only one public key 
  # when we call the "getaddressesbyaccount" rpc later
  label = random.randint(0, 2**128)
  subprocess.call("bitcoin-cli importprivkey {0} {1}".format(privkey, label), shell=True)
  addresses = subprocess.check_output("bitcoin-cli getaddressesbyaccount {0}".format(label), shell=True)
  addresses_json = json.loads(addresses)
  return addresses_json[0]

def get_multisig_interactive(m,n):
  """Asks user for n bitcoin addresses. Returns an m of n multisig address and redeem script"""
  addrs = []
  while len(addrs) < n:
    print "enter address #{0}:".format(len(addrs) + 1)
    new_addr = raw_input()
    addrs.append(new_addr)
  
  addrs_string = json.dumps(addrs)
  label = random.randint(0, 2**128)

  argstring = "{0} '{1}'".format(m, addrs_string)

  results = subprocess.check_output("bitcoin-cli createmultisig {0}".format(argstring), shell=True)
  
  return json.loads(results)


#### multisig redemption functions ####

def multisig_gen_trx(dest_addr, amount, redeem_script, in_txid, in_vout, in_ouput_script, privkeys):
  data_1 = [{
   "txid": in_txid,
   "vout": in_vout
  }]
  dest_data_1 = {
    dest_addr: amount
  }
  argstring_1 = "'{0}' '{1}'".format(json.dumps(data_1), json.dumps(dest_data_1))
  print argstring_1

  tx_hex = subprocess.check_output("bitcoin-cli createrawtransaction {0}".format(argstring_1), shell=True).strip()

  print tx_hex
  
  data_2 = [{
    "txid": in_txid,
    "vout": in_vout,
    "scriptPubKey": in_ouput_script,
    "redeemScript": redeem_script
  }]

  argstring_2 = "{0} '{1}' '{2}'".format(tx_hex, json.dumps(data_2), json.dumps(privkeys))
  signed_tx_hex = subprocess.check_output("bitcoin-cli signrawtransaction {0}".format(argstring_2), shell=True).strip()

  print signed_tx_hex

  return signed_tx_hex


if __name__ == "__main__": 

  # wif_interactive()
  # print get_address_for_privkey("5JHLk1zFzbDY7jJS6RdmZYqHEv5J89NpVC7teru7xrhghqo53mf")

  # print get_multisig_interactive(1,2)
  print multisig_gen_trx("14bdjdoN2orodNcPaq5iVd8aSToKKn7cnN", 0.00020000, "51410421167f7dac2a159bc3957e3498bb6a7c2f16874bf1fbbe5b523b3632d2c0c43f1b491f6f2f449ae45c9b0716329c0c2dbe09f3e5d4e9fb6843af083e222a70a441043704eafafd73f1c32fafe10837a69731b93c0179fa268fc325bdc08f3bb3056b002eac4fa58c520cc3f0041a097232afbe002037edd5ebdab2e493f18ef19e9052ae",
    "5a507797946da2310ddbc6820e1115ca6d640ab499cb1748db316030c269cb62", 0, "a914f1e3f2ba9971cf5f82daf0f8fe6b4c999f4dfc3587", ["5JHLk1zFzbDY7jJS6RdmZYqHEv5J89NpVC7teru7xrhghqo53mf", "5JH4aEVfQgfjC4tZ394sWyGv8NqLMPd3XmwVtnJ1cKwksYQqan6"])


