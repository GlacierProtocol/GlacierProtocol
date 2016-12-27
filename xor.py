#!/usr/bin/env python

# todo: convert string comprehensions to for-loops where they are easier to read. 

import argparse
import sys
import hashlib
from hashlib import sha256

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


#### main functions #####

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


def main_interactive(dice_length = 62, seed_length = 20):
  # dice_string = read_dice_interactive(dice_length)
  dice_string = "123425362526352316253516215216351525112515236121213423423412312"
  
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


if __name__ == "__main__": 

  main_interactive()  