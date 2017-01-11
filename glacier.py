#!/usr/bin/env python

import argparse
import sys
import hashlib
from hashlib import sha256
import random
import subprocess
import json
from decimal import *

from base58 import b58encode, b58decode, b58encode_check, b58decode_check

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

def seed_to_privkey(seed):
  seed_80 = "80" + seed
  key = seed_80 + checksum(seed_80)
  return key


def key_to_WIF(key):
  key_58 = b58encode(key.decode("hex"))
  return key_58
  

def hashSha256(s):
  """A thin wrapper around the hashlib sha 256 library to provide a more functional interface"""
  m = sha256()
  m.update(s)
  return m.hexdigest()

def checksum(s):
  h1 = hashSha256(s.decode("hex"))
  h2 = hashSha256(h1.decode("hex"))
  return h2[0:8]


def wif_interactive(dice_length = 62, seed_length = 20):

  dice_string = read_dice_interactive(dice_length)
  dice_hash = hashSha256(dice_string)

  seed_string = read_seed_interactive(seed_length)
  seed_hash = hashSha256(seed_string)

  # get decimal numbers and bitwise-or them
  dice_dec = int(dice_hash, 16)
  seed_dec = int(seed_hash, 16)

  xored = seed_dec ^ dice_dec

  # back to hex string
  combined_seed = "{:02x}".format(xored)


  privkey = seed_to_privkey(combined_seed)
  print ""
  print "Your private key (hex):"
  print privkey
  print ""

  privkey_WIF = key_to_WIF(privkey)
  print "Your private key (WIF):"
  print privkey_WIF
  print ""

  address = get_address_for_privkey(privkey_WIF)
  print "Your Bitcoin address:"
  print address
  print ""


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
  
  print "Creating {0}-of-{1} multisig address....".format(m, n)
  print ""

  addrs = []
  while len(addrs) < n:
    print "enter address #{0}:".format(len(addrs) + 1)
    new_addr = raw_input()
    addrs.append(new_addr)
  
  addrs_string = json.dumps(addrs)
  label = random.randint(0, 2**128)

  argstring = "{0} '{1}'".format(m, addrs_string)

  results = subprocess.check_output("bitcoin-cli createmultisig {0}".format(argstring), shell=True)
  results = json.loads(results)
  
  print ""
  print "Redeem script: {0}".format(results["redeemScript"])
  print ""
  print "Multisig address: {0}".format(results["address"])
  print ""


#### multisig redemption functions ####

def multisig_gen_trx(addresses, amount, redeem_script, in_txid, in_vout, in_script_pub_key, privkeys):
  """generate a signed multisig transaction
  addresses: a dictionary of base58 bitcoin destination addresses to decimal bitcoin ammounts
  amount: amount in bitcoins
  redeem_script: hex string,
  in_txid: txid of an input transaction to the multisig address
  in_vout: which output you are sending
  in_output_script: the scriptPubKey of the output
  privkeys: an array of private keys to sign with"""

  data_1 = [{
   "txid": in_txid,
   "vout": int(in_vout)
  }]
  
  argstring_1 = "'{0}' '{1}'".format(json.dumps(data_1), json.dumps(addresses))

  tx_hex = subprocess.check_output("bitcoin-cli createrawtransaction {0}".format(argstring_1), shell=True).strip()

  data_2 = [{
    "txid": in_txid,
    "vout": int(in_vout),
    "scriptPubKey": in_script_pub_key,
    "redeemScript": redeem_script
  }]

  argstring_2 = "{0} '{1}' '{2}'".format(tx_hex, json.dumps(data_2), json.dumps(privkeys))
  signed_tx_hex = subprocess.check_output("bitcoin-cli signrawtransaction {0}".format(argstring_2), shell=True).strip()

  return signed_tx_hex


def yes_no_interactive():
  def confirm_prompt():
    return raw_input("Confirm? (y/n): ")

  confirm = confirm_prompt()

  while True:
    if confirm.upper() == "Y":
      return True
    if confirm.upper() == "N":
      return False
    else:
      print "You must enter y or n"
      confirm = confirm_prompt()


def multisig_withdraw_interactive():
  """Interactive script for withdrawing coins from a multisig address"""
  #dest_addr, amount, redeem_script, in_txid, in_vout, in_script_pub_key, privkeys
  
  approve = False

  while not approve:
    addresses = {}
    print ""
    print "Welcome to the multisig funds withdrawal script!"
    print "We will need several pieces of information to create a withdrawal transaction. See guide for help."
    dest_address = raw_input("destination address: ")
    addresses[dest_address] = 0
    print ""
    source_address = raw_input("source address: ")
    addresses[source_address] = 0
    print ""
    
    print "For the next steps, you need several pieces of information from an input transaction"
    txid = raw_input("input txid: ")
    vout = raw_input("input vout: ")
    script_pub_key = raw_input("input scriptPubKey (hex):")
    input_amount = raw_input("input transaction amount in BTC (ex. 1002.1): ")
    input_amount = Decimal(input_amount)

    print "How many private keys will you be signing with?"
    key_count = int(raw_input("#: "))
    print key_count

    keys = []
    while len(keys) < key_count:
      key = raw_input("key #{0}: ".format(len(keys) + 1))
      keys.append(key)

    print ""
    print "Please enter the decimal amount (in bitcoin) to send to destination"
    print "Example: 2.3 for 2.3 bitcoin."
    print ""
    amount = raw_input("Amount to send to {0}".format(dest_address))
    amount = Decimal(amount)

    print ""
    print "Please enter the amount (in bitcoin) to send as a miner fee."
    print "Example: .0001 for .0001 bitcoin"
    print "All balance not sent to destination or as fee will be returned to source address"
    fee = raw_input("Fee amount: ")
    fee = Decimal(fee)
    print ""

    if fee + amount > input_amount:
      print "Error: fee + destination amount greater than input amount"
      raise Exception("Output values greater than input value")

    change_amount = input_amount - amount - fee
    print "{0} going to change address {1}".format(change_amount, source_address)

    addresses[dest_address] = str(amount)
    addresses[source_address] = str(change_amount)

    print ""
    print "Please provide the redeem script for this multisig address."
    redeem_script = raw_input("Redeem script: ")

    print ""
    print "Is this data correct?"
    print "WARNING: incorrect data may lead to loss of funds"
    print "{0} input value".format(input_amount)
    for address, value in addresses.iteritems():
      print "{0} btc going to address {1}".format(value, address)
    print "fee amount: {0}".format(fee)
    print "input txid: {0}".format(txid)
    print "input vout: {0}".format(vout)
    print "input scriptPubKey (hex): {0}".format(script_pub_key)
    print "private keys: {0}".format(keys)
    print "redeem script: {0}".format(redeem_script)
    print ""
    confirm = yes_no_interactive()
      
    if confirm:
      approve = True
    else:
      print ""
      print "Process aborted. Starting over...."

  print "\nCalculating transaction.....\n"

  signed_tx = multisig_gen_trx(addresses, amount, redeem_script, txid, vout, script_pub_key, keys)

  signed_tx = json.loads(signed_tx)

  print ""
  print "Complete signature?"
  print signed_tx["complete"]
  print ""

  print "Signed transaction (hex):"
  print signed_tx["hex"]


if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument('program', choices=['keygen', 'multisig-deposit', 'multisig-withdraw'])

  parser.add_argument("-d", "--dice", type=int, help="The minimum number of dice rolls to use for entropy when generating private keys (default: 64)", default=64)
  parser.add_argument("-s", "--seed", type=int, help="Minimum number of 8-bit bytes to use for seed entropy when generating private keys (default: 20)", default=20)
  parser.add_argument("-m", type=int, help="Number of signing keys required in an m-of-n multisig address creation (default m-of-n = 1-of-2)", default=1)
  parser.add_argument("-n", type=int, help="Number of total keys required in an m-of-n multisig address creation (default m-of-n = 1-of-2)", default=2)
  args = parser.parse_args()

  if args.program == "keygen":
    wif_interactive(dice_length = args.dice, seed_length = args.seed)

  if args.program == "multisig-deposit":
    get_multisig_interactive(args.m, args.n)

  if args.program == "multisig-withdraw":
    multisig_withdraw_interactive()

