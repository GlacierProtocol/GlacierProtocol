#!/usr/bin/env python

################################################################################################
#
# GlacierScript:  Part of the Glacier Protocol (http://glacierprotocol.org)
#
# GlacierScript is designed specifically for use in the context of executing the broader Glacier
# Protocol, a step-by-step procedure for high-security cold storage of Bitcoin.  It is not
# intended to be used as standalone software.
#
# GlacierScript primarily replaces tasks that users would otherwise be doing manually, such as
# typing things on the command line, copying-and-pasting strings, and hand-editing JSON.  It
# mostly consists of print statements, user input, string & JSON manipulation, and command-line
# wrappers around Bitcoin Core and other applications (e.g. those involved in reading and writing
# QR codes.)
#
# GlacierScript avoids cryptographic and other security-sensitive operations as much as possible.
#
# GlacierScript depends on the following command-line applications:
# - Bitcoin Core (http://bitcoincore.org)
# - qrencode (QR code writer: http://packages.ubuntu.com/xenial/qrencode)
# - zbarimg (QR code reader: http://packages.ubuntu.com/xenial/zbar-tools)
# - veracrypt (encryption software: https://www.veracrypt.fr/en/Home.html)
#
################################################################################################

# standard Python libraries
import time
import argparse
import os
import sys
import hashlib
from hashlib import sha256, md5
import random
import subprocess
import json
from decimal import Decimal

# Taken from Gavin Andresen's "bitcointools" python library (exact link in source file)
from base58 import b58encode

SATOSHI_PLACES = Decimal("0.00000001")

VERBOSE_MODE = 0
# if VERBOSE_MODE is 1 will display more verbose output including most bitcoin-cli calls (see help/main-arguments re toggling)

SINGLE_SAFETY_CONFIRM = 1
#if SINGLE_SAFETY_CONFIRM set to 1 will suppress manually entering in "y" repeatedly for safety checklist (replaces with single confirmation)
#repeated prompts like this aren't going to save anyone from catastrophe and make debugging/development laborious on repeated runs - if users need this for the safety items they have bigger problems on their hands

RE_SIGN_MODE = 0
# RE_SIGN_MODE set to 1 to sign a partially-signed transaction (rather than newly created tx) - used in withdraw interactive function. toggled with "sign-transaction" script call

USING_TAILS = 0
# USING_TAILS is set to 1 if using the Tails operating system. used in setup function. toggled via CLI when -t flag supplied

USING_VERACRYPT = 0
# USING_VERACRYPT is set to 1 if using the veracrypt installer in setup function. toggled via CLI arguments (see argument parser section)
# note that installing veracrypt is required only to create volumes, NOT for opening volumes (can just use cryptsetup)

# note: tails/veracrypt global constants are defined below (just above related functions) to make referencing them easier in code audits. not put within related functions (i.e. kept global) in order to print values for CLI help

################################################################################################
#
# Minor helper functions
#
################################################################################################

def hash_sha256(s):
    """A thin wrapper around the hashlib SHA256 library to provide a more functional interface"""
    m = sha256()
    m.update(s)
    return m.hexdigest()


def hash_md5(s):
    """A thin wrapper around the hashlib md5 library to provide a more functional interface"""
    m = md5()
    m.update(s)
    return m.hexdigest()


def satoshi_to_btc(satoshi):
    """
    Converts a value in satoshi to a value in BTC
    outputs => Decimal

    satoshi: <int>
    """
    value = Decimal(satoshi) / Decimal(100000000)
    return value.quantize(SATOSHI_PLACES)


def btc_to_satoshi(btc):
    """
    Converts a value in BTC to satoshi
    outputs => <int>

    btc: <Decimal> or <Float>
    """
    value = btc * 100000000
    return int(value)

def btc_to_mbtc(btc):
    mbtc = Decimal(btc)*1000
    return mbtc.quantize(SATOSHI_PLACES)

################################################################################################
#
# Read & validate random data from the user
#
################################################################################################

def validate_rng_seed(seed, min_length):
    """
    Validates random hexadecimal seed
    returns => <boolean>

    seed: <string> hex string to be validated
    min_length: <int> number of characters required.  > 0
    """

    if len(seed) < min_length:
        print "Error: Computer entropy must be at least {0} characters long".format(min_length)
        return False

    if len(seed) % 2 != 0:
        print "Error: Computer entropy must contain an even number of characters."
        return False

    try:
        int(seed, 16)
    except ValueError:
        print "Error: Illegal character. Computer entropy must be composed of hexadecimal characters only (0-9, a-f)."
        return False

    return True


def read_rng_seed_interactive(min_length):
    """
    Reads random seed (of at least min_length hexadecimal characters) from standard input
    returns => string

    min_length: <int> minimum number of bytes in the seed.
    """

    char_length = min_length * 2

    def ask_for_rng_seed(length):
        print "Enter at least {0} characters of computer entropy. Spaces are OK, and will be ignored:".format(length)

    ask_for_rng_seed(char_length)
    seed = raw_input()
    seed = unchunk(seed)

    while not validate_rng_seed(seed, char_length):
        ask_for_rng_seed(char_length)
        seed = raw_input()
        seed = unchunk(seed)

    return seed


def validate_dice_seed(dice, min_length):
    """
    Validates dice data (i.e. ensures all digits are between 1 and 6).
    returns => <boolean>

    dice: <string> representing list of dice rolls (e.g. "5261435236...")
    """

    if len(dice) < min_length:
        print "Error: You must provide at least {0} dice rolls".format(min_length)
        return False

    for die in dice:
        try:
            i = int(die)
            if i < 1 or i > 6:
                print "Error: Dice rolls must be between 1 and 6."
                return False
        except ValueError:
            print "Error: Dice rolls must be numbers between 1 and 6"
            return False

    return True


def read_dice_seed_interactive(min_length):
    """
    Reads min_length dice rolls from standard input, as a string of consecutive integers
    Returns a string representing the dice rolls
    returns => <string>

    min_length: <int> number of dice rolls required.  > 0.
    """

    def ask_for_dice_seed(x):
        print "Enter {0} dice rolls (example: 62543 16325 21341...) Spaces are OK, and will be ignored:".format(x)

    ask_for_dice_seed(min_length)
    dice = raw_input()
    dice = unchunk(dice)

    while not validate_dice_seed(dice, min_length):
        ask_for_dice_seed(min_length)
        dice = raw_input()
        dice = unchunk(dice)

    return dice


################################################################################################
#
# private key generation
#
################################################################################################

def xor_hex_strings(str1, str2):
    """
    Return xor of two hex strings.
    An XOR of two pieces of data will be as random as the input with the most randomness.
    We can thus combine two entropy sources in this way as a safeguard against one source being
    compromised in some way.
    For details, see http://crypto.stackexchange.com/a/17660

    returns => <string> in hex format
    """
    if len(str1) != len(str2):
        raise Exception("tried to xor strings of unequal length")
    str1_dec = int(str1, 16)
    str2_dec = int(str2, 16)

    xored = str1_dec ^ str2_dec

    return "{:0{}x}".format(xored, max(len(str1), len(str2)))


def hex_private_key_to_WIF_private_key(hex_key):
    """
    Converts a raw 256-bit hex private key to WIF format
    returns => <string> in hex format
    """

    hex_key_with_prefix = wif_prefix + hex_key + "01"

    h1 = hash_sha256(hex_key_with_prefix.decode("hex"))
    h2 = hash_sha256(h1.decode("hex"))
    checksum = h2[0:8]

    wif_key_before_base58Check = hex_key_with_prefix + checksum
    wif_key = b58encode(wif_key_before_base58Check.decode("hex"))

    return wif_key


################################################################################################
#
# Bitcoin helper functions
#
################################################################################################

def ensure_bitcoind_running():
    """
    Start bitcoind (if it's not already running) and ensure it's functioning properly
    """
    devnull = open("/dev/null")

    # start bitcoind.  If another bitcoind process is already running, this will just print an error
    # message (to /dev/null) and exit.
    #
    # -connect=0.0.0.0 because we're doing local operations only (and have no network connection anyway)
    #
    # The only way to make our signrawtransaction compatible with both 0.16 and 0.17 is using this -deprecatedrpc=signrawtransaction..
    # Once Bitcoin Core v0.17 is published on the Ubuntu PPA we should:
    # 1. Convert signrawtransaction to signrawtransactionwithkeys (note, argument order changes)
    # 2. Remove this -deprecatedrpc=signrawtransaction
    # 3. Change getaddressesbyaccount to getaddressesbylabel
    # 4. Remove this -deprecatedrpc=accounts
    subprocess.call(bitcoind + "-daemon -connect=0.0.0.0 -deprecatedrpc=signrawtransaction -deprecatedrpc=accounts",
                    shell=True, stdout=devnull, stderr=devnull)

    # verify bitcoind started up and is functioning correctly
    times = 0
    while times <= 20:
        times += 1
        if subprocess.call(bitcoin_cli + "getnetworkinfo", shell=True, stdout=devnull, stderr=devnull) == 0:
            return
        time.sleep(0.5)

    raise Exception("Timeout while starting bitcoin server")

def require_minimum_bitcoind_version(min_version):
    """
    Fail if the bitcoind version in use is older than required
    <min_version> - required minimum version in format of getnetworkinfo, i.e. 150100 for v0.15.1
    """
    networkinfo_str = subprocess.check_output(bitcoin_cli + "getnetworkinfo", shell=True)
    networkinfo = json.loads(networkinfo_str)

    if int(networkinfo["version"]) < min_version:
        print "ERROR: Your bitcoind version is too old. You have {}, I need {} or newer. Exiting...".format(networkinfo["version"], min_version)
        sys.exit()

def get_address_for_wif_privkey(privkey):
    """A method for retrieving the address associated with a private key from bitcoin core
       <privkey> - a bitcoin private key in WIF format"""

    # Bitcoin Core doesn't have an RPC for "get the addresses associated w/this private key"
    # just "get the addresses associated with this account"
    # where "account" corresponds to an arbitrary tag we can associate with each private key
    # so, we'll generate a unique "account number" to put this private key into.
    #
    # we're running on a fresh bitcoind installation in the Glacier Protocol, so there's no
    # meaningful risk here of colliding with previously-existing account numbers.
    account_number = random.randint(0, 2**128)

    ensure_bitcoind_running()
    subprocess.call(
        bitcoin_cli + "importprivkey {0} {1}".format(privkey, account_number), shell=True)
    addresses = subprocess.check_output(
        bitcoin_cli + "getaddressesbyaccount {0}".format(account_number), shell=True)

    # extract address from JSON output
    addresses_json = json.loads(addresses)
    return addresses_json[0]


def addmultisigaddress(m, addresses_or_pubkeys, address_type='p2sh-segwit'):
    """
    Call `bitcoin-cli addmultisigaddress`
    returns => JSON response from bitcoin-cli

    m: <int> number of multisig keys required for withdrawal
    addresses_or_pubkeys: List<string> either addresses or hex pubkeys for each of the N keys
    """

    require_minimum_bitcoind_version(160000) # addmultisigaddress API changed in v0.16.0
    address_string = json.dumps(addresses_or_pubkeys)
    argstring = "{0} '{1}' '' '{2}'".format(m, address_string, address_type)
    return json.loads(bitcoin_cli_call("addmultisigaddress",argstring))

def get_utxos(tx, address):
    """
    Given a transaction, find all the outputs that were sent to an address
    returns => List<Dictionary> list of UTXOs in bitcoin core format

    tx - <Dictionary> in bitcoind core format
    address - <string>
    """
    utxos = []

    for output in tx["vout"]:
        if "addresses" not in output["scriptPubKey"]:
            # In Bitcoin Core versions older than v0.16, native segwit outputs have no address decoded
            continue
        out_addresses = output["scriptPubKey"]["addresses"]
        amount_btc = output["value"]
        if address in out_addresses:
            utxos.append(output)

    return utxos

def verbose(content):
    # if verbose mode enabled, print content
    if VERBOSE_MODE:
        print content

def bitcoin_cli_call(cmd,args):
    full_cmd = "{0}{1} {2}".format(bitcoin_cli,cmd,args)
    # note glacier has a space after bitcoind call in "bitcoin_cli" variable
    verbose("\nbitcoin cli call:\n {0} \n".format(full_cmd))
    cmd_output = subprocess.check_output(full_cmd, shell=True)
    verbose("\ncli output:\n {0} \n\n".format(cmd_output))
    return cmd_output

def create_unsigned_transaction(source_address, destinations, redeem_script, input_txs):
    """
    Returns a hex string representing an unsigned bitcoin transaction
    returns => <string>

    source_address: <string> input_txs will be filtered for utxos to this source address
    destinations: {address <string>: amount<string>} dictionary mapping destination addresses to amount in BTC
    redeem_script: <string>
    input_txs: List<dict> List of input transactions in dictionary form (bitcoind decoded format)
    """
    ensure_bitcoind_running()

    # prune destination addresses sent 0 btc
    for address, value in destinations.items():
        if value == "0":
            del destinations[address]

    # For each UTXO used as input, we need the txid and vout index to generate a transaction
    inputs = []
    for tx in input_txs:
        utxos = get_utxos(tx, source_address)
        txid = tx["txid"]

        for utxo in utxos:
            inputs.append({
                "txid": txid,
                "vout": int(utxo["n"])
            })

    argstring = "'{0}' '{1}'".format(
        json.dumps(inputs), json.dumps(destinations))

    tx_unsigned_hex = bitcoin_cli_call("createrawtransaction",argstring).strip()

    return tx_unsigned_hex


def sign_transaction(source_address, keys, redeem_script, unsigned_hex, input_txs):
    """
    Creates a signed transaction
    output => dictionary {"hex": transaction <string>, "complete": <boolean>}

    source_address: <string> input_txs will be filtered for utxos to this source address
    keys: List<string> The private keys you wish to sign with
    redeem_script: <string>
    unsigned_hex: <string> The unsigned transaction, in hex format
    input_txs: List<dict> A list of input transactions to use (bitcoind decoded format)
    """

    # For each UTXO used as input, we need the txid, vout index, scriptPubKey, amount, and redeemScript
    # to generate a signature
    inputs = []
    for tx in input_txs:
        utxos = get_utxos(tx, source_address)
        txid = tx["txid"]
        for utxo in utxos:
            inputs.append({
                "txid": txid,
                "vout": int(utxo["n"]),
                "amount": utxo["value"],
                "scriptPubKey": utxo["scriptPubKey"]["hex"],
                "redeemScript": redeem_script
            })

    argstring_2 = "{0} '{1}' '{2}'".format(
        unsigned_hex, json.dumps(inputs), json.dumps(keys))
    signed_hex = bitcoin_cli_call("signrawtransaction",argstring_2).strip()

    signed_tx = json.loads(signed_hex)
    return signed_tx


def get_fee_interactive(source_address, keys, destinations, redeem_script, input_txs):
    """
    Returns a recommended transaction fee, given market fee data provided by the user interactively
    Because fees tend to be a function of transaction size, we build the transaction in order to
    recomend a fee.
    return => <Decimal> fee value

    Parameters:
      source_address: <string> input_txs will be filtered for utxos to this source address
      keys: A list of signing keys
      destinations: {address <string>: amount<string>} dictionary mapping destination addresses to amount in BTC
      redeem_script: String
      input_txs: List<dict> List of input transactions in dictionary form (bitcoind decoded format)
      fee_basis_satoshis_per_byte: <int> optional basis for fee calculation
    """

    MAX_FEE = .005  # in btc.  hardcoded limit to protect against user typos

    ensure_bitcoind_running()

    approve = False
    while not approve:
        print "\nEnter fee rate."
        fee_basis_satoshis_per_byte = int(raw_input("Satoshis per vbyte: "))

        unsigned_tx = create_unsigned_transaction(
            source_address, destinations, redeem_script, input_txs)

        signed_tx = sign_transaction(source_address, keys,
                                     redeem_script, unsigned_tx, input_txs)

        decoded_tx = json.loads(bitcoin_cli_call("decoderawtransaction",signed_tx["hex"]))
        size = decoded_tx["vsize"]

        fee = size * fee_basis_satoshis_per_byte
        fee = satoshi_to_btc(fee)

        if fee > MAX_FEE:
            print "Calculated fee ({}) is too high. Must be under {}".format(fee, MAX_FEE)
        else:
            print "\nBased on the provided rate, the fee will be {0} bitcoin = {1} mBTC.".format(fee,btc_to_mbtc(fee))
            confirm = yes_no_interactive()

            if confirm:
                approve = True
            else:
                print "\nFee calculation aborted. Starting over..."

    return fee


################################################################################################
#
# QR code helper functions
#
################################################################################################

def write_and_verify_qr_code(name, filename, data):
    """
    Write a QR code and then read it back to try and detect any tricksy malware tampering with it.

    name: <string> short description of the data
    filename: <string> filename for storing the QR code. note that ".png" is added in function to make incrementing easier
    data: <string> the data to be encoded
    """

    # note: it would probably be better to write qr codes to RAM disk or secure volume. while shouldn't contain keys, may increase security by decreasing chance of unencrypted transaction history being discovered
    QR_SUBDIR = "qrcodes"
    QR_SUFFIX = ".png"
    script_root = os.path.dirname(os.path.abspath(__file__))
    QR_DIRPATH = script_root + "/" + QR_SUBDIR
    if not os.path.isdir(QR_DIRPATH):
        os.mkdir(QR_DIRPATH)
    QR_PATH = QR_DIRPATH + "/" + filename + QR_SUFFIX
    if os.path.exists(QR_PATH):
        #print "QR exists at: {0}".format(QR_PATH)
        i = 2
        while os.path.exists(QR_DIRPATH + "/" + filename + str(i) + QR_SUFFIX):
            i += 1
        QR_PATH = QR_DIRPATH + "/" + filename + str(i) + QR_SUFFIX

    subprocess.call("qrencode -o {0} {1}".format(QR_PATH, data), shell=True)
    check = subprocess.check_output(
        "zbarimg --set '*.enable=0' --set 'qr.enable=1' --quiet --raw {}".format(QR_PATH), shell=True)

    if check.strip() != data:
        print "********************************************************************"
        print "WARNING: {} QR code could not be verified properly. This could be a sign of a security breach.".format(name)
        print "********************************************************************"

    print "QR code for {0} written to {1}".format(name, QR_PATH)


################################################################################################
#
# User sanity checking
#
################################################################################################

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
            print "You must enter y (for yes) or n (for no)."
            confirm = confirm_prompt()

def safety_checklist():

    checks = [
        "Are you running this on a computer WITHOUT a network connection of any kind?",
        "Have the wireless cards in this computer been physically removed?",
        "Are you running on battery power?",
        "Are you running on an operating system booted from a USB drive?",
        "Is your screen hidden from view of windows, cameras, and other people?",
        "Are smartphones and all other nearby devices turned off and in a Faraday bag?"]

    for check in checks:
        if SINGLE_SAFETY_CONFIRM is 0:
            answer = raw_input(check + " (y/n)?")
            if answer.upper() != "Y":
                print "\n Safety check failed. Exiting."
                sys.exit()
        else:
            print check + "\n"

    if SINGLE_SAFETY_CONFIRM is 1:
        # this could clearly be more efficient/condensed w above block
        answer = raw_input("confirm the above (y/n): ")
        if answer.upper() != "Y":
            print "\n Safety check failed. Exiting."
            sys.exit()


################################################################################################
#
# Main "entropy" function
#
################################################################################################


def unchunk(string):
    """
    Remove spaces in string
    """
    return string.replace(" ", "")


def format_chunks(size, string):
    """
    Splits a string into chunks of [size] characters, for easy human readability
    """
    tail = ""
    remainder = len(string) % size
    arr = [string[size * i: size * i + size] for i in range(len(string) / size)]
    body = " ".join(arr)
    if remainder > 0:
        tail = string[-remainder:]
    return body + " " + tail


def entropy(n, length):
    """
    Generate n random strings for the user from /dev/random
    """
    safety_checklist()

    print "\n\n"
    print "Making {} random data strings....".format(n)
    print "If strings don't appear right away, please continually move your mouse cursor. These movements generate entropy which is used to create random data.\n"

    idx = 0
    while idx < n:
        seed = subprocess.check_output(
            "xxd -l {} -p /dev/random".format(length), shell=True)
        idx += 1
        seed = seed.replace('\n', '')
        print "Computer entropy #{0}: {1}".format(idx, format_chunks(4, seed))


################################################################################################
#
# Main "deposit" function
#
################################################################################################

def deposit_interactive(m, n, dice_seed_length=62, rng_seed_length=20):
    """
    Generate data for a new cold storage address (private keys, address, redemption script)
    m: <int> number of multisig keys required for withdrawal
    n: <int> total number of multisig keys
    dice_seed_length: <int> minimum number of dice rolls required
    rng_seed_length: <int> minimum length of random seed required
    """

    safety_checklist()
    ensure_bitcoind_running()

    print "\n"
    print "Creating {0}-of-{1} cold storage address.\n".format(m, n)

    keys = []

    while len(keys) < n:
        index = len(keys) + 1
        print "\nCreating private key #{}".format(index)

        dice_seed_string = read_dice_seed_interactive(dice_seed_length)
        dice_seed_hash = hash_sha256(dice_seed_string)

        rng_seed_string = read_rng_seed_interactive(rng_seed_length)
        rng_seed_hash = hash_sha256(rng_seed_string)

        # back to hex string
        hex_private_key = xor_hex_strings(dice_seed_hash, rng_seed_hash)
        WIF_private_key = hex_private_key_to_WIF_private_key(hex_private_key)

        keys.append(WIF_private_key)

    print "Private keys created."
    print "Generating {0}-of-{1} cold storage address...\n".format(m, n)

    addresses = [get_address_for_wif_privkey(key) for key in keys]
    results = addmultisigaddress(m, addresses)

    print "Private keys:"
    for idx, key in enumerate(keys):
        print "Key #{0}: {1}".format(idx + 1, key)

    print "\nCold storage address:"
    print "{}".format(results["address"])

    print "\nRedemption script:"
    print "{}".format(results["redeemScript"])
    print ""

    write_and_verify_qr_code("cold storage address", "address", results["address"])
    write_and_verify_qr_code("redemption script", "redemption",
                       results["redeemScript"])


################################################################################################
#
# Main "withdraw" function
#
################################################################################################

def withdraw_interactive():
    """
    Construct and sign a transaction to withdaw funds from cold storage
    All data required for transaction construction is input at the terminal
    """

    safety_checklist()
    ensure_bitcoind_running()

    approve = False

    while not approve:
        addresses = {}

        print "\nYou will need to enter several pieces of information to create a withdrawal transaction."
        print "\n\n*** PLEASE BE SURE TO ENTER THE CORRECT DESTINATION ADDRESS ***\n"

        source_address = raw_input("\nSource cold storage address: ")

        if RE_SIGN_MODE is not 1:
            redeem_script = raw_input("\nRedemption script for source cold storage address: ")
            dest_address = raw_input("\nDestination address: ")
            num_tx = int(raw_input("\nHow many unspent transactions will you be using for this withdrawal? "))
        else:
            # begin main re-sign code block
            print "\nPlease paste the partially-signed raw transaction (hexadecimal format) with unspent outputs at the source address"
            print "OR"
            print "input a filename located in the current directory which contains the raw transaction data"
            print "(If the transaction data is over ~4000 characters long, you _must_ use a file.):"

            part_signed_hex_tx = raw_input()
            if os.path.isfile(part_signed_hex_tx):
                part_signed_hex_tx = open(part_signed_hex_tx).read().strip()

            part_signed_tx = json.loads(bitcoin_cli_call("decoderawtransaction",part_signed_hex_tx))
            redeem_script=part_signed_tx["vin"][0]["txinwitness"][-1]
            num_tx = len(part_signed_tx["vin"])

            # parse change amount & destination address from partly-signed data
            if len(part_signed_tx["vout"]) is 1:
                verbose("only 1 transaction output indicates entire balance being withdrawn (change amount = 0)")
                #thus destination address data in vout[0]
                change_amount = Decimal(0)
                withdrawal_amount = Decimal(part_signed_tx["vout"][0]["value"]).quantize(SATOSHI_PLACES)
                dest_address = part_signed_tx["vout"][0]["scriptPubKey"]["addresses"][0]
            else:
                verbose("multiple outputs indicates change to be delivered back to cold storage address")
                # ascertain where destination and change addresses are in vout array
                cold_storage_vout_index = -1
                destination_vout_index = -1
                i = 0
                for output in part_signed_tx["vout"]:
                    for address in output["scriptPubKey"]["addresses"]:
                        if address == source_address:
                            cold_storage_vout_index = i
                            break
                    i += 1

                if cold_storage_vout_index is -1:
                    print "could not find cold storage source address in partially signed transaction hex (more than 1 output without cold address found in these for change!)! exiting..."
                    sys.exit()
                if cold_storage_vout_index == 0:
                    destination_vout_index = 1
                else:
                    destination_vout_index = 0
                dest_address = part_signed_tx["vout"][destination_vout_index]["scriptPubKey"]["addresses"][0]

                # now parse out amounts knowing array positions of source/destination vouts
                change_amount = Decimal(part_signed_tx["vout"][cold_storage_vout_index]["value"]).quantize(SATOSHI_PLACES)
                withdrawal_amount = Decimal(part_signed_tx["vout"][destination_vout_index]["value"]).quantize(SATOSHI_PLACES)

            print"\nfollowing variables parsed from partially signed hex input:"
            print "\n    cold storage / source_address: {0}".format(source_address)
            print "\n    redemption script: {0}".format(redeem_script)
            print "\n    destination address: {0}".format(dest_address)
            print "\n    number of input transactions: {0}".format(num_tx)
            print "\n    change amount: {0}".format(change_amount)
            print "\n    withdrawal amount: {0}".format(withdrawal_amount)

            print "\n\nplease confirm whether above data is correct before proceeding to input additional data for transaction re-sign"
            confirm = yes_no_interactive()
            if not confirm:
                print "auto parsed data from transaction incorrect so aborting"
                sys.exit()
            # end main re-sign code block

        addresses[source_address] = 0
        addresses[dest_address] = 0

        # input_txs was "txs" (renamed for clarity)
        input_txs = []
        utxos = []
        utxo_sum = Decimal(0).quantize(SATOSHI_PLACES)

        while len(input_txs) < num_tx:
            print "\nPlease paste raw transaction #{} (hexadecimal format) with unspent outputs at the source address".format(len(input_txs) + 1)
            print "OR"
            print "input a filename located in the current directory which contains the raw transaction data"
            print "(If the transaction data is over ~4000 characters long, you _must_ use a file.):"

            hex_tx = raw_input()
            if os.path.isfile(hex_tx):
                hex_tx = open(hex_tx).read().strip()

            tx = json.loads(bitcoin_cli_call("decoderawtransaction",hex_tx))
            input_txs.append(tx)
            utxos += get_utxos(tx, source_address)

        if len(utxos) == 0:
            print "\nTransaction data not found for source address: {}".format(source_address)
            sys.exit()
        else:
            print "\nTransaction data found for source address."

            for utxo in utxos:
                value = Decimal(utxo["value"]).quantize(SATOSHI_PLACES)
                utxo_sum += value

            print "TOTAL unspent amount for this raw transaction: {} BTC".format(utxo_sum)

        print "\nHow many private keys will you be signing this transaction with? "
        key_count = int(raw_input("#: "))

        keys = []
        while len(keys) < key_count:
            key = raw_input("Key #{0}: ".format(len(keys) + 1))
            keys.append(key)

        ###### fees, amount, and change #######

        input_amount = utxo_sum
        # exclude re-sign mode from running fee calculation function again
        if RE_SIGN_MODE is not 1:
            fee = get_fee_interactive(
                source_address, keys, addresses, redeem_script, input_txs)
            # Got this far
            if fee > input_amount:
                print "ERROR: Your fee is greater than the sum of your unspent transactions.  Try using larger unspent transactions. Exiting..."
                sys.exit()

            print "\nPlease enter the decimal amount (in bitcoin) to withdraw to the destination address."
            print "\nExample: For 2.3 bitcoins, enter \"2.3\"."
            print "\nAfter a fee of {0}, you have {1} bitcoins available to withdraw.".format(fee, input_amount - fee)
            print "\n*** Technical note for experienced Bitcoin users:  If the withdrawal amount & fee are cumulatively less than the total amount of the unspent transactions, the remainder will be sent back to the same cold storage address as change. ***\n"
            withdrawal_amount = raw_input(
                "Amount to send to {0} (leave blank to withdraw all funds stored in these unspent transactions): ".format(dest_address))
            if withdrawal_amount == "":
                withdrawal_amount = input_amount - fee
            else:
                withdrawal_amount = Decimal(withdrawal_amount).quantize(SATOSHI_PLACES)

            if fee + withdrawal_amount > input_amount:
                print "Error: fee + withdrawal amount greater than total amount available from unspent transactions"
                raise Exception("Output values greater than input value")

            change_amount = input_amount - withdrawal_amount - fee

            # less than a satoshi due to weird floating point imprecision
            if change_amount < 1e-8:
                change_amount = 0

            if change_amount > 0:
                print "{0} being returned to cold storage address address {1}.".format(change_amount, source_address)
        else:
            fee = input_amount - withdrawal_amount - change_amount

        addresses[dest_address] = str(withdrawal_amount)
        addresses[source_address] = str(change_amount)

        # check data
        print "\nIs this data correct?"
        print "*** WARNING: Incorrect data may lead to loss of funds ***\n"

        print "{0} BTC in unspent supplied transactions".format(input_amount)
        for address, value in addresses.iteritems():
            if address == source_address:
                print "{0} BTC going back to cold storage address {1}".format(value, address)
            else:
                print "{0} BTC going to destination address {1}".format(value, address)
        print "Fee amount: {0} btc ({1} mbtc)".format(fee,btc_to_mbtc(fee))
        print "\nSigning with private keys: "
        for key in keys:
            print "{}".format(key)

        print "\n"
        confirm = yes_no_interactive()

        if confirm:
            approve = True
        else:
            print "\nProcess aborted. Starting over...."

    #### Calculate Transaction ####
    print "\nCalculating transaction...\n"

    if RE_SIGN_MODE is not 1:
        unsigned_tx = create_unsigned_transaction(
            source_address, addresses, redeem_script, input_txs)

        signed_tx = sign_transaction(source_address, keys,
                                     redeem_script, unsigned_tx, input_txs)
    else:
        re_sign_input_txs = []
        txid = tx["txid"]
        for utxo in utxos:
            re_sign_input_txs.append({
                "txid": txid,
                "vout": int(utxo["n"]),
                "amount": utxo["value"],
                "scriptPubKey": utxo["scriptPubKey"]["hex"],
                "redeemScript": redeem_script
            })
        resign_args = "{0} '{1}' '{2}'".format(part_signed_hex_tx, json.dumps(re_sign_input_txs), json.dumps(keys))
        signed_tx = json.loads(bitcoin_cli_call("signrawtransaction",resign_args))

    print "\nSufficient private keys to execute transaction?"
    print signed_tx["complete"]

    print "\nRaw signed transaction (hex):"
    print signed_tx["hex"]

    print "\nTransaction fingerprint (md5):"
    print hash_md5(signed_tx["hex"])

    write_and_verify_qr_code("transaction", "transaction", signed_tx["hex"])

################################################################################################
#
# install/setup & veracrypt functions
#
################################################################################################

DEFAULT_TAILS_DEB_DIR = "/media/amnesia/apps/tails_apps"
DEFAULT_TAILS_BTC_DIR = "/media/amnesia/apps/tails_apps/bitcoin-0.17.0"
DEFAULT_TAILS_VERACRYPT_INSTALLER = "/media/amnesia/apps/tails_apps/veracrypt-1.23-setup/veracrypt-1.23-setup-gui-x64"
# download from https://launchpad.net/veracrypt/trunk/1.23/+download/veracrypt-1.23-setup.tar.bz2

def install_software(deb_dir,btc_dir,veracrypt):
    # note: this is written/tested now only for tails
    verbose("\ninstall function called w following directories/files:")
    verbose("\n  deb package dir: {0}\n  bitcoin dir: {1}\n  veracrypt file: {2}".format(deb_dir,btc_dir,veracrypt))

    # use 1 string for executing multiple sudo commands together (avoids multi prompts on tails)
    cmds_string = ""

    # need to validate paths to deb, btc, and veracrypt dirs/files
    #   consider consolidation of following blocks into new function w multi calls
    if deb_dir is None:
        if os.path.isdir(DEFAULT_TAILS_DEB_DIR):
            print "\nno debian application packages directory supplied but found exiting default application directory at {0} (will use this)".format(DEFAULT_TAILS_DEB_DIR)
            deb_dir = DEFAULT_TAILS_DEB_DIR
        else:
            print "\nno debian application package directory supplied with --appdir flag and no app directory found at default path (must either supply --appdir flag or have apps existing in default path to run setup)"
            sys.exit()
    else:
        if not os.path.isdir(deb_dir):
            print "\ndebian package directory path supplied via command line not found (at {0})- please ensure this exists and retry...exiting".format(deb_dir)
            sys.exit()
        else:
            print "\nusing supplied debian package path at {0}".format(deb_dir)

    if btc_dir is None:
        if os.path.isdir(DEFAULT_TAILS_BTC_DIR):
            print "\nno bitcoin application directory supplied but found exiting default bitcoin application directory at {0} (will use this)".format(DEFAULT_TAILS_BTC_DIR)
            btc_dir = DEFAULT_TAILS_BTC_DIR
        else:
            print "\nno bitcoin application directory path supplied with --btcdir flag, nor folder existing at default bitcoin application path at {0} (one of these required for setup)".format(DEFAULT_TAILS_BTC_DIR)
            sys.exit()
    else:
        if not os.path.isdir(btc_dir):
            print "\nbitcoin application path supplied via command line not found (at {0})- please ensure this exists and retry...exiting".format(btc_dir)
            sys.exit()

    if USING_VERACRYPT is 1:
        # note: sometimes get a stranger error w "xmessage" popup when veracrypt gui installer launches - however does not appear to preclude normally installation
        #   consider recoding for non-gui installer if available?
        valid_veracrypt = 0
        if veracrypt is not None:
            if os.path.isfile(veracrypt):
                valid_veracrypt = 1
        if valid_veracrypt is 0:
            if os.path.isfile(DEFAULT_TAILS_VERACRYPT_INSTALLER):
                veracrypt = DEFAULT_TAILS_VERACRYPT_INSTALLER
            else:
                print "\nveracrypt installer doesn't exist at default location or custom path. please provide valid veracrypt path or place installer at default location ({0})".format(DEFAULT_TAILS_VERACRYPT_INSTALLER)
                sys.exit()

    cmds_string += "dpkg -i {0}/*.deb".format(deb_dir)
    cmds_string += "; install -m 0755 -o root -g root -t /usr/local/bin {0}/bin/*".format(btc_dir)

    print "\nabout to perform the following operations:"
    print "  install debian packages from {0}".format(deb_dir)
    print "  install bitcoin from {0}".format(btc_dir)

    if USING_TAILS is 1:
        print "  manually opening Tails port for bitcoind to locally listen on"
        cmds_string += "; iptables -I OUTPUT -p tcp -d 127.0.0.1 --dport 8332 -m owner --uid-owner amnesia -j ACCEPT"
        # note that without the above code bitcoin-cli commands will not work in tails

    if USING_VERACRYPT is 1:
        print "  running veracrypt gui installer from: {0}".format(veracrypt)
        cmds_string += "; {0}".format(veracrypt)

    # execute commands together to avoid many prompts in tails, after user verification
    print "\n"
    if not yes_no_interactive():
        print "user not verifying setup parameters so aborting..."
        sys.exit()
    verbose("\nsetup is executing multiple sudo commands: {0}".format(cmds_string))
    subprocess.call("sudo -- sh -c '{0}'".format(cmds_string), shell=True)

DEFAULT_VERACRYPT_TAILS_VOL_NAME = "glaciervc"
# DEFAULT_VERACRYPT_TAILS_VOL_NAME defines default mapper name for veracrypt file decryption. used in veracrypt open function
DEFAULT_VERACRYPT_TAILS_VC_FILE_PATH = "/media/amnesia/apps/user_data/glacierVol.vc"
# DEFAULT_VERACRYPT_TAILS_VC_FILE_PATH defines full default path to veracrypt file to decrypt/mount. used in veracrypt open function
VERACRYPT_TAILS_MOUNT_DIR = "/media/amnesia/veracrypt-volumes"
# VERACRYPT_TAILS_MOUNT_DIR defines the directory veracrypt volumes are mounted to when using veracrypt on tails. used in both veracrypt open & close functions

def veracrypt_open_vol(vc_vol_path,vc_vol_name):
    if vc_vol_path is None:
        vc_vol_path = DEFAULT_VERACRYPT_TAILS_VC_FILE_PATH
    if vc_vol_name is None:
        vc_vol_name = DEFAULT_VERACRYPT_TAILS_VOL_NAME
    print "\nwill attempt to mount veracrypt volume at {0} to {1}/{2}".format(vc_vol_path,VERACRYPT_TAILS_MOUNT_DIR,vc_vol_name)
    if not yes_no_interactive():
        print "\ndid not confirm veracrypt file/mount paths so exiting"
        sys.exit()
    if not os.path.exists(vc_vol_path):
        print "\nno file exists at {0}".format(vc_vol_path)
        sys.exit()
    cmds_string = "cryptsetup --veracrypt open --type tcrypt {0} {1}".format(vc_vol_path,vc_vol_name)
    cmds_string +="; mkdir -p {0}/{1}".format(VERACRYPT_TAILS_MOUNT_DIR,vc_vol_name)
    cmds_string +="; mount -o uid=1000,gid=1000 /dev/mapper/{0} {1}/{2}".format(vc_vol_name,VERACRYPT_TAILS_MOUNT_DIR,vc_vol_name)
    try:
        subprocess.call("sudo -- sh -c '{0}'".format(cmds_string), shell=True)
    except:
        print "\nerror while attempting to open/mount veracrypt volume"

def veracrypt_close_vol(vc_vol_name):
    if vc_vol_name is None:
        vc_vol_name = DEFAULT_VERACRYPT_TAILS_VOL_NAME
    # additional verification and error-catching should be written here (e.g. if volume not mounted at given location)
    cmd = "sudo umount {0}/{1}".format(VERACRYPT_TAILS_MOUNT_DIR,vc_vol_name)
    verbose("\nabout to execute following cmd: \n{0}\n".format(cmd))
    try:
        subprocess.call(cmd, shell=True)
    except:
        print "\nerror while attempting to close veracrypt volume"

################################################################################################
#
# main function
#
# Show help, or execute one of the three main routines: entropy, deposit, withdraw
#
################################################################################################

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('program', choices=[
                        'setup', 'entropy', 'create-deposit-data', 'create-withdrawal-data', 'sign-transaction', 'qr-code', 'veracrypt-open', 'veracrypt-close'])
    parser.add_argument("--num-keys", type=int,
                        help="The number of keys to create random entropy for", default=1)
    parser.add_argument("-d", "--dice", type=int,
                        help="The minimum number of dice rolls to use for entropy when generating private keys (default: 62)", default=62)
    parser.add_argument("-r", "--rng", type=int,
                        help="Minimum number of 8-bit bytes to use for computer entropy when generating private keys (default: 20)", default=20)
    parser.add_argument(
        "-m", type=int, help="Number of signing keys required in an m-of-n multisig address creation (default m-of-n = 1-of-2)", default=1)
    parser.add_argument(
        "-n", type=int, help="Number of total keys required in an m-of-n multisig address creation (default m-of-n = 1-of-2)", default=2)
    parser.add_argument('--testnet', type=int, help=argparse.SUPPRESS)
    parser.add_argument("-q", "--qrdata", help="Data to be encoded into qr-code")
    parser.add_argument('-t', action='store_const',
                        default=0,
                        dest='USING_TAILS',
                        const=1,
                        help='indicate using tails operating system - used in setup for deb package loading & configuring bitcoind start (on tails need manual bitcoind port opening for bitcoin-cli calls)')
    parser.add_argument("--appdir",
                        help="for setup function: path to debian application packages to install. default tails location: {0}".format(DEFAULT_TAILS_DEB_DIR))
    parser.add_argument("--btcdir",
                        help="for setup function: path to untarred bitcoin application directory (for local install of bitcoin binaries). default tails location: {0}".format(DEFAULT_TAILS_BTC_DIR))
    parser.add_argument("--veracrypt", action='store_const',
                        default=0,
                        dest='USING_VERACRYPT',
                        const=1,
                        help="for setup function: run veracrypt gui installer if set to 1")
    parser.add_argument("--veracrypt-dir",
                        dest='veracrypt_dir',
                        help="for setup function: path to untarred veracrypt setup file if using veracrypt. default tails location: {0}".format(DEFAULT_TAILS_VERACRYPT_INSTALLER))
    parser.add_argument("--vc-path",
                        dest='vc_vol_path',
                        help="for use with veracrypt-open - path to existing veracrypt volume (to be opened) in non-default location. optional - if not provided default path of {0}".format(DEFAULT_VERACRYPT_TAILS_VC_FILE_PATH))
    parser.add_argument("--vc-name",
                        dest='vc_vol_name',
                        help="for use with veracrypt-open & veracrypt-close - mapper name to give veracrypt volume (will be mounted with this). optional - if not provided default name of {0}".format(DEFAULT_VERACRYPT_TAILS_VOL_NAME))
    parser.add_argument('-v', action='store_const',
                        default=0,
                        dest='VERBOSE_MODE',
                        const=1,
                        help='increase output verbosity including showing bitcoin-cli calls/outputs')

    args = parser.parse_args()

    VERBOSE_MODE = args.VERBOSE_MODE
    USING_TAILS = args.USING_TAILS
    USING_VERACRYPT = args.USING_VERACRYPT

    global bitcoind, bitcoin_cli, wif_prefix
    cli_args = "-testnet -rpcport={} -datadir=bitcoin-test-data ".format(args.testnet) if args.testnet else ""
    wif_prefix = "EF" if args.testnet else "80"
    bitcoind = "bitcoind " + cli_args
    bitcoin_cli = "bitcoin-cli " + cli_args

    if args.program == "setup":
        install_software(args.appdir,args.btcdir,args.veracrypt_dir)

    if args.program == "entropy":
        entropy(args.num_keys, args.rng)

    if args.program == "create-deposit-data":
        deposit_interactive(args.m, args.n, args.dice, args.rng)

    if args.program == "create-withdrawal-data":
        withdraw_interactive()

    if args.program == "sign-transaction":
        # Sign an existing transaction (i.e. add a signature to partially signed tx) to withdaw funds from cold storage
        RE_SIGN_MODE = 1
        withdraw_interactive()

    if args.program == "qr-code":
        write_and_verify_qr_code("qrcode", "qrcode", args.qrdata)

    if args.program == "veracrypt-open":
        veracrypt_open_vol(args.vc_vol_path,args.vc_vol_name)

    if args.program == "veracrypt-close":
        veracrypt_close_vol(args.vc_vol_name)
