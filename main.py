#! /usr/bin/env python

import binascii
import argparse
import secrets
import _pysha3
import base58
import socket
import hashlib
import bip32
import json
import rlp
import os
from ethereum.transactions import Transaction
# pip install 'rlp==0.6.0'

from collections import namedtuple
from bytes import bytes2int, int2bytes

DEBUG = True

ExtPrivateKey = namedtuple("ExtPrivateKey", "private_key chain_code")

IPC_ADDRESS = os.path.expanduser("~") + "/.ethereum/geth.ipc"
KEY_STORE_FILE = "keystore.txt"
ACCOUNT_STORE_FILE = "accounts.txt"

CHILD_KEY_PATH = "m/44/60/0/0"  # BIP44 standard for Ethereum HD keys derivation

ESTIMATE_GAS = False  # should the script get estimated
DEFAULT_GAS = 2100

LOCALE = {
    "error_eth_estimateGas": "The program could not get estimated gas value from Ethereum node IPC server.",
    "error_eth_getTransactionCount": "The program could not retrieve nonce from Ethereum node IPC server.",
    "error_eth_sendRawTransaction": "Unable to broadcast raw transaction onto Ethereum network.",
    "error_net_version": "The program could not determine net id from Ethereum node IPC server."
}

class EthereumNode():
    """

    """
    response_bufsize = 1024

    def __init__(self, address: str, sock: socket.socket=socket.AF_UNIX):
        """
        Create interface for interaction with node
        :param address: full path to
        :param sock: socket type
        """
        self.socket = socket.socket(sock)
        self.node_address = address
        self.transaction_count = 0

        self.socket.connect(self.node_address)

    def send_transaction(self, method: str, params: list, fail_on_error: bool) -> bool:
        """
        Connect to Ethereum node ipc socket, send transaction and return the response.

        :param method: Ethereum json-rpc / ipc method name, in format methodProvider_method, e.g. eth_getBalance
                       See all methods at https://github.com/ethereum/wiki/wiki/JSON-RPC
        :param params: Method parameters
        :param fail_on_error: if True, *RuntimeError* is raised if request to Ethereum IPC server returns an error
                       otherwise, *False* is returned. Either way error message is stored to *self.response_msg*
        :return: response message received from Ethereum node.
        """
        transaction = self._build_transaction(method, params)
        error_msg = LOCALE["error_" + method]

        sock = self.socket

        byte_transaction = bytes(transaction.encode("utf-8"))
        sock.send(byte_transaction)

        msg = sock.recv(self.response_bufsize)
        response = json.loads(msg)
        self.response = response

        if "result" in response:
            self.response_msg = response["result"]
            return True
        elif "error" in response:
            self.response_msg = response["error"]
            if fail_on_error:
                raise RuntimeError(error_msg + "IPC server returned the following error message: {}".format(node.response_msg))
            return False
        else:
            self.response = None
            self.response_msg = None
            raise ConnectionError("Ethereum node IPC server returned an unexpected response")

    def _build_transaction(self, method: str, params: list) -> str:
        """
        Build a json stransaction string
        :param method: Ethereum json-rpc / ipc method name, in format methodProvider_method, e.g. eth_getBalance
                       See all methods at https://github.com/ethereum/wiki/wiki/JSON-RPC
        :param params: Method parameters
        :return: Json-encoded request string
        """
        self.transaction_count += 1

        request = {"method": method, "params": params, "id": self.transaction_count}
        tr = json.dumps(request)

        return tr

    def __repr__(self):
        return "Ethereum node ipc connections at {}".format(self.node_address)


def derive_hd_key(master_key: ExtPrivateKey, path: str):
    """Derive a hierarchically-deterministic wallet key tree from an extended master private key"""

    path = path.strip().split('/')
    if path[0] != 'm' or not 2 < len(path) < 10:
        raise ValueError("Invalid HD key derivation path")
    for level in path[1:]:
        if not level.isdigit():
            # check if number is in format [digits]h, where h stands for +2**31
            if not level[-1:].lower() == "h" and level[:-1].isdigit():
                raise ValueError("Invalid HD key derivation path")

    levels = [int(level) for level in path[1:]]
    key = master_key

    for level in levels:
        print(key, level)
        key = bip32.private_to_private(*key, i=level)

    return key


def get_eth_address(public_key: tuple) -> str:
    """Given Ethereum account public key produce an 20-byte account number"""
    return '0x' + _pysha3.keccak_256(bip32.ser_coord_point(public_key)).digest()[-20:].hex()


def gen_eth_accounts(master_key,  path: str, num_accounts: int=1) -> [tuple, str]:
    """
    Generate child private-public key pairs from the given parent private key
    :param master_key:
    :param path: String representing BIP32 HD key derivation path
    :param num_accounts: Number of accounts to be generated
    :return:
    """

    chain_key = derive_hd_key(master_key, path)
    accounts = {}

    for i in range(num_accounts):
        private_key = ExtPrivateKey(*bip32.private_to_private(*chain_key, i))
        public_key = bip32.get_point_coord(private_key.private_key)
        accounts[i] = private_key, public_key

    return accounts


def key_to_base58(key: bytes):
    """Take serialized extended key as bytes sequence.
    Return base58 key representation according to bip32"""
    checksum = hashlib.sha256(hashlib.sha256(key).digest()).digest()  # USE OLD SHA256!!!
    return base58.b58encode(key + checksum[:4])


parser = argparse.ArgumentParser(description='Script for blockchain transactions, supports 3 modes:\nMode 1 (default) -'
                                             ' create a new Extended private key, according to BIP32 specification, and'
                                             ' save it to a keystore file.\nInvocation: *no arguments*\n\n'
                                             'Mode 2 - from given Extended private key'
                                             ' generate child public keys and derive Etherium wallet addresses from it.'
                                             '\nInvocation: -private_key [key], where key is 128-char hex string\n\n'
                                             '\nMode 3 - generates Ether transfer\ntransaction and'
                                             ' broadcasts it to blockchain. Default blockchain is Ropsten testnet'
                                             '(net_id 3).\nTo change destination blockchain provide --net_id argument'
                                             ' with desired network id.'
                                             '\nInvocation:\n'
                                             '        -private_key [key], [key] is 64-char hex string\n'
                                             '        -sender [address]\n'
                                             '        -receiver [address]\n'
                                             '        -value [int]'
                                             '',
                                 formatter_class=argparse.RawTextHelpFormatter)

parser.add_argument('-private_key', help="ECDSA private key, either 128 (private key + chain code)\nor 64 char hex string"
                                         " for hardened and non-hardened key respectively.")
parser.add_argument('-sender', help="Standard form Ethereum address in hex format, prefixed with 0x")
parser.add_argument('-receiver', help="Same format as sender")
parser.add_argument('-value', help="Amount of Eth to send in wei (1 ETh = 1e18 wei)")
parser.add_argument('--net_id', default=3, type=int, help="Ethereum network id. 1 -- mainnet,"
                                                          "3 -- ropsten testnet, etc.")
parser.add_argument('--console_output', action="store_const", const=True,
                    help="If provided, the script will write output into console "
                    "alongside writing it into file")
args = parser.parse_args()

if __name__ == "__main__":

    mode = None

    if args.private_key is None:
        mode = "gen_private_key"
    elif args.private_key is not None:
        if args.sender is not None and args.receiver is not None and args.value is not None:
            mode = "send_ether"
        elif args.sender is None and args.receiver is None and args.value is None:
            mode = "gen_addresses"

    console_output = args.console_output

    if DEBUG: print(mode)

    if mode == "gen_private_key":
        seed = secrets.token_bytes(64)

        master_key = ExtPrivateKey(*bip32.master_key(seed))
        private_key = int2bytes(master_key.private_key).hex(), master_key.chain_code.hex()

        if console_output:
            print(private_key[0], ",", private_key[1], sep='')

        # append new private key to key storage file to prevent loss of previous private keys
        with open(KEY_STORE_FILE, 'a') as f:
            f.write(json.dumps({"private_key": private_key}) + "\n")

    elif mode == "gen_addresses":
        private_key = bytes2int(bytes.fromhex(args.private_key[:64]))
        chain_code = bytes.fromhex(args.private_key[64:])
        master_key = ExtPrivateKey(private_key, chain_code)
        key_pairs = gen_eth_accounts(master_key, CHILD_KEY_PATH, 2)

        with open(ACCOUNT_STORE_FILE, 'w') as f:
            accounts_dict = {get_eth_address(key_pair[1]):
                             dict(private_key=(bip32.int2bytes(key_pair[0][0]).hex(), key_pair[0][1].hex()),
                                  public_key=bip32.ser_coord_point(key_pair[1]).hex())
                             for key_pair in key_pairs.values()}
            f.write(json.dumps(accounts_dict))

    elif mode == "send_ether":
        ipc = socket.socket(socket.AF_UNIX)
        ipc.connect(IPC_ADDRESS)

        sender = args.sender
        to_address = args.receiver
        value = args.value
        data = ""

        private_key = args.private_key

        node = EthereumNode(IPC_ADDRESS, socket.AF_UNIX)

        # get sender account nonce
        node.send_transaction(method="eth_getTransactionCount", params=[sender, "latest"], fail_on_error=True)
        nonce = int(node.response_msg, base=16)

        # determine gas quantity
        if ESTIMATE_GAS:
            node.send_transaction(method="eth_estimateGas", params=[{"sender": sender}], fail_on_error=True)
            gas = int(node.response_msg, base=16)
        else:
            gas = DEFAULT_GAS

        # get gas price
        node.send_transaction(method="eth_gasPrice", params=[], fail_on_error=True)
        gas_price = int(node.response_msg, base=16)

        node.send_transaction(method="net_version", params=[], fail_on_error=True)
        net_id = int(node.response_msg)

        tx = Transaction(nonce, gas_price, gas, to_address, value, data)
        tx.sign(int2bytes(private_key[0]), network_id=net_id)

        node.send_transaction(method="eth_sendRawTransaction", params=['0x' + rlp.encode(tx).hex()], fail_on_error=True)

    else:
        raise SystemExit("Invalid arguments supplied. Exiting script")