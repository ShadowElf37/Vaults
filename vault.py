from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode
from typing import Union, Iterable
from os.path import exists
import json

class Vault(dict):
    def __repr__(self):
        if 'name' not in self.keys():
            raise ValueError("Please instantiate Vault with newVault()")
        return '<Vault \'%s\': %d data entries>' % (self['name'], len(self['data']))


def newVault(name: str, password: str, bits=2048):
    key = RSA.generate(bits)
    private = key.export_key(format='DER', passphrase=password, pkcs=8)
    public = key.publickey().export_key(format='DER')
    return Vault(name=name, k0=private, k1=public, data=[])

def copy(old_vault: Vault, new_vault: Vault, old_password: str):
    """
    Copies contents of old_vault into new_vault, without replacing new_vault data.
    Useful if updates to Vault or key generation are made, or you want to change your password.
    """
    storeAll(new_vault, readAll(old_vault, old_password))

def sanitizedVault(vault: Vault):
    clean = Vault()
    clean['name'] = vault['name']
    clean['k0'] = b64encode(vault['k0']).decode()
    clean['k1'] = b64encode(vault['k1']).decode()
    clean['data'] = [b64encode(item).decode() for item in vault['data']]
    return clean
def unsanitizedVault(cleanVault: Vault):
    dirty = Vault()
    dirty['name'] = cleanVault['name']
    dirty['k0'] = b64decode(cleanVault['k0'])
    dirty['k1'] = b64decode(cleanVault['k1'])
    dirty['data'] = [b64decode(item) for item in cleanVault['data']]
    return dirty

def dumpVault(vault: Vault):
    clean = sanitizedVault(vault)
    fname = clean['name']+'.vault'

    if exists(fname):
        answer = input('WARNING: a vault named \'%s\' already exists. Overwrite it? (y/n): ' % clean['name'])
        if answer[0].lower() != 'y':
            return

    with open(fname, 'w') as file:
        file.write(json.dumps(clean, indent=4))

def loadVault(fp: str):
    with open(fp, 'r') as file:
        return unsanitizedVault(json.loads(file.read()))

def storeItem(vault: Vault, data: Union[bytes, str]):
    if type(data) is str:
        data = data.encode()
    key = RSA.import_key(vault['k1'])
    cipher = PKCS1_OAEP.new(key)
    vault['data'].append(cipher.encrypt(data))
def storeAll(vault: Vault, data: Iterable[Union[bytes, str]]):
    key = RSA.import_key(vault['k1'])
    cipher = PKCS1_OAEP.new(key)
    for item in data:
        if type(data) is str:
            item = item.encode()
        vault['data'].append(cipher.encrypt(item))
        
def readItem(vault: Vault, password: str, index: int):
    key = RSA.import_key(vault['k0'], password)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(vault['data'][index])
def readAll(vault: Vault, password: str):
    key = RSA.import_key(vault['k0'], password)
    cipher = PKCS1_OAEP.new(key)
    return [cipher.decrypt(item) for item in vault['data']]


def test():
    vault = newVault('test', 'password')  # creates a new vault 'test' with password 'helloworld'
    storeItem(vault, 'hello world!')  # writes 'hello world!!' as a data entry in the vault - no password required, uses public key
    dumpVault(vault)  # dumps the vault to 'test.vault' - base64 encoded json
    print(vault)
    loaded_vault = loadVault('test.vault')  # reads contents of 'test.vault' into a new vault
    print(readAll(loaded_vault, 'password'))  # prints all data entries of the new vault - password required, uses private key to decrypt
