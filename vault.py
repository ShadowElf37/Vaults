from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, Salsa20
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from typing import Union, Iterable
from os.path import exists
import os.path
import pickle
import io

try:
    import cv2
    import numpy as np
    USE_CV = True
except ImportError:
    USE_CV = False
    print('Could not find opencv-python. Image and video capability will be limited.')

class Vault:
    SALT = b'\xad]:\xbf\xcd\xfd\x92\xe2\xe0w\x18\xc0\xf0\x98\xff-\x99J}4\\\x13?Dbd\xb8Wh\xe4\x00H'
    # N_ENCRYPTIONS = 1 # more than 1 breaks :(
    N_PRIVKEY_ENCRYPTIONS = 5

    def __init__(self, name: str, password: str, bits=2048):
        password = password[:32]

        key = RSA.generate(bits)

        self.private = key.export_key(format='DER')
        for i in range(self.N_PRIVKEY_ENCRYPTIONS):
            sym = Salsa20.new((password.encode() + self.SALT)[:32], nonce=get_random_bytes(8))
            self.private = sym.nonce + sym.encrypt(self.private)
        self.public = key.publickey().export_key(format='DER')
        self.name = name
        self.bits = bits
        self.data = []
        self.data_names = []

        self.__init_encryptor()

    def __repr__(self):
        return '<Vault %s: %d entries>' % (self.name, len(self.data))

    @staticmethod
    def copy(old_vault, new_vault, old_password: str):
        """
        Copies contents of old_vault into new_vault, without replacing new_vault data.
        Useful if updates to Vault or key generation are made, or you want to change your password.
        """
        new_vault.store_all(old_vault.read_all(old_password))

    @staticmethod
    def from_file(fp: str):
        """
        Load vault from file
        """
        with open(fp, 'rb') as file:
            vault_dict = pickle.load(file)
            vault = Vault.__new__(Vault)
            vault.__dict__.update(vault_dict)
            vault.__init_encryptor()
        return vault

    def __init_encryptor(self):
        self.encoder = PKCS1_OAEP.new(RSA.import_key(self.public))
    def __encrypt_parts(self, data: bytes):
        block_size = self.bits//16
        blocks = []
        for block_i in range(len(data)//block_size+int(bool(len(data)%block_size))):
            block = data[block_i*block_size:(block_i+1)*block_size]
            blocks.append(self.encoder.encrypt(block))
        return blocks
    def __decrypt_parts(self, password: str, data: Iterable[bytes], cipher=None):
        cipher = cipher or self.__make_decrypter(password)
        decrypted = []
        for block in data:
            decrypted.append(cipher.decrypt(block))
        return b''.join(decrypted)

    if USE_CV:
        def disp_image(self, password: str, index: int):
            """
            This method displays an image without ever saving it decrypted to a file
            """
            imdata = np.frombuffer(self.read_item(password, index), dtype=np.uint8)
            img = cv2.imdecode(imdata, cv2.IMREAD_UNCHANGED)
            fname = self.data_names[index]
            cv2.imshow(f'vault_display_{fname}', img)
            cv2.setWindowTitle(f'vault_display_{fname}', fname)
            print('Displaying image. Press any key to exit.')
            cv2.waitKey(0)
            cv2.destroyAllWindows()

        # not functional
        """
        def disp_video(self, password: str, index: int):
            ""
            This method displays a video without ever saving it decrypted to a file
            ""
            video_data = np.frombuffer(self.read_item(password, index), dtype=np.uint8)
            video_stream = cv2.imdecode(video_data, cv2.IMREAD_UNCHANGED)
            fname = self.data_names[index]
            cv2.setWindowTitle(f'vault_display_{fname}', fname)
            print('Displaying image. Press any key to exit.')
            while True:
                for frame in video_stream:
                    cv2.imshow(f'vault_display_{fname}', frame)
                    if cv2.waitKey(1000//60) != -1:
                        cv2.destroyAllWindows()
                        return
        """

    def __make_decrypter(self, password):
        key = self.private
        for _ in range(self.N_PRIVKEY_ENCRYPTIONS):
            sym = Salsa20.new((password.encode() + self.SALT)[:32], nonce=key[:8])
            key = sym.decrypt(key[8:])
        #print(key)
        try:
            return PKCS1_OAEP.new(RSA.import_key(key))
        except ValueError:
            raise ValueError('Wrong password %s' % password)

    def ls(self):
        return f'Vault "{self.name}"\n' + '\n'.join(('\t%d - ' % i) + name for i, name in enumerate(self.data_names))

    def rename_vault(self, name):
        self.name = name
    def rename_item(self, index, name):
        self.data_names[index] = name

    def store_file(self, fp:str):
        """
        Stores a whole file.
        """
        self.store_item(open(fp, 'rb').read(), os.path.split(fp)[-1])

    def export_item_into_file(self, password: str, index: int, fp: str):
        """
        Exports an item, DECRYPTED
        """
        with open(fp, 'wb') as f:
            f.write(self.read_item(password, index))

    def store_item(self, data: Union[bytes, str], name='Unnamed Data'):
        """
        Stores an item in the vault. Doesn't require password! Encrypts immediately.
        """
        print('Encrypting %.1f kB...' % (len(data)/1000))
        if type(data) is str:
            data = data.encode()
        self.data.append(self.__encrypt_parts(data))
        self.data_names.append(name)

    def store_all(self, data: Iterable[Union[bytes, str]], names=()):
        """
        Store multiple items at once.
        """
        for i, item in enumerate(data):
            if names:
                self.store_item(item, names[i])
            else:
                self.store_item(item, 'Unnamed Data')

    def read_item(self, password: str, index: int, cipher=None):
        """
        Reads item from vault and decrypts.
        """
        if len(self.data[index]) > 2:
            print('Decrypting large item. This may take a while... ', end='')
        dec = self.__decrypt_parts(password, self.data[index], cipher=cipher)
        print('done!')
        return dec

    def read_all(self, password: str):
        """
        Reads everything from vault, decrypted.
        """
        cipher = self.__make_decrypter(password)
        return [self.read_item(password, i, cipher=cipher) for i in range(len(self.data))]

    def dump(self):
        """
        Dump to file
        """
        fname = self.name + '.vault'

        if exists(fname):
            answer = input('WARNING: a vault named \'%s\' already exists. Overwrite it? (y/n): ' % self.name)
            if answer[0].lower() != 'y':
                return

        vault_dict = {'name': self.name,
                      'bits': self.bits,
                      'private': self.private,
                      'public': self.public,
                      'data': self.data,
                      'data_names': self.data_names}

        with open(fname, 'wb') as file:
            pickle.dump(vault_dict, file)


def test():
    vault = Vault('test', 'password')  # creates a new vault 'test' with password 'password'
    vault.store_item('hello world!')  # writes 'hello world!' as a data entry in the vault - no password required, uses public key
    #vault.store_file('sus_image.png')  # writes a whole file into the vault - no maximum size, as it is broken up into blocks
    vault.dump()  # dumps the vault to 'test.vault' using pickle
    print(vault.ls())  # displays a summary of the vault content
    loaded_vault = Vault.from_file('test.vault')  # reads contents of 'test.vault' into a new vault
    #loaded_vault.disp_image('password', 1)  # prints all data entries of the new vault - password required, uses private key to decrypt

if __name__ == "__main__":
    test()