from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, Salsa20, AES
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
    N_ENCRYPT = 3
    N_KEY_ENCRYPT = 20

    STORE_FIELDS = ('name', 'true_key', 'data')

    def __init__(self, name: str, password: str):
        self.true_key_decrypted = get_random_bytes(32)
        self.true_key = self.true_key_decrypted
        pwd_cipher = AES.new((password.encode() + self.SALT)[:32], mode=AES.MODE_ECB)
        for i in range(self.N_KEY_ENCRYPT):
            self.true_key = pwd_cipher.encrypt(self.true_key)

        self.name = name
        self.data: [dict] = []

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
    def from_file(fp: str, password: str):
        """
        Load vault from file
        """
        with open(fp, 'rb') as file:
            vault_dict = pickle.load(file)
            vault = Vault.__new__(Vault)
            vault.__dict__.update(vault_dict)
            vault.unlock(password)
        return vault

    def unlock(self, password: str):
        pwd = (password.encode() + self.SALT)[:32]
        pwd_cipher = AES.new(pwd, mode=AES.MODE_ECB)
        self.true_key_decrypted = self.true_key
        for i in range(self.N_KEY_ENCRYPT):
            self.true_key_decrypted = pwd_cipher.decrypt(self.true_key_decrypted)
    def lock(self):
        self.true_key_decrypted = None

    def __init_cipher(self, iv: bytes):
        if not self.true_key_decrypted:
            raise ValueError('Vault is locked. Please call vault.unlock()')
        return AES.new(self.true_key_decrypted, mode=AES.MODE_CBC, iv=iv)
    def __encrypt(self, data: bytes, iv: bytes, n_times=N_ENCRYPT):
        data = pad(data, AES.block_size)
        for _ in range(n_times):
            cipher = self.__init_cipher(iv)
            data = cipher.encrypt(data)
        return data
    def __decrypt(self, data: bytes, iv: bytes, n_times=N_ENCRYPT):
        for _ in range(n_times):
            cipher = self.__init_cipher(iv)
            data = cipher.decrypt(data)
        return unpad(data, AES.block_size)

    def __make_entry(self, data: bytes, name: str = 'Unnamed Data'):
        iv = get_random_bytes(16)
        return {'name': name, 'data': self.__encrypt(data, iv), 'iv': iv}

    if USE_CV:
        def disp_image(self, index: int):
            """
            This method displays an image without ever saving it decrypted to a file
            """
            imdata = np.frombuffer(self.read_item(index), dtype=np.uint8)
            img = cv2.imdecode(imdata, cv2.IMREAD_UNCHANGED)
            fname = self.data[index]['name']
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

    def ls(self):
        return f'Vault "{self.name}"\n' + '\n'.join(('\t%d - ' % i) + entry['name'] for i, entry in enumerate(self.data))

    def rename_vault(self, name):
        self.name = name
    def rename_item(self, index, name):
        self.data[index]['name'] = name

    def store_file(self, fp:str):
        """
        Stores a whole file.
        """
        self.store_item(open(fp, 'rb').read(), os.path.split(fp)[-1])

    def export_item_into_file(self, index: int, fp: str):
        """
        Exports an item, DECRYPTED
        """
        with open(fp, 'wb') as f:
            f.write(self.read_item(index))

    def store_item(self, data: Union[bytes, str], name='Unnamed Data'):
        """
        Stores an item in the vault. Doesn't require password! Encrypts immediately.
        """
        print('Encrypting %.1f kB...' % (len(data)/1000))
        if type(data) is str:
            data = data.encode()
        self.data.append(self.__make_entry(data, name))

    def store_all(self, data: Iterable[Union[bytes, str]], names=()):
        """
        Store multiple items at once.
        """
        for i, item in enumerate(data):
            if names:
                self.store_item(item, names[i])
            else:
                self.store_item(item)

    def read_item(self, index: int):
        """
        Reads item from vault and decrypts.
        """
        if len(self.data[index]) > 1024:
            print('Decrypting large item. This may take a while... ', end='')
        entry = self.data[index]
        dec = self.__decrypt(entry['data'], entry['iv'])
        return dec

    def read_all(self):
        """
        Reads everything from vault, decrypted.
        """
        return [self.read_item(i) for i in range(len(self.data))]

    def dump(self, overwrite=False):
        """
        Dump to file
        """
        fname = self.name + '.vault'
        if exists(fname) and not overwrite:
            answer = input('WARNING: a vault named \'%s\' already exists. Overwrite it? (y/n): ' % self.name)
            if answer[0].lower() != 'y':
                return
        with open(fname, 'wb') as file:
            pickle.dump({k:self.__dict__[k] for k in self.STORE_FIELDS}, file)


def test():
    vault = Vault('test', 'password')  # creates a new vault 'test' with password 'password'
    vault.store_item('hello world!')  # writes 'hello world!' as a data entry in the vault - no password required, uses public key
    vault.store_file('sus_image.png')  # writes a whole file into the vault - no maximum size, as it is broken up into blocks
    vault.dump()  # dumps the vault to 'test.vault' using pickle
    print(vault.ls())  # displays a summary of the vault content
    loaded_vault = Vault.from_file('test.vault', 'password')  # reads contents of 'test.vault' into a new vault
    loaded_vault.disp_image(1)  # prints all data entries of the new vault - password required, uses private key to decrypt

if __name__ == "__main__":
    test()