import os
import struct
import io
import ciphers
from typing import BinaryIO
try:
    import cv2
    import numpy as np
    USE_CV = True
except ImportError:
    USE_CV = False

ENCODING = 'utf-8'

class Record:
    """
    [64 bytes] name
    [12 bytes] data nonce
    [8 bytes] data size
    [8 bytes] data ptr

    total: 92 bytes per Record
    """

    FMT = '<64s12sQQ'
    SIZE = struct.calcsize(FMT)

    def __init__(self, name, nonce, data_size, data_ptr):
        self.name = name
        self.nonce = nonce
        self.data_size = data_size
        self.data_ptr = data_ptr

    def __repr__(self):
        return str((self.name, self.nonce, self.data_size, self.data_ptr))

    @staticmethod
    def load(buffer: bytes):
        return Record(*struct.unpack(Record.FMT, buffer))
    def dump(self) -> bytes:
        return struct.pack(Record.FMT, self.name, self.nonce, self.data_size, self.data_ptr)


class Vault:
    MAX_ENTRIES = 128

    @staticmethod
    def new(password: str, buffer: BinaryIO = io.BytesIO()):
        v = Vault(password, buffer, Vault.MAX_ENTRIES)
        buffer.write(v.__record_nonce)
        buffer.write(bytes(Vault.MAX_ENTRIES*Record.SIZE))
        return v

    @staticmethod
    def from_file(buffer: BinaryIO, password: str):
        v = Vault(password, buffer, Vault.MAX_ENTRIES)
        v.__load_record_table()
        return v

    def __init__(self, password: str, buffer: BinaryIO, max_entries):
        if not (buffer.readable() and buffer.writable()):
            raise IOError('Buffer must have read/write perms')

        self.__record_nonce = os.urandom(12)
        self.records: [Record] = []
        self.max_entries = Vault.MAX_ENTRIES
        self.__data_start = self.max_entries * Record.SIZE + 12
        self.buffer = buffer
        self.__cipher = ciphers.CipherGenerator(password)

    def __enter__(self, *args):
        pass
    def __exit__(self, *args):
        self.buffer.close()

    def __load_record_table(self):
        self.buffer.seek(0)
        self.__record_nonce = self.buffer.read(12)
        cipher = self.__cipher.renew(self.__record_nonce)
        while True:
            data = self.buffer.read(Record.SIZE)
            data = cipher.decrypt(data)
            if not any(data):
                break
            self.records.append(Record.load(data))
    def __dump_record_table(self):
        cipher = self.__cipher.renew(self.__record_nonce)
        self.buffer.seek(12)
        zeros = bytes(Record.SIZE)
        for i in range(self.max_entries):
            if i < self.count:
                self.buffer.write(cipher.encrypt(self.records[i].dump()))
            else:
                self.buffer.write(cipher.encrypt(zeros))

    def __write_raw(self, data: bytes):
        self.buffer.seek(self.__data_start + self.data_size)
        self.buffer.write(data)
    def __chunk_read_raw(self, rec: Record, chunk_size=1024) -> bytes:
        for i in range(0, rec.data_size, chunk_size):
            self.buffer.seek(self.__data_start + rec.data_ptr + i)
            yield self.buffer.read(min(chunk_size, rec.data_size - i))
    def read_chunks(self, index: int, chunk_size=1024) -> bytes:
        """
        Generator that returns chunks of data from a file index
        """
        rec = self.records[index]
        cipher = self.__cipher.renew(rec.nonce)
        for chunk in self.__chunk_read_raw(rec, chunk_size):
            yield cipher.decrypt(chunk)

    @property
    def data_size(self):
        """
        Total bytes of data only
        """
        return sum(rec.data_size for rec in self.records)
    @property
    def count(self):
        """
        Number of entries
        """
        return len(self.records)

    def ls(self):
        """
        Return a nice summary of the vault contents
        """
        return ('Vault with %d entries (%.1f kB):' % (self.count, (self.__data_start + self.data_size) / 1000)) + ''.join(
            ['\n%d\t• %s  (%d B)' % (i, rec.name.decode(ENCODING), rec.data_size) for i, rec in enumerate(self.records)]
        ) + '\n'

    def store_item(self, data: str | bytes, name='Unnamed Data'):
        """
        Main function for writing data, encrypted
        """
        if type(name) is str:
            name = name.encode(ENCODING)
        if type(data) is str:
            data = data.encode(ENCODING)

        rec = Record(name, os.urandom(12), len(data), self.data_size)
        cipher = self.__cipher.renew(rec.nonce)
        self.__write_raw(cipher.encrypt(data))

        self.records.append(rec)
        self.__dump_record_table()

    def store_file(self, fp:str):
        """
        Stores a whole file.
        """
        self.store_item(open(fp, 'rb').read(), os.path.split(fp)[-1])

    def read_item(self, index: int):
        """
        Main function for reading data, decrypted
        """

        rec = self.records[index]
        self.buffer.seek(self.__data_start + rec.data_ptr)
        cipher = self.__cipher.renew(rec.nonce)
        return cipher.decrypt(self.buffer.read(rec.data_size))

    def read_all(self):
        """
        Reads everything from vault, decrypted.
        """
        return [self.read_item(i) for i in range(self.count)]

    def write_item_to_file(self, index: int, fp: str):
        """
        Exports an item, DECRYPTED
        """
        with open(fp, 'wb') as f:
            f.write(self.read_item(index))

    def close(self):
        self.buffer.close()

    if USE_CV:
        def disp_image(self, index: int):
            """
            Displays an image without saving it to a file
            """
            imdata = np.frombuffer(self.read_item(index), dtype=np.uint8)
            img = cv2.imdecode(imdata, cv2.IMREAD_UNCHANGED)
            fname = self.records[index].name.decode(ENCODING)
            cv2.imshow(f'vault_display_{fname}', img)
            cv2.setWindowTitle(f'vault_display_{fname}', fname)
            print('Displaying image. Press any key to exit.')
            cv2.waitKey(0)
            cv2.destroyAllWindows()

        def disp_video(self, index: int):
            """
            Displays a video without saving it to a file
            """


if __name__ == '__main__':
    file = open('test.vault2', 'rb+')

    v = Vault.new('password', file)
    v.store_item(b'secret sauce')
    v.store_file('sus_image.png')
    print(v.ls())
    v.close()
    v = Vault.from_file(open('test.vault2', 'rb+'), 'password')
    v.disp_image(1)
    v.close()