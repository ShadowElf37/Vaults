import os
import struct
import io
import ciphers
from typing import BinaryIO
import datetime
import time
try:
    import cv2
    import numpy as np
    import video
    USE_CV = True
except ImportError:
    USE_CV = False

ENCODING = 'utf-8'

class Record:
    """
    [12 bytes] record nonce

    [12 bytes] data nonce
    [64 bytes] name
    [8 bytes] data size
    [8 bytes] timestamp

    total: 12 + 92 bytes per Record
    """

    FMT = '<12s64sQq'
    RECORD_SIZE = struct.calcsize(FMT)
    FULL_SIZE = RECORD_SIZE + 12

    def __init__(self, rec_nonce, nonce, name, data_size, timestamp):
        self.rec_nonce = rec_nonce
        self.nonce = nonce
        self.name = name.strip(b'\x00')
        self.data_size = data_size
        self.timestamp = int(timestamp)
        self.data_ptr = 0

    def __repr__(self):
        return 'Record'+str((self.rec_nonce, self.nonce, self.name, self.data_size, self.timestamp))

    def delete(self):
        self.name = b''
        self.timestamp = int(time.time())

    @property
    def dt(self):
        return datetime.datetime.fromtimestamp(self.timestamp).strftime(r'%Y-%m-%d %H:%M:%S')

    @staticmethod
    def load(buffer: BinaryIO, rec_nonce: bytes, cipher_gen: ciphers.CipherGenerator):
        cipher = cipher_gen.renew(rec_nonce)
        rec = Record(rec_nonce, *struct.unpack(Record.FMT, cipher.decrypt(buffer.read(Record.RECORD_SIZE))))
        rec.data_ptr = buffer.tell()
        return rec
    def dump(self, cipher_gen: ciphers.CipherGenerator) -> bytes:
        cipher = cipher_gen.renew(self.rec_nonce)
        return self.rec_nonce + cipher.encrypt(struct.pack(Record.FMT, self.nonce, self.name, self.data_size, self.timestamp))


class Vault:
    """
    Data:
    [Record] [Data]
    """

    @staticmethod
    def new(password: str, fp: str):
        buffer = open(fp, 'wb+')
        return Vault(password, buffer)

    @staticmethod
    def from_buffer(buffer: BinaryIO, password: str):
        v = Vault(password, buffer)
        v.__load_record_table()
        return v
    @staticmethod
    def from_file(fp: str, password: str):
        return Vault.from_buffer(open(fp, 'rb+'), password)

    def __init__(self, password: str, buffer: BinaryIO = io.BytesIO()):
        if not (buffer.readable() and buffer.writable()):
            raise IOError('Buffer must have read/write perms')

        self.records: [Record] = []
        self.buffer = buffer
        self.__cipher = ciphers.CipherGenerator(password)

    def __enter__(self, *args):
        pass
    def __exit__(self, *args):
        self.buffer.close()
        self.__cipher = None

    def __load_record_table(self):
        self.buffer.seek(0)
        while rec_nonce := self.buffer.read(12):
            rec = Record.load(self.buffer, rec_nonce, self.__cipher)
            self.buffer.seek(rec.data_ptr + rec.data_size)
            self.records.append(rec)

    def __chunk_read_raw(self, rec: Record, chunk_size=1024) -> bytes:
        for i in range(0, rec.data_size, chunk_size):
            self.buffer.seek(rec.data_ptr + i)
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
    def record_size(self):
        """
        Total bytes of records only
        """
        return self.count * Record.FULL_SIZE
    @property
    def count(self):
        """
        Number of entries
        """
        return len(self.records)
    @property
    def buffer_end(self):
        return self.count * Record.FULL_SIZE + self.data_size

    def ls(self):
        """
        Return a nice summary of the vault contents
        """
        return ('Vault with %d entries (%.1f kB):' % (self.count, (self.record_size + self.data_size) / 1000)) + ''.join(
            ['\n%d\t• %s  (%d B) (%s)' % (i, rec.name.decode(ENCODING), rec.data_size, rec.dt) for i, rec in enumerate(self.records)]
        ) + '\n'

    def store_item(self, data: str | bytes, name='Unnamed Data'):
        """
        Main function for writing data, encrypted
        """
        if type(name) is str:
            name = name.encode(ENCODING)
        if type(data) is str:
            data = data.encode(ENCODING)

        rec = Record(os.urandom(12), os.urandom(12), name, len(data), time.time())
        self.buffer.seek(self.buffer_end)
        self.buffer.write(rec.dump(self.__cipher))
        rec.data_ptr = self.buffer.tell()
        self.records.append(rec)

        cipher = self.__cipher.renew(rec.nonce)
        self.buffer.write(cipher.encrypt(data))

    def store_from_buffer(self, buffer: BinaryIO, name='Unnamed Data', chunk_size=10**7):
        """
        Main function for writing data, encrypted
        """
        if type(name) is str:
            name = name.encode(ENCODING)

        record_start = self.buffer_end

        self.buffer.seek(record_start+Record.FULL_SIZE)
        nonce = os.urandom(12)
        cipher = self.__cipher.renew(nonce)
        bytes_written = 0
        while data := buffer.read(chunk_size):
            bytes_written += self.buffer.write(cipher.encrypt(data))

        rec = Record(os.urandom(12), nonce, name, bytes_written, time.time())
        self.buffer.seek(record_start)
        self.buffer.write(rec.dump(self.__cipher))
        rec.data_ptr = record_start+Record.FULL_SIZE
        self.records.append(rec)

    def read_item(self, index: int):
        """
        Main function for reading data, decrypted
        """

        rec = self.records[index]
        self.buffer.seek(rec.data_ptr)
        cipher = self.__cipher.renew(rec.nonce)
        return cipher.decrypt(self.buffer.read(rec.data_size))

    def store_file(self, fp: str):
        """
        Stores a whole file.
        """
        with open(fp, 'rb') as f:
            self.store_from_buffer(f, os.path.split(fp)[-1])


    def read_all(self):
        """
        Reads everything from vault, decrypted.
        """
        return [self.read_item(i) for i in range(self.count)]

    def export_item_to_file(self, index: int, fp: str):
        """
        Exports an item, DECRYPTED
        """
        print('Exporting %.1f MB...' % (self.records[index].data_size/1000000), end=' ')
        with open(fp, 'wb') as f:
            for chunk in self.read_chunks(index, chunk_size=10**7):
                f.write(chunk)
        print('done!')

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

        def store_streamable_video(self, fp: str):
            t = time.time()
            print('Storing video (%.1f MB), this may take a while...' % (os.path.getsize(fp)/1000000), end='')
            name = os.path.split(fp)[-1]
            record_start = self.buffer_end

            nonce = os.urandom(12)
            cipher = self.__cipher.renew(nonce)
            self.buffer.seek(record_start + Record.FULL_SIZE)
            bytes_written = video.stream_h264_into_buffer(fp, lambda data: self.buffer.write(cipher.encrypt(data)))
            print('done in %.1f! (-> %.1f MB)' % (time.time()-t, bytes_written/1000000))

            rec = Record(os.urandom(12), nonce, name.encode(ENCODING), bytes_written, time.time())
            self.buffer.seek(record_start)
            self.buffer.write(rec.dump(self.__cipher))
            rec.data_ptr = record_start + Record.FULL_SIZE
            self.records.append(rec)

        def disp_video(self, index: int):
            """
            Displays a video without saving it to a file
            """


if __name__ == '__main__':
    v = Vault.new('password', 'test.vault')
    v.store_item(b'secret sauce')
    v.store_streamable_video('nge_op.mkv')
    v.export_item_to_file(1, 'nge_op_recovered.mkv')
    print(v.ls())