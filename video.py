from typing import Callable
import subprocess as sp
import sys

def stream_h264_into_buffer(fp: str, buffer_write_function: Callable, chunk_size=10**7):
    command = ['ffmpeg',
               '-i', fp,
               '-c:v', 'libx264',
               '-c:a', 'copy',
               '-f', 'matroska',
               'pipe:1'
               ]

    logf = open('h264_stream_log.log', 'wb+')

    proc = sp.Popen(command, stdin=sp.PIPE, stdout=sp.PIPE, stderr=logf, bufsize=chunk_size)
    print(' [' + ' '.join(command) + '] ', end='')

    bytes_written = 0

    for line in iter(proc.stdout.read, b''):
        bytes_written += buffer_write_function(line)

    return bytes_written


if __name__ == '__main__':
    with open('out.mov', 'wb+') as f:
        stream_h264_into_buffer('nge_op.mkv', f)