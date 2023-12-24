from typing import Callable
import subprocess as sp

def stream_video_into_buffer(fp: str, buffer_write_function: Callable,
                             codec='libx265', preset='slow', crf='21',
                             chunk_size=10**7,
                             *ffmpeg_flags):
    command = ['ffmpeg',
               '-i', fp,
               '-c:v', codec,
               '-c:a', 'copy',
               '-preset', preset,
               '-crf', str(crf),
               '-f', 'matroska',
               *ffmpeg_flags,
               'pipe:1'
               ]

    logf = open('video_write.log', 'wb+')
    bytes_written = 0

    proc = sp.Popen(command, stdin=sp.PIPE, stdout=sp.PIPE, stderr=logf, bufsize=chunk_size)
    print('cmd:', ' '.join(command))

    for chunk in iter(lambda: proc.stdout.read(chunk_size), b''):
        bytes_written += buffer_write_function(chunk)

    return bytes_written


def play_buffer(buffer_read_function: Callable):
    command = ['ffplay',
               '-i', '-',
               '-top', '30',
               '-left', '30'
               ]

    logf = open('video_play.log', 'wb+')
    proc = sp.Popen(command, stdin=sp.PIPE, stdout=sp.PIPE, stderr=logf)
    print('cmd:', ' '.join(command))

    for chunk in iter(buffer_read_function, b''):
        if (errcode := proc.poll()) is not None:
            return errcode
        try:
            proc.stdin.write(chunk)
        except BrokenPipeError:
            return -1



if __name__ == '__main__':
    with open('out.mov', 'wb+') as f:
        stream_video_into_buffer('nge_op.mkv', f.write)

    with open('out.mov', 'rb', buffering=10**6) as f:
        play_buffer(lambda: f.read(10**6))
