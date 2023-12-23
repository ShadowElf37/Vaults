import cv2
import numpy as np

def reader(buffer):
    arr = np.frombuffer(buffer, dtype=np.uint16)
    for frame in arr:
        yield frame