from ctypes import cdll
import os

C_LIBRARY = cdll.LoadLibrary(
    os.path.join(os.path.dirname(__file__), 'libessp.so'),
)

from .eSSP import eSSP
