'''Wrapping the c library to correctly define its functions and easily
access them.
'''

from ctypes import cdll
import os

C_LIBRARY = cdll.LoadLibrary(
    os.path.join(os.path.dirname(__file__), 'libessp.so'),
)
