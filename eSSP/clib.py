'''Wrapping the c library to correctly define its functions and easily
access them.
'''
from aenum import Enum

from ctypes import (
    cdll,
    Structure,
    c_ubyte,
    c_uint,
    c_char,
    c_ulong,
    c_ulonglong,
    POINTER,
    c_int,
    c_char_p,
)
import os

import faulthandler

faulthandler.enable()

C_LIBRARY = cdll.LoadLibrary(
    os.path.join(os.path.dirname(__file__), 'libessp.so'),
)


class Ssp6ChannelData(Structure):
    _fields_ = [
        ('security', c_ubyte),
        ('value', c_uint),
        ('cc', c_char * 4),
    ]


class Ssp6SetupRequestData(Structure):
    _fields_ = [
        ('UnitType', c_ubyte),
        ('FirmwareVersion', c_char * 5),
        ('NumberOfChannels', c_uint),
        ('ChannelData', Ssp6ChannelData * 20),
        ('RealValueMultiplier', c_ulong),
        ('ProtocolVersion', c_ubyte),
    ]


class SspPollEvent6(Structure):
    _fields_ = [
        ('event', c_ubyte),
        ('data1', c_ulong),
        ('data2', c_ulong),
        ('cc', c_char * 4),
    ]


class SspPollData6(Structure):
    _fields_ = [
        ('events', SspPollEvent6 * 20),
        ('event_count', c_ubyte),
    ]


class SspResponseEnum(Enum):
    SSP_RESPONSE_OK = 0xF0
    SSP_RESPONSE_UNKNOWN_COMMAND = 0xF2
    SSP_RESPONSE_INCORRECT_PARAMETERS = 0xF3
    SSP_RESPONSE_INVALID_PARAMETER = 0xF4
    SSP_RESPONSE_COMMAND_NOT_PROCESSED = 0xF5
    SSP_RESPONSE_SOFTWARE_ERROR = 0xF6
    SSP_RESPONSE_CHECKSUM_ERROR = 0xF7
    SSP_RESPONSE_FAILURE = 0xF8
    SSP_RESPONSE_HEADER_FAILURE = 0xF9
    SSP_RESPONSE_KEY_NOT_SET = 0xFA
    SSP_RESPONSE_TIMEOUT = 0xFF

    @classmethod
    def from_param(cls, obj):
        return int(obj)


class UpdateDeviceResponseEnum(Enum):
    OK = 0x00
    FILE_NOT_FOUND = 0x01
    FILE_ERROR = 0x02
    INVALID_FILE_TYPE = 0x03
    PORT_ERROR = 0x04
    NO_VALIDATOR = 0x05
    SEND_PROGRAM_CMD_ERROR = 0x06
    TIMEOUT = 0x07
    BAD_CHECKSUM = 0x08
    DEVICE_DID_NOT_ACK = 0x09

    @classmethod
    def from_param(cls, obj):
        return int(obj)


class SspChannelState(Enum):
    DISABLED = 0x00
    ENABLED = 0x01

    @classmethod
    def from_param(cls, obj):
        '''from_param is required for ctypes to pass an enum to a c
        function.
        '''
        return int(obj)


class SspFullKey(Structure):
    _fields_ = [
        ('FixedKey', c_ulonglong),
        ('EncryptKey', c_ulonglong),
    ]


class SspCommand(Structure):
    _fields_ = [
        ('Key', SspFullKey),
        ('BaudRate', c_ulong),
        ('Timeout', c_ulong),
        ('PortNumber', c_ubyte),
        ('SSPAddress', c_ubyte),
        ('RetryLevel', c_ubyte),
        ('EncryptionStatus', c_ubyte),
        ('CommandDataLength', c_ubyte),
        ('CommandData', c_ubyte * 255),
        ('ResponseStatus', c_ubyte),
        ('ResponseDataLength', c_ubyte),
        ('ResponseData', c_ubyte * 255),
        ('IgnoreError', c_ubyte),
    ]



def define_function(name, restype, *argtypes):
    getattr(C_LIBRARY, name).restype = restype
    getattr(C_LIBRARY, name).argtypes = argtypes


CommandPointer = POINTER(SspCommand)
PollDataPointer = POINTER(SspPollData6)
SetupRequestDataPointer = POINTER(Ssp6SetupRequestData)

define_function('close_ssp_port', None)
define_function('ssp6_disable', SspResponseEnum, CommandPointer)
define_function('ssp6_disable_payout', SspResponseEnum, CommandPointer)
define_function('ssp6_empty', SspResponseEnum, CommandPointer, c_char)
define_function('ssp6_enable', SspResponseEnum, CommandPointer)
define_function('ssp6_enable_payout', SspResponseEnum, CommandPointer, c_char)
define_function(
    'ssp6_get_note_amount',
    SspResponseEnum,
    CommandPointer,
    c_int,
    c_char_p,
)
define_function(
    'ssp6_host_protocol',
    SspResponseEnum,
    CommandPointer,
    c_ubyte,
)
define_function(
    'ssp6_payout',
    SspResponseEnum,
    CommandPointer,
    c_int,
    c_char_p,
    c_char,
)
define_function('ssp6_payout_note', SspResponseEnum, CommandPointer)
define_function(
    'ssp6_poll',
    SspResponseEnum,
    CommandPointer,
    PollDataPointer,
)
define_function('ssp6_reject', SspResponseEnum, CommandPointer)
define_function('ssp6_reset', SspResponseEnum, CommandPointer)
define_function('ssp6_run_calibration', SspResponseEnum, CommandPointer)
define_function(
    'ssp6_set_coinmech_inhibits',
    SspResponseEnum,
    CommandPointer,
    c_uint,
    c_char_p,
    SspChannelState,
)
define_function(
    'ssp6_set_inhibits',
    SspResponseEnum,
    CommandPointer,
    c_ubyte,
    c_ubyte,
)
define_function(
    'ssp6_set_route',
    SspResponseEnum,
    CommandPointer,
    c_int,
    c_char_p,
    c_char,
)
define_function(
    'ssp6_setup_encryption',
    SspResponseEnum,
    CommandPointer,
    c_ulonglong,
)
define_function(
    'ssp6_setup_request',
    SspResponseEnum,
    CommandPointer,
    SetupRequestDataPointer,
)
define_function('ssp6_stack_note', SspResponseEnum, CommandPointer)
define_function('ssp6_sync', SspResponseEnum, CommandPointer)
define_function('ssp_init', CommandPointer, c_char_p, c_char_p, c_int)
define_function(
    'update_device',
    UpdateDeviceResponseEnum,
    c_char_p,
    c_char_p,
    c_char_p,
)
