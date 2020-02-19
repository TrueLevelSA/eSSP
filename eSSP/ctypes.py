from ctypes import (
    Structure,
    c_ubyte,
    c_uint,
    c_char,
    c_ulong,
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
