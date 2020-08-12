# !/usr/bin/env python3
import threading
from ctypes import (
    cdll,
    c_ulonglong,
    byref,
)
from time import sleep

from six.moves import queue

from . import C_LIBRARY
from . import actions
from .clib import (
    Ssp6ChannelData,
    Ssp6SetupRequestData,
    SspPollEvent6,
    SspPollData6,
    SspResponseEnum
)
from .constants import Status, FailureStatus
from .polls import handle_event


class eSSP:
    '''Encrypted Smiley Secure Protocol Class'''

    def __init__(self, com_port, ssp_address='0', nv11=False, debug=False):
        self.debug = debug
        self.nv11 = nv11
        self.actions = queue.Queue()
        self.response_data = {}
        self.events = []

        # There can't be 9999 notes in the storage
        self.response_data['getnoteamount_response'] = 9999
        self.sspC = C_LIBRARY.ssp_init(
            com_port.encode(),
            ssp_address.encode(),
            debug,
        )
        if not self.sspC:
            exit(-1)

        self.poll = SspPollData6()
        setup_req = Ssp6SetupRequestData()

        # Check if the validator is present
        if C_LIBRARY.ssp6_sync(self.sspC) != SspResponseEnum.SSP_RESPONSE_OK:
            self.print_debug('No validator found')
            self.close()
            raise Exception('No validator found')
        else:
            self.print_debug('Validator found!')

        # Try to setup encryption
        if C_LIBRARY.ssp6_setup_encryption(
                    self.sspC,
                    c_ulonglong(0x123456701234567),
                ) == SspResponseEnum.SSP_RESPONSE_OK:
            self.print_debug('Encryption setup')
        else:
            self.print_debug('Encryption failed')

        # Checking the version, make sure we are using ssp version 6
        if (C_LIBRARY.ssp6_host_protocol(self.sspC, 0x06)
                != SspResponseEnum.SSP_RESPONSE_OK):
            self.print_debug(
                C_LIBRARY.ssp6_host_protocol(self.sspC, 0x06),
            )
            self.print_debug('Host protocol failed')
            self.close()
            raise Exception('Host protocol failed')

        # Get some information about the validator
        if (C_LIBRARY.ssp6_setup_request(self.sspC, byref(setup_req))
                != SspResponseEnum.SSP_RESPONSE_OK):
            self.print_debug('Setup request failed')
            self.close()
            raise Exception('Setup request failed')

        self.print_debug(
            f'Firmware {setup_req.FirmwareVersion.decode("utf8")}',
        )
        self.print_debug('Channels:')
        for i, channel in enumerate(setup_req.ChannelData):
            self.print_debug(
                f'Channel {i + 1}: {channel.value} {channel.cc.decode()}',
            )

        # Enable the validator
        if (C_LIBRARY.ssp6_enable(self.sspC)
                != SspResponseEnum.SSP_RESPONSE_OK):
            self.print_debug('Enable failed')
            self.close()
            raise Exception('Enable failed')

        if setup_req.UnitType == 0x03:  # magic number
            for channel in enumerate(setup_req.ChannelData):
                C_LIBRARY.ssp6_set_coinmech_inhibits(
                    self.sspC,
                    channel.value,
                    channel.cc,
                    Status.ENABLED,
                )
        else:
            if setup_req.UnitType in {0x06, 0x07}:
                # Enable the payout unit
                if C_LIBRARY.ssp6_enable_payout(
                            self.sspC,
                            setup_req.UnitType,
                        ) != SspResponseEnum.SSP_RESPONSE_OK:
                    self.print_debug('Payout enable failed')

            # Set the inhibits (enable all note acceptance)
            if (C_LIBRARY.ssp6_set_inhibits(self.sspC, 0xFF, 0xFF)
                    != SspResponseEnum.SSP_RESPONSE_OK):
                self.print_debug('Inhibits failed')
                self.close()
                raise Exception('Inhibits failed')

        system_loop_thread = threading.Thread(target=self.system_loop)
        system_loop_thread.setDaemon(True)
        system_loop_thread.start()

    def close(self):
        '''Close the connection'''
        self.reject()
        C_LIBRARY.close_ssp_port()

    def reject(self):
        '''Reject the bill if there is one'''
        if C_LIBRARY.ssp6_reject(self.sspC) != SspResponseEnum.SSP_RESPONSE_OK:
            self.print_debug('Error to reject bill OR nothing to reject')

    def do_actions(self):
        while not self.actions.empty():
            action = self.actions.get()
            self.print_debug(action.debug_message)
            action(self)

    def print_debug(self, text):
        if self.debug:
            print(text)

    def enable_validator(self):
        '''Enable the validator'''
        setup_req = Ssp6SetupRequestData()
        if C_LIBRARY.ssp6_enable(self.sspC) != SspResponseEnum.SSP_RESPONSE_OK:
            self.print_debug('ERROR: Enable failed')
            return
        # SMART Hopper requires different inhibit commands, so use setup
        # request to see if it is an SH
        if (C_LIBRARY.ssp6_setup_request(self.sspC, byref(setup_req))
                != SspResponseEnum.SSP_RESPONSE_OK):
            self.print_debug('Setup request failed')
            return
        if setup_req.UnitType == 0x03:  # Magic number
            # SMART Hopper requires different inhibit commands
            for channel in setup_req.ChannelData:
                C_LIBRARY.ssp6_set_coinmech_inhibits(
                    self.sspC,
                    channel.value,
                    channel.cc,
                    Status.ENABLED,
                )
        else:
            if (C_LIBRARY.ssp6_set_inhibits(self.sspC, 0xFF, 0xFF)
                    != SspResponseEnum.SSP_RESPONSE_OK):  # Magic numbers here
                self.print_debug('Inhibits failed')

    def parse_poll(self):
        '''Parse the poll, for getting events'''
        for event in self.poll.events:
            handle_event(self, event)
        self.events.append((0, 0, Status.NO_EVENT))

    def system_loop(self):
        '''Looping to get the alive signal (mandatory in eSSP6)'''
        while True:
            response = C_LIBRARY.ssp6_poll(
                self.sspC,
                byref(self.poll),
            )
            if response != SspResponseEnum.SSP_RESPONSE_OK:
                if response == SspResponseEnum.SSP_RESPONSE_TIMEOUT:
                    self.print_debug('SSP poll timeout')
                    self.close()
                    exit(0)
                elif response == SspResponseEnum.SSP_RESPONSE_KEY_NOT_SET:
                    # The self has responded with key not set, so we should
                    # try to negotiate one
                    if C_LIBRARY.ssp6_setup_encryption(
                                self.sspC,
                                c_ulonglong(0x123456701234567),
                            ) == SspResponseEnum.SSP_RESPONSE_OK:
                        self.print_debug('Encryption setup')
                    else:
                        self.print_debug('Encryption failed')
                else:
                    # Not theses two, stop the program
                    raise Exception(f'SSP poll error {response}')
            self.parse_poll()
            self.do_actions()
            sleep(0.5)

    def get_last_event(self):
        '''Get the last event and delete it from the event list'''
        event = self.events[len(self.events) - 1]
        self.events.pop(len(self.events) - 1)
        return event

    def set_route_cashbox(self, amount, currency='CHF'):
        '''Will set the route of <amount> in the cashbox
        NV11: Will set the route of <= amount in the cashbox
        '''
        self.actions.put(actions.RouteToCashbox(
            amount=amount * 100,
            currency=currency,
        ))

    def set_route_storage(self, amount, currency='CHF'):
        '''Set the bills <amount> in the storage
        NV11: Set the bills <= amount in the storage
        '''
        self.actions.put(actions.RouteToStorage(
            amount=amount * 100,
            currency=currency,
        ))

    def payout(self, amount, currency='CHF'):
        '''Payout note(s) for completing the amount passed in parameter'''
        self.actions.put(actions.Payout(
            amount=amount * 100,
            currency=currency,
        ))

    def get_note_amount(self, amount, currency='CHF'):
        '''Get the numbers of note of value X in the smart payout device'''
        self.actions.put(actions.GetNoteAmount(
            amount=amount * 100,
            currency=currency,
        ))

    def reset(self):
        self.print_debug('Starting reset')
        C_LIBRARY.ssp6_reset(self.sspC)
        self.print_debug('Reset complete')

    def nv11_payout_next_note(self):
        self.actions.put(actions.PayoutNextNoteNv11())

    def nv11_stack_next_note(self):
        self.actions.put(actions.StackNextNoteNv11())

    def empty_storage(self):
        self.actions.put(actions.EmptyStorage())

    def disable_payout(self):
        self.actions.put(actions.DisablePayout())

    def disable_validator(self):
        self.actions.put(actions.DisableValidator())
