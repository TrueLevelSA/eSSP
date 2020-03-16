from ctypes import byref

from . import C_LIBRARY
from .clib import (
    Ssp6SetupRequestData,
    SspResponseEnum,
)
from .constants import Status


class Action:
    def __init__(self, **kwargs):
        self.arguments = kwargs

    def __call__(self, essp):
        self.function(essp, **self.arguments)

    def __str__(self):
        return self.debug_message()

    def function(self, essp, **kwargs):
        raise NotImplementedError

    @classmethod
    def debug_message(cls):
        cls.debug_message


class RouteToCashbox(Action):
    debug_message = 'Route to cashbox'

    def function(self, essp, **kwargs):
        if C_LIBRARY.ssp6_set_route(
                    essp.sspC,
                    kwargs['amount'],
                    kwargs['currency'].encode(),
                    Status.ENABLED.value,
                ) != SspResponseEnum.SSP_RESPONSE_OK:
            essp.print_debug('ERROR: Route to cashbox failed')


class RouteToStorage(Action):
    debug_message = 'Route to storage'

    def function(self, essp, **kwargs):
        if C_LIBRARY.ssp6_set_route(
                    essp.sspC,
                    kwargs['amount'],
                    kwargs['currency'].encode(),
                    Status.DISABLED.value,
                ) != SspResponseEnum.SSP_RESPONSE_OK:
            essp.print_debug('ERROR: Route to storage failed')


class Payout(Action):
    debug_message = 'Payout'

    def function(self, essp, **kwargs):
        if C_LIBRARY.ssp6_payout(
                    essp.sspC,
                    kwargs['amount'],
                    kwargs['currency'].encode(),
                    Status.SSP6_OPTION_BYTE_DO.value,
                ) != SspResponseEnum.SSP_RESPONSE_OK:
            essp.print_debug('ERROR: Payout failed')
            # Checking the error
            response_data = essp.sspC.contents.ResponseData
            if response_data[1] == Status.SMART_PAYOUT_NOT_ENOUGH:
                essp.print_debug(Status.SMART_PAYOUT_NOT_ENOUGH)
            elif response_data[1] == Status.SMART_PAYOUT_EXACT_AMOUNT:
                essp.print_debug(Status.SMART_PAYOUT_EXACT_AMOUNT)
            elif response_data[1] == Status.SMART_PAYOUT_BUSY:
                essp.print_debug(Status.SMART_PAYOUT_BUSY)
            elif response_data[1] == Status.SMART_PAYOUT_DISABLED:
                essp.print_debug(Status.SMART_PAYOUT_DISABLED)


class PayoutNextNoteNv11(Action):
    debug_message = 'Payout next note'

    def function(self, essp, **kwargs):
        essp.print_debug('Payout next note')
        setup_req = Ssp6SetupRequestData()
        if C_LIBRARY.ssp6_setup_request(
                    essp.sspC,
                    byref(setup_req),
                ) != SspResponseEnum.SSP_RESPONSE_OK:
            essp.print_debug('Setup request failed')
        # Maybe the version, or something (taken from the SDK C code)
        if setup_req.UnitType != 0x07:
            essp.print_debug('Payout next note is only valid for NV11')
        if C_LIBRARY.ssp6_payout_note(
                essp.sspC) != SspResponseEnum.SSP_RESPONSE_OK:
            essp.print_debug('Payout next note failed')


class StackNextNoteNv11(Action):
    debug_message = 'Stack next note'

    def function(self, essp, **kwargs):
        setup_req = Ssp6SetupRequestData()
        if C_LIBRARY.ssp6_setup_request(
                    essp.sspC,
                    byref(setup_req),
                ) != SspResponseEnum.SSP_RESPONSE_OK:
            essp.print_debug('Setup request failed')
        # Maybe the version, or something (taken from the SDK C code)
        if setup_req.UnitType != 0x07:
            essp.print_debug('Payout next note is only valid for NV11')
        if (C_LIBRARY.ssp6_stack_note(essp.sspC)
                != SspResponseEnum.SSP_RESPONSE_OK):
            essp.print_debug('Stack next note failed')


class DisableValidator(Action):
    debug_message = 'Disable validator'

    def function(self, essp, **kwargs):
        if (C_LIBRARY.ssp6_disable(essp.sspC)
                != SspResponseEnum.SSP_RESPONSE_OK):
            essp.print_debug('ERROR: Disable failed')


class DisablePayout(Action):
    debug_message = 'Disable payout'

    def function(self, essp, **kwargs):
        if (C_LIBRARY.ssp6_disable_payout(essp.sspC)
                != SspResponseEnum.SSP_RESPONSE_OK):
            essp.print_debug('ERROR: Disable payout failed')


class GetNoteAmount(Action):
    debug_message = 'Get note amount'

    def function(self, essp, **kwargs):
        if C_LIBRARY.ssp6_get_note_amount(
                    essp.sspC,
                    kwargs['amount'],
                    kwargs['currency'].encode(),
                ) != SspResponseEnum.SSP_RESPONSE_OK:
            essp.print_debug('ERROR: Can''t read the note amount')
            # There can't be 9999 notes
            essp.response_data['getnoteamount_response'] = 9999
        else:
            # The number of note
            essp.response_data['getnoteamount_response'] = (
                essp.sspC.contents.ResponseData[1]
            )


class EmptyStorage(Action):
    debug_message = 'Empty storage & cleaning indexes'

    def function(self, essp, **kwargs):
        # Fixme: ssp6_empty takes a char named 'type' that seems to add a command
        # with hex 0x00 when its value is 0x07. The documentation makes no
        # mention of this that can be found. Since this function was called with
        # this mysterious argument missing, it was decided to call it with 0x00
        # and avoid adding a command that doesn't seem to exist.
        if (C_LIBRARY.ssp6_empty(essp.sspC, 0x00)
                != SspResponseEnum.SSP_RESPONSE_OK):
            essp.print_debug('ERROR: Can''t empty the storage')
        else:
            essp.print_debug('Emptying, please wait...')
