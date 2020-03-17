from . import C_LIBRARY
from .clib import SspPollEvent6, SspResponseEnum
from .constants import Status, FailureStatus

events = {}


def register_event(constant):
    def internal(event_function):
        events[constant.value] = event_function
        return event_function
    return internal


def handle_event(essp, event):
    try:
        if event.event != Status.DISABLED:
            essp.print_debug(Status(event.event))
    except ValueError:
        essp.print_debug(f'Unknown status: {event.event}')

    try:
        events[event.event](essp, event.data1, event.data2, event.cc)
    except KeyError:
        # Most events don't require a specialised function.
        pass

    essp.events.append((0, 0, event.event))


@register_event(Status.SSP_POLL_RESET)
def poll_reset(essp, _data1, _data2, _cc):
    if (C_LIBRARY.ssp6_host_protocol(essp.sspC, 0x06)
            != SspResponseEnum.SSP_RESPONSE_OK):  # Magic number
        raise Exception('Host Protocol Failed')
        essp.close()


@register_event(Status.SSP_POLL_READ)
def poll_read(essp, data1, data2, cc):
    if data1 > 0:
        essp.print_debug(f'Note Read {data1} {cc.decode()}')
        essp.events.append(
            (data1, cc.decode(), Status.SSP_POLL_READ),
        )


@register_event(Status.SSP_POLL_CREDIT)
def poll_credit(essp, data1, data2, cc):
    essp.print_debug(f'Credit {data1} {cc.decode()}')
    essp.events.append(
        (data1, cc.decode(), Status.SSP_POLL_CREDIT),
    )


@register_event(Status.SSP_POLL_INCOMPLETE_PAYOUT)
def poll_incomplete_payout(essp, data1, data2, cc):
    essp.print_debug(f'Incomplete payout {data1} of {data2} {cc.decode()}')


@register_event(Status.SSP_POLL_INCOMPLETE_FLOAT)
def poll_incomplete_float(essp, data1, data2, cc):
    essp.print_debug(f'Incomplete float {data1} of {data2} {cc.decode()}')


@register_event(Status.SSP_POLL_FRAUD_ATTEMPT)
def poll_fraud_attempt(essp, data1, data2, cc):
    essp.print_debug(f'Fraud Attempt {data1} {cc.decode()}')
    essp.events.append(
        (data1, cc.decode(), Status.SSP_POLL_FRAUD_ATTEMPT),
    )


@register_event(Status.SSP_POLL_CALIBRATION_FAIL)
def poll_calibration_fail(essp, data1, data2, cc):
    essp.print_debug('Calibration fail:')
    essp.print_debug(FailureStatus(data1))
    if data1 == FailureStatus.COMMAND_RECAL:
        essp.print_debug('Trying to run autocalibration')
        C_LIBRARY.ssp6_run_calibration(essp.sspC)
