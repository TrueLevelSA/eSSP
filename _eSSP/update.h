#ifndef ESSP_UPDATE_H
#define ESSP_UPDATE_H

#include "inc/ssp_defines.h"

typedef enum
{
    ESSP_UDR_OK = 0x00,
    ESSP_UDR_FILE_NOT_FOUND = 0x01,
    ESSP_UDR_FILE_ERROR = 0x02,
    ESSP_UDR_INVALID_FILE_TYPE = 0x03,
    ESSP_UDR_PORT_ERROR = 0x04,
    ESSP_UDR_NO_VALIDATOR = 0x05,
    ESSP_UDR_SEND_PROGRAM_CMD_ERROR = 0x06,
    ESSP_UDR_TIMEOUT = 0x07,
    ESSP_UDR_BAD_CHECKSUM = 0x08,
    ESSP_UDR_DEVICE_DID_NOT_ACK = 0x09
} ESSP_UPDATE_DEVICE_RESPONSE;

ESSP_UPDATE_DEVICE_RESPONSE update_device(
        const char* const file_name,
        const char* const port_c,
        const char* const addr_c);

#endif
