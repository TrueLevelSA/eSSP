#include "update.h"
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <stdlib.h>
#include "ssp_helpers.h"
#include "lib/serialfunc.h"
#include "lib/ITLSSPProc.h"

#ifdef WIN32
#include "port_win32.h"
#include "port_win32_ssp.h"
#else
#include "inc/SSPComs.h"
#include "port_linux.h"
#endif

#define ACK 0x32
#define HEADER_SIZE 128
#define RAM_BLOCK_SIZE 128
#define SECTIONS_SIZE 128

#define SSP_CMD_PROGRAM_DEVICE 0x0B
#define SSP_CMD_RAM_FILE 0x03

/*
 * Source: http://marrginal.ru/files/cashmachine/itl/GA973%20SSP%20Implementation%20Guide%20v2.2.pdf
 * From page 123 to 131.
 */

ESSP_UPDATE_DEVICE_RESPONSE _compare_byte_in_buffer(
        const unsigned char expected_byte,
        const SSP_PORT port,
        const unsigned long timeout,
        int* const result)
{
    unsigned char buffer_byte;
    clock_t start = GetClockMs();

    while(!BytesInBuffer(port))
    {
        usleep(1000);
        if (GetClockMs() - start > timeout)
            return ESSP_UDR_TIMEOUT;
    }

    ReadData(port, &buffer_byte, 1);
    *result = expected_byte == buffer_byte;
    return ESSP_UDR_OK;
}

ESSP_UPDATE_DEVICE_RESPONSE _compare_checksum(
    const unsigned char checksum,
    const SSP_PORT port)
{
    int ok;

    ESSP_UPDATE_DEVICE_RESPONSE response = _compare_byte_in_buffer(
        checksum,
        port,
        1000,
        &ok);
    if (response != ESSP_UDR_OK)
        return response;
    if (!ok)
        return ESSP_UDR_BAD_CHECKSUM;
    return ESSP_UDR_OK;
}

ESSP_UPDATE_DEVICE_RESPONSE _send_header_via_command(
        SSP_COMMAND* const sspC,
        const unsigned char* const data,
        const SSP_PORT port)
{
    memcpy(sspC->CommandData, data, HEADER_SIZE);
    sspC->CommandDataLength = HEADER_SIZE;
    if(_ssp_return_values(sspC) != SSP_RESPONSE_OK)
        return ESSP_UDR_INVALID_FILE_TYPE;
    return ESSP_UDR_OK;
}

void _send_header_directly(
        const unsigned char* const data,
        const SSP_PORT port)
{
    WriteData(data, HEADER_SIZE, port);
}

ESSP_UPDATE_DEVICE_RESPONSE _send_ram_file(
        SSP_COMMAND* const sspC,
        const unsigned char* const data,
        const unsigned long data_length,
        const SSP_PORT port,
        const unsigned long baud,
        int* const ram_file_size,
        unsigned short int* const block_size)
{

    sspC->CommandDataLength = 2;
    sspC->CommandData[0] = SSP_CMD_PROGRAM_DEVICE;
    sspC->CommandData[1] = SSP_CMD_RAM_FILE;

    if (_ssp_return_values(sspC) != SSP_RESPONSE_OK)
        return ESSP_UDR_SEND_PROGRAM_CMD_ERROR;

    *block_size =
        sspC->ResponseData[1]
        | (unsigned short int)sspC->ResponseData[2] << 8;

    _send_header_via_command(sspC, data, port);
    SetBaud(port, baud);
    *ram_file_size =
        data[10]
        | (int)data[9] << 8
        | (int)data[8] << 16
        | (int)data[7] << 24;

    const int blocks_to_send = *ram_file_size / RAM_BLOCK_SIZE;

    unsigned char checksum = 0;
    for (int i = 0; i < blocks_to_send; i++)
    {
        WriteData(
            data + HEADER_SIZE + i * RAM_BLOCK_SIZE,
            RAM_BLOCK_SIZE,
            port);
        for (int j = 0; j < RAM_BLOCK_SIZE; j++)
            checksum ^= data[HEADER_SIZE + i * RAM_BLOCK_SIZE + j];
    }

    const int remaining_bytes = *ram_file_size % RAM_BLOCK_SIZE;
    if (remaining_bytes > 0)
    {
        WriteData(
            data + HEADER_SIZE + *ram_file_size - remaining_bytes,
            remaining_bytes,
            port);
        for (int j = 0; j < remaining_bytes; j++)
            checksum ^= data[HEADER_SIZE + *ram_file_size - remaining_bytes + j];
    }

    ESSP_UPDATE_DEVICE_RESPONSE response = _compare_checksum(checksum, port);
    if (response != ESSP_UDR_OK)
        return response;

    return ESSP_UDR_OK;
}

ESSP_UPDATE_DEVICE_RESPONSE _send_main_file(
        const unsigned char* const data,
        const unsigned long data_length,
        const char* const port_c,
        SSP_PORT port,
        const unsigned long baud,
        const int ram_file_size,
        const unsigned short int block_size)
{
    ESSP_UPDATE_DEVICE_RESPONSE response;
    unsigned char checksum;
    int ok;

    close_ssp_port();
    sleep(3);
    if (!open_ssp_port(port_c))
        return ESSP_UDR_PORT_ERROR;
    port = get_open_port();
    SetBaud(port, baud);

    WriteData(data + 6, 1, port);
    response = _compare_byte_in_buffer(ACK, port, 1000, &ok);
    if (response != ESSP_UDR_OK)
        return response;
    if (!ok)
        return ESSP_UDR_DEVICE_DID_NOT_ACK;

    _send_header_directly(data, port);
    response = _compare_byte_in_buffer(ACK, port, 1000, &ok);
    if (response != ESSP_UDR_OK)
        return response;
    if (!ok)
        return ESSP_UDR_DEVICE_DID_NOT_ACK;

    const int start_position = HEADER_SIZE + ram_file_size;
    const int main_file_size = data_length - start_position;
    const int blocks_to_send = main_file_size / block_size;
    const int sections_to_send = block_size / SECTIONS_SIZE;

    for (int b = 0; b < blocks_to_send; b++)
    {
        checksum = 0;
        int position = start_position + block_size * b;
        WriteData(
            data + position,
            block_size,
            port);
        for (int i = 0; i < block_size; i++)
            checksum ^= data[position + i];

        WriteData(&checksum, 1, port);
        response = _compare_checksum(checksum, port);
        if (response != ESSP_UDR_OK)
            return response;
    }

    const int remaining_bytes = main_file_size % block_size;
    if (remaining_bytes > 0)
    {
        checksum = 0;
        for (int s = 0; s < sections_to_send; s++)
        {
            int position = start_position + block_size * blocks_to_send + SECTIONS_SIZE * s;
            WriteData(
                data + position,
                SECTIONS_SIZE,
                port);
            for (int i = 0; i < SECTIONS_SIZE; i++)
                checksum ^= data[position + i];
        }
        response = _compare_checksum(checksum, port);
        if (response != ESSP_UDR_OK)
            return response;
    }

    return ESSP_UDR_OK;
}

ESSP_UPDATE_DEVICE_RESPONSE _update_device(
        const unsigned char* const data,
        const unsigned long data_length,
        const char* const port_c,
        const char* const addr_c)
{
    if (data[0] != 'I' && data[1] != 'T' && data[2] != 'L')
        return ESSP_UDR_INVALID_FILE_TYPE;

    SSP_COMMAND sspC;
    sspC.Timeout = 1000;
    sspC.BaudRate = 9600;
    sspC.RetryLevel = 3;
    sspC.SSPAddress = (int)(strtod(addr_c, NULL));
    sspC.EncryptionStatus = NO_ENCRYPTION;
    if (!open_ssp_port(port_c))
        return ESSP_UDR_PORT_ERROR;
    SSP_PORT port = get_open_port();

    if (ssp6_sync(&sspC) != SSP_RESPONSE_OK)
        return ESSP_UDR_NO_VALIDATOR;

    unsigned long baud = 38400;
    if (data[5] != 0x9 && data[5] != 0xA)
    {
        // There is some exception with the baud rate for the NV9 and NV10.
        baud =
            data[71]
            | (long)data[70] << 8
            | (long)data[69] << 16
            | (long)data[68] << 24;
        if (baud == 0)
            baud = 38400;
    }

    int ram_file_size;
    unsigned short int block_size;
    ESSP_UPDATE_DEVICE_RESPONSE response = _send_ram_file(
        &sspC,
        data,
        data_length,
        port,
        baud,
        &ram_file_size,
        &block_size);
    if (response != ESSP_UDR_OK)
        return response;
    response = _send_main_file(
        data,
        data_length,
        port_c,
        port,
        baud,
        ram_file_size,
        block_size);
    if (response != ESSP_UDR_OK)
        return response;

    close_ssp_port(port);
    SetBaud(port, 9600);
    port = OpenSSPPort(port_c);

    int ok = 0;
    do {
        if (ssp6_sync(&sspC) == SSP_RESPONSE_OK)
            ok = 1;
    } while (!ok);

    return ESSP_UDR_OK;
}

ESSP_UPDATE_DEVICE_RESPONSE update_device(
        const char* const file_name,
        const char* const port_c,
        const char* const addr_c)
{
    FILE* file = fopen(file_name,"r");
    if (file == NULL)
        return ESSP_UDR_FILE_NOT_FOUND;

    fseek(file, 0 , SEEK_END);
    unsigned long data_length = ftell(file);
    rewind(file);

    unsigned char *data;
    data = malloc(data_length);
    if (fread(data, 1, data_length, file) != data_length)
        return ESSP_UDR_FILE_ERROR;

    fclose(file);

    ESSP_UPDATE_DEVICE_RESPONSE response =
        _update_device(data, data_length, port_c, addr_c);

    free(data);
    return response;
}
