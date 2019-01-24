//
// Created by Shahak on 17/01/2019.
//

/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _SAMPLE_H
#define _SAMPLE_H

#include <string>
#include <iostream>
#include <fstream>

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <libgen.h>
#include <pwd.h>
#include <sgx_urts.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

#define MAX_USERS 10000
#define MAX_DATA ((2 * MAX_USERS) + 1)
#define MAX_DATA_SIZE ((sizeof(unsigned int)) * MAX_DATA)
#define PORT (5765)
#define MAX_PATH FILENAME_MAX

#define TOKEN_FILENAME   "compsecEnclave.token"
#define COMPSECENCLAVE_FILENAME "compsecEnclave.signed.so"

#define SGX_SUCCESS 0
#define SGX_FAILURE -1

#define SOCKET_SUCCESS 0
#define SOCKET_FAILURE -1

#define ENCLAVE_SUCCESS 0
#define ENCLAVE_FAILURE -1

#define IS_DEBUG 0

using namespace std;

extern sgx_enclave_id_t global_eid;    /* global enclave id */

bool isBob(const char* name);

bool isAlice(const char* name);

void debug(const char *sender, const char *str);

unsigned int* readDataFromFile(char* data_path);

int openSocketServer();

int openSocketClient();

int writeToSocket(int socketFD, void* data, int size);

int readFromSocket(int socketFD, void* data, int size);

void printErrorMessage(sgx_status_t ret);

int initEnclave(void);

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(__cplusplus)
}
#endif

#endif
