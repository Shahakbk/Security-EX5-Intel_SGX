//
// Created by Shahak on 17/01/2019.
//

// The implementation of this file is partly based on Intel's SGX samples.

#ifndef _APP_H
#define _APP_H

#include <assert.h>
#include <stdio.h>
#include <string>
#include <stdlib.h>
#include <stdarg.h>

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

#define TOKEN_FILENAME   "compsecEnclave.token"
#define COMPSECENCLAVE_FILENAME "compsecEnclave.signed.so"

#define SGX_SUCCESS 0
#define SGX_FAILURE -1

#define SOCKET_SUCCESS 0
#define SOCKET_FAILURE -1

#define FILE_READ_SUCCESS 0
#define FILE_READ_FAILURE -1

#define ENCLAVE_SUCCESS 0
#define ENCLAVE_FAILURE -1

#define DEBUG 1

extern sgx_enclave_id_t global_eid;    /* global enclave id */

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(__cplusplus)
}
#endif

#endif
