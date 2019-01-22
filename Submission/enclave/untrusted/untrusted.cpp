//
// Created by Shahak on 17/01/2019.
//

#include <iostream>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <libgen.h>
#include <pwd.h>
#include <fstream>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "sgx_urts.h"
#include "untrusted.h"
#include "Enclave_u.h"
#include "Seal_u.h"

#define SEAL_FILENAME             "Seal.signed.so"
#define SEALED_KEY_FILE_NAME     "sealed_key.bin"
#define TOKEN_FILENAME            "enclave.token"
#define MAX_USERS 10000
#define MAX_PATH FILENAME_MAX

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug;
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
        {
                SGX_ERROR_UNEXPECTED,
                "Unexpected error occurred.",
                NULL
        },
        {
                SGX_ERROR_INVALID_PARAMETER,
                "Invalid parameter.",
                NULL
        },
        {
                SGX_ERROR_OUT_OF_MEMORY,
                "Out of memory.",
                NULL
        },
        {
                SGX_ERROR_ENCLAVE_LOST,
                "Power transition occurred.",
                "Please refer to the sample \"PowerTransition\" for details."
        },
        {
                SGX_ERROR_INVALID_ENCLAVE,
                "Invalid enclave image.",
                NULL
        },
        {
                SGX_ERROR_INVALID_ENCLAVE_ID,
                "Invalid enclave identification.",
                NULL
        },
        {
                SGX_ERROR_INVALID_SIGNATURE,
                "Invalid enclave signature.",
                NULL
        },
        {
                SGX_ERROR_OUT_OF_EPC,
                "Out of EPC memory.",
                NULL
        },
        {
                SGX_ERROR_NO_DEVICE,
                "Invalid Intel(R) SGX device.",
                "Please make sure Intel(R) SGX module is enabled in the BIOS, and install Intel(R) SGX driver afterwards."
        },
        {
                SGX_ERROR_MEMORY_MAP_CONFLICT,
                "Memory map conflicted.",
                NULL
        },
        {
                SGX_ERROR_INVALID_METADATA,
                "Invalid enclave metadata.",
                NULL
        },
        {
                SGX_ERROR_DEVICE_BUSY,
                "Intel(R) SGX device was busy.",
                NULL
        },
        {
                SGX_ERROR_INVALID_VERSION,
                "Enclave version was invalid.",
                NULL
        },
        {
                SGX_ERROR_INVALID_ATTRIBUTE,
                "Enclave was not authorized.",
                NULL
        },
        {
                SGX_ERROR_ENCLAVE_FILE_ACCESS,
                "Can't open enclave file.",
                NULL
        },
        {
                SGX_ERROR_PCL_ENCRYPTED,
                "sgx_create_enclave can't open encrypted enclave.",
                NULL
        },
        {
                SGX_ERROR_PCL_NOT_ENCRYPTED,
                "sgx_create_encrypted_enclave can't open not-encrypted enclave.",
                NULL
        },
        {
                SGX_ERROR_PCL_MAC_MISMATCH,
                "PCL detected invalid section in encrypted enclave.",
                NULL
        },
        {
                SGX_ERROR_PCL_SHA_MISMATCH,
                "PCL sealed key SHA mismatch.",
                NULL
        },
        {
                SGX_ERROR_PCL_GUID_MISMATCH,
                "PCL sealed key GUID mismatch.",
                NULL
        },
};

/* Check error conditions for loading enclave */
void printErrorMessage(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
sgx_status_t  initEnclave(const char *file_name, sgx_enclave_id_t *eid)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    size_t read_num = 0;

    /* Step 1: try to retrieve the launch token saved by last transaction
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;

    if (home_dir != NULL &&
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    // Print the token path.
    printf("The token path is %s\n", token_path);

    if (fp != NULL) {
        /* read the token from saved file */
        read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }

    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */

    // PCL usage for intellectual property protection removed.

    ret = sgx_create_enclave(file_name, SGX_DEBUG_FLAG, &token, &updated, eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return SGX_FAILURE;
    }

    /* Step 3: save the launch token if it is updated */

    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return SGX_SUCCESS;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return SGX_SUCCESS;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return SGX_SUCCESS;
}

/* OCall functions */
void ocallPrintString(const char *user, const char *str)
{
    printf("%s:\t%s\n", user, str);
}


/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{

    //TODO to be implemented

    (void)(argc);
    (void)(argv);


    /* Initialize the enclave */
    if ( initialize_enclave ( ENCLAVE_FILENAME, &global_eid ) < 0 ){
        return -1;
    }

    printf("Info: SampleEnclave successfully returned.\n");

    return 0;
}
