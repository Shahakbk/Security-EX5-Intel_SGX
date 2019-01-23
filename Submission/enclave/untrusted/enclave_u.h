//
// Created by Shahak on 17/01/2019.
//

#ifndef HW5_ENCLAVE_U_H
#define HW5_ENCLAVE_U_H

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h> /* for size_t */

#include "sgx_edger8r.h" // For sgx_status_t etc.
#include "sgx_tcrypto.h"

#define SGX_CAST(type, item) ((type)(item))

// This module is based on SGX-Tor open source.

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_enclave_sample, (const char* str));

/** ECalls **/

sgx_status_t ecall_enclave_write(sgx_enclave_id_t eid, int *retval, unsigned int *data, unsigned int num_customers);
sgx_status_t ecall_enclave_generate_keys(sgx_enclave_id_t eid, int *retval, sgx_ec256_public_t *public_encryption_key, sgx_ec256_public_t *public_signature_key);
sgx_status_t ecall_enclave_generate_shared_key(sgx_enclave_id_t eid, int *retval, sgx_ec256_public_t *received_public_encryption_key, sgx_ec256_public_t *received_public_signature_key);
sgx_status_t ecall_enclave_encrypt_data(sgx_enclave_id_t eid, int *retval, unsigned int *encrypted_data, unsigned int *encrypted_num_customers, sgx_ec256_signature_t *data_signature);
sgx_status_t ecall_enclave_write_encrypted(sgx_enclave_id_t eid, int *retval, unsigned int *encrypted_data, unsigned int *encrypted_num_customers, sgx_ec256_signature_t data_signature);
sgx_status_t ecall_enclave_decrypt_data(sgx_enclave_id_t eid, int *retval);
sgx_status_t ecall_enclave_calculate_avg(sgx_enclave_id_t eid, int *retval, double *result, sgx_ec256_signature_t *result_signature);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif //HW5_ENCLAVE_U_H
