//
// Created by Shahak on 17/01/2019.
//

#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_enclave_write_t {
    int ms_retval;
    unsigned int *ms_data;
    unsigned int ms_num_customers;
} ms_ecall_enclave_write_t;

typedef struct ms_ecall_enclave_generate_keys_t {
    int ms_retval;
    sgx_ec256_public_t *public_encryption_key;
    sgx_ec256_public_t *public_signature_key;
} ms_ecall_enclave_generate_keys_t;

typedef struct ms_ecall_enclave_generate_shared_key_t {
    int ms_retval;
    sgx_ec256_public_t *received_public_encryption_key;
    sgx_ec256_public_t *received_public_signature_key;
} ms_ecall_enclave_generate_shared_key_t;

typedef struct ms_ecall_enclave_encrypt_data_t {
    int ms_retval;
    unsigned int *encrypted_data;
    unsigned int *encrypted_num_customers;
    sgx_ec256_signature_t *data_signature;
} ms_ecall_enclave_encrypt_data_t;

typedef struct ms_ecall_enclave_write_encrypted_t {
    int ms_retval;
    unsigned int *encrypted_data;
    unsigned int *encrypted_num_customers;
    sgx_ec256_signature_t *data_signature;
} ms_ecall_enclave_write_encrypted_t;

typedef struct ms_ecall_decrypt_data_t {
    int ms_retval;
} ms_ecall_decrypt_data_t;

typedef struct ms_ecall_enclave_calculate_avg_t {
    int ms_retval;
    double *result;
    sgx_ec256_signature_t *result_signature;
} ms_ecall_enclave_calculate_avg_t;

typedef struct ms_ocall_enclave_sample_t {
    char *ms_str;
} ms_ocall_enclave_sample_t;

static ms_sgx_status_t SGX_CDECL enclave_ocall_enclave_sample(void* pms)
{
    ms_ocall_enclave_sample_t *ms = SGX_CAST(ms_ocall_enclave_sample_t*, pms);
    ocall_enclave_sample((const char*)ms->ms_str);

    return SGX_SUCCESS;
}

static const struct {
    size_t nr_ocall;
    void *table[1];
} ocall_table_enclave = {
        1,
        {
                (void*)enclave_ocall_enclave_sample,
        }
};

sgx_status_t ecall_enclave_write(sgx_enclave_id_t eid, int *retval, unsigned int *data, unsigned int num_customers)
{
    ms_ecall_enclave_write_t ms;
    ms.ms_data = data;
    ms.ms_num_customers = num_customers;

    sgx_status_t status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
    if (status == SGX_SUCCESS && NULL != retval)
    {
        *retval = ms.ms_retval;
    }

    return status;
}

sgx_status_t ecall_enclave_generate_keys(sgx_enclave_id_t eid, int *retval, sgx_ec256_public_t *public_encryption_key, sgx_ec256_public_t *public_signature_key)
{
    ms_ecall_enclave_generate_keys_t ms;
    ms.public_encryption_key = public_encryption_key;
    ms.public_signature_key = public_signature_key;

    sgx_status_t status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
    if (status == SGX_SUCCESS && NULL != retval)
    {
        *retval = ms.ms_retval;
    }

    return status;
}

sgx_status_t ecall_enclave_generate_shared_key(sgx_enclave_id_t eid, int *retval, sgx_ec256_public_t *received_public_encryption_key, sgx_ec256_public_t *received_public_signature_key)
{
    ms_ecall_enclave_generate_shared_key_t ms;
    ms.received_public_encryption_key = received_public_encryption_key;
    ms.received_public_signature_key = received_public_signature_key;

    sgx_status_t status = sgx_ecall(eid, 2, &ocall_table_enclave, &ms);
    if (status == SGX_SUCCESS && NULL != retval)
    {
        *retval = ms.ms_retval;
    }

    return status;
}

sgx_status_t ecall_enclave_encrypt_data(sgx_enclave_id_t eid, int *retval, unsigned int *encrypted_data, unsigned int *encrypted_num_customers, sgx_ec256_signature_t *data_signature)
{
    ms_ecall_enclave_encrypt_data_t ms;
    ms.encrypted_data = encrypted_data;
    ms.encrypted_num_customers = encrypted_num_customers;
    ms.data_signature = data_signature;

    sgx_status_t status = sgx_ecall(eid, 3, &ocall_table_enclave, &ms);
    if (status == SGX_SUCCESS && NULL != retval)
    {
        *retval = ms.ms_retval;
    }

    return status;
}

sgx_status_t ecall_enclave_write_encrypted(sgx_enclave_id_t eid, int *retval, unsigned int *encrypted_data, unsigned int *encrypted_num_customers, sgx_ec256_signature_t data_signature)
{
    ms_ecall_enclave_write_encrypted_t ms;
    ms.encrypted_data = encrypted_data;
    ms.encrypted_num_customers = encrypted_num_customers;
    ms.data_signature = data_signature;

    sgx_status_t status = sgx_ecall(eid, 4, &ocall_table_enclave, &ms);
    if (status == SGX_SUCCESS && NULL != retval)
    {
        *retval = ms.ms_retval;
    }

    return status;
}

sgx_status_t ecall_enclave_decrypt_data(sgx_enclave_id_t eid, int *retval)
{
    ms_ecall_decrypt_data_t ms;

    sgx_status_t status = sgx_ecall(eid, 5, &ocall_table_enclave, &ms);
    if (status == SGX_SUCCESS && NULL != retval)
    {
        *retval = ms.ms_retval;
    }

    return status;
}

sgx_status_t ecall_enclave_calculate_avg(sgx_enclave_id_t eid, int *retval, double *result, sgx_ec256_signature_t *result_signature)
{
    ms_ecall_enclave_calculate_avg_t ms;
    ms.result = result;
    ms.result_signature = result_signature;

    sgx_status_t status = sgx_ecall(eid, 6, &ocall_table_enclave, &ms);
    if (status == SGX_SUCCESS && NULL != retval)
    {
        *retval = ms.ms_retval;
    }

    return status;
}
