//
// Created by Shahak on 17/01/2019.
//

/** Based on Intel's SGX sample enclave **/

#include <stdio.h>

#include "enclave.h"
#include "enclave_t.h"

#include "sgx_tcrypto.h"
#include <string.h>

#define TOKEN_FILENAME            "enclave.token"
#define MAX_USERS 10000
#define MAX_DATA 20000
#define MAX_DATA_SIZE (MAX_DATA * (sizeof(unsigned int)))
#define PORT (5765)
#define MAX_PATH FILENAME_MAX

/** Global Variables Definitions **/

// Data variables.
unsigned int enclave_num_customers = 0;
unsigned int enclave_received_num_customers_encrypted = 0;
unsigned int enclave_received_num_customers_decrypted = 0;

unsigned int enclave_data[MAX_DATA];
unsigned int enclave_data_encrypted[MAX_DATA];

unsigned int enclave_received_data_encrypted[MAX_DATA];
unsigned int enclave_received_data_decrypted[MAX_DATA];


// Keys and signatures.
sgx_ec256_private_t enclave_private_encryption_key;
sgx_ec256_private_t enclave_private_signature_key;

sgx_ec256_signature_t enclave_received_signature;
sgx_ec256_public_t enclave_received_public_signature_key;

sgx_ec256_dh_shared_t enclave_shared_key;
sgx_aes_ctr_128bit_key_t enclave_shared_key_hashed;


/** ECalls Implementations **/

// Writes the data to the enclave and return the number of customers.
int ecall_enclave_write(sgx_enclave_id_t eid, int *retval, unsigned int *data, unsigned int num_customers)
{
    enclave_num_customers = num_customers;
    for (int idx = 0; idx < MAX_DATA; ++idx)
    {
        enclave_data[idx] = data[idx];
    }

    return SGX_SUCCESS;
}

int ecall_enclave_generate_keys(sgx_ec256_public_t *public_encryption_key, sgx_ec256_public_t *public_signature_key)
{
    sgx_ecc_state_handle_t p_ecc_handle;
    sgx_status_t result = sgx_ecc256_open_context(&p_ecc_handle);
    if (SGX_SUCCESS != result)
    {
        return result;
    }

    result = sgx_ecc256_create_key_pair(&enclave_private_encryption_key, public_encryption_key, p_ecc_handle);
    if (SGX_SUCCESS != result)
    {
        return result;
    }

    result = sgx_ecc256_create_key_pair(&enclave_private_signature_key, public_signature_key, p_ecc_handle);
    if (SGX_SUCCESS != result)
    {
        return result;
    }

    result = sgx_ecc256_close_context(&p_ecc_handle);
    if (SGX_SUCCESS != result)
    {
        return result;
    }

    return SGX_SUCCESS
}

int ecall_enclave_generate_shared_key(sgx_ec256_public_t *received_public_encryption_key, sgx_ec256_public_t *received_public_signature_key)
{
    sgx_ecc_state_handle_t p_ecc_handle;
    sgx_status_t result = sgx_ecc256_open_context(&p_ecc_handle);
    if (SGX_SUCCESS != result)
    {
        return result;
    }

    enclave_received_public_signature_key = *received_public_signature_key;

    result = sgx_ecc256_compute_shared_dhkey(&enclave_private_signature_key, received_public_signature_key, &enclave_shared_key, p_ecc_handle);
    if (SGX_SUCCESS != result)
    {
        sgx_ecc256_close_context(p_ecc_handle);
        return result;
    }

    result = sgx_ecc256_close_context(&p_ecc_handle);
    if (SGX_SUCCESS != result)
    {
        return result;
    }

    sgx_sha256_hash_t hash[SGX_SHA256_HASH_SIZE];
    result = sgx_sha256_msg(enclave_shared_key.s, SGX_ECP256_KEY_SIZE, hash);
    if (SGX_SUCCESS != result)
    {
        return result;
    }

    memcpy(enclave_shared_key_hashed, hash, SGX_AESCTR_KEY_SIZE);

    return SGX_SUCCESS
}

int ecall_enclave_encrypt_data(unsigned int *encrypted_data, unsigned int *encrypted_num_customers, sgx_ec256_signature_t *data_signature)
{
    sgx_ecc_state_handle_t p_ecc_handle;
    const uint32_t ctr_inc_bits = 0;
    uint8_t p_ctr[SGX_AESCTR_KEY_SIZE] = {0};


    // Encrypt the data.
    sgx_status_t result = sgx_aes_ctr_encrypt(&enclave_shared_key_hashed, (uint8_t*)enclave_data, MAX_DATA_SIZE, p_ctr, ctr_inc_bits, (uint8_t*)enclave_data_encrypted);
    if (SGX_SUCCESS != result)
    {
        return result;
    }

    sgx_status_t result = sgx_aes_ctr_encrypt(&enclave_shared_key_hashed, (uint8_t*)&enclave_num_customers, sizeof(enclave_num_customers), p_ctr, ctr_inc_bits, (uint8_t*)encrypted_num_customers); //TODO &
    if (SGX_SUCCESS != result)
    {
        return result;
    }

    result = sgx_ecc256_open_context(&p_ecc_handle);
    if (SGX_SUCCESS != result)
    {
        return result;
    }

    // Sign the data.
    result = sgx_ecdsa_sign((uint8_t*)enclave_data_encrypted, MAX_DATA_SIZE, &enclave_private_signature_key, data_signature, p_ecc_handle);
    if (SGX_SUCCESS != result)
    {
        sgx_ecc256_close_context(p_ecc_handle);
        return result;
    }

    result = sgx_ecdsa_sign((uint8_t*)encrypted_num_customers, MAX_DATA_SIZE, &enclave_private_signature_key, data_signature, p_ecc_handle); //TODO &
    if (SGX_SUCCESS != result)
    {
        sgx_ecc256_close_context(p_ecc_handle);
        return result;
    }

    sgx_ecc256_close_context(p_ecc_handle);
    return SGX_SUCCESS;
}

int ecall_enclave_write_encrypted(unsigned int *encrypted_data, unsigned int *encrypted_num_customers, sgx_ec256_signature_t data_signature)
{
    for(int idx = 0; idx < MAX_DATA; ++idx)
    {
        enclave_received_data_encrypted[idx] = encrypted_data[idx];
    }

    enclave_received_num_customers_encrypted = *encrypted_num_customers;
    enclave_received_signature = data_signature;
    return SGX_SUCCESS;
}

int ecall_enclave_decrypt_data()
{
    sgx_ecc_state_handle_t p_ecc_handle;
    const uint32_t ctr_inc_bits = 0;
    uint8_t p_ctr[SGX_AESCTR_KEY_SIZE] = {0};

    memset(enclave_received_data_decrypted, 0, MAX_DATA_SIZE);

    // Decrypt the received data.
    sgx_status_t result = sgx_aes_ctr_decrypt(&enclave_shared_key_hashed, (uint8_t*)enclave_received_data_encrypted, MAX_DATA_SIZE, p_ctr, ctr_inc_bits, (uint8_t*)enclave_received_data_decrypted);
    if (SGX_SUCCESS != result)
    {
        return result;
    }

    result = sgx_aes_ctr_decrypt(&enclave_shared_key_hashed, (uint8_t*)&enclave_received_num_customers_encrypted, sizeof(enclave_received_num_customers_encrypted), p_ctr, ctr_inc_bits, (uint8_t*)&enclave_received_num_customers_decrypted); //TODO sizeof
    if (SGX_SUCCESS != result)
    {
        return result;
    }

    result = sgx_ecc256_open_context(&p_ecc_handle);
    if (SGX_SUCCESS != result)
    {
        return result;
    }

    // Check signature.
    uint8_t output;
    result = sgx_ecdsa_verify((uint8_t*)enclave_received_data_encrypted, MAX_DATA_SIZE, &enclave_received_public_signature_key, &enclave_received_signature, &output, p_ecc_handle);
    if (SGX_SUCCESS != result)
    {
        sgx_ecc256_close_context(p_ecc_handle);
        return result;
    }

    if (output != SGX_EC_VALID)
    {
        printf("Enclave could not verify the signature of encrypted data.\n");
        sgx_ecc256_close_context(p_ecc_handle);
        return 0;
    }

    result = sgx_ecdsa_verify((uint8_t*)&enclave_received_num_customers_encrypted, sizeof(enclave_received_num_customers_encrypted), &enclave_received_public_signature_key, &enclave_received_signature, &output, p_ecc_handle); //TODO sizeof
    if (SGX_SUCCESS != result)
    {
        sgx_ecc256_close_context(p_ecc_handle);
        return result;
    }

    if (output != SGX_EC_VALID)
    {
        printf("Enclave could not verify the signature of encrypted data.\n");
        sgx_ecc256_close_context(p_ecc_handle);
        return 0;
    }

    sgx_ecc256_close_context(p_ecc_handle);
    return SGX_SUCCESS
}

int ecall_enclave_calculate_avg(double *result, sgx_ec256_signature_t *result_signature)
{
    sgx_ecc_state_handle_t p_ecc_handle;
    unsigned int sum = 0, num_shared_customers = 0;

    // Iterating over the data to find shared customers. The data contains names & values so the increase will be 2 at a time.
    for (int i = 1; i < enclave_num_customers * 2; i += 2)
    {
        for (int j = 1; j < enclave_received_num_customers_decrypted * 2; j += 2)
        {
            if (enclave_data[i] == enclave_received_data_decrypted[i])
            {
                sum += enclave_data[i];
                ++num_shared_customers;
            }
        }
    }

    if (0 == num_shared_customers)
    {
        *result = 0;
    } else {
        *result = sum / num_shared_customers;
    }

    return SGX_SUCCESS;
}

/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_e_sample(buf);
}