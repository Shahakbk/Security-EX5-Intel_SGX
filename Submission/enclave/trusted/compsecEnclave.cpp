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

#include <stdio.h>

#include "compsecEnclave.h"
#include "compsecEnclave_t.h"

#include "sgx_tcrypto.h"
#include <string.h>

#define MAX_USERS 10000
#define MAX_DATA ((2 * MAX_USERS) + 1)
#define MAX_DATA_SIZE (MAX_DATA * (sizeof(unsigned int)))
#define MAX_PATH FILENAME_MAX


/** Enclave Personal Data **/
// Data variables.
unsigned int enclave_num_customers = 0;

unsigned int enclave_data[MAX_DATA];
unsigned int enclave_data_encrypted[MAX_DATA];

// Keys and signatures.
sgx_ec256_private_t enclave_private_encryption_key;
sgx_ec256_private_t enclave_private_signature_key;

sgx_ec256_dh_shared_t enclave_shared_key;
sgx_aes_ctr_128bit_key_t enclave_shared_key_hashed;

/** Enclave External Data **/
// Data variables.
unsigned int enclave_received_num_customers = 0;

unsigned int enclave_received_data_encrypted[MAX_DATA];
unsigned int enclave_received_data_decrypted[MAX_DATA];

// Keys and signatures.

sgx_ec256_signature_t enclave_received_signature;
sgx_ec256_public_t enclave_received_public_signature_key;

/** ECalls Implementations **/

// Writes the data to the enclave and return the number of customers.
int ecall_compsecEnclave_write(unsigned int *data)
{
    enclave_num_customers = data[0];
    for (int idx = 0; idx < MAX_DATA; ++idx)
    {
        enclave_data[idx] = data[idx];
    }

    return SGX_SUCCESS;
}

int ecall_compsecEnclave_generate_keys(sgx_ec256_public_t *public_encryption_key, sgx_ec256_public_t *public_signature_key)
{
    sgx_ecc_state_handle_t p_ecc_handle;

    // Open context.
    sgx_status_t result = sgx_ecc256_open_context(&p_ecc_handle);
    if (SGX_SUCCESS != result)
    {
        return result;
    }

    // Create encryption keys.
    result = sgx_ecc256_create_key_pair(&enclave_private_encryption_key, public_encryption_key, p_ecc_handle);
    if (SGX_SUCCESS != result)
    {
        sgx_ecc256_close_context(p_ecc_handle);
        return result;
    }

    // Create signature keys.
    result = sgx_ecc256_create_key_pair(&enclave_private_signature_key, public_signature_key, p_ecc_handle);
    if (SGX_SUCCESS != result)
    {
        sgx_ecc256_close_context(p_ecc_handle);
        return result;
    }

    // Close context.
    result = sgx_ecc256_close_context(p_ecc_handle);
    if (SGX_SUCCESS != result)
    {
        return result;
    }

    return SGX_SUCCESS;
}

int ecall_compsecEnclave_generate_shared_key(sgx_ec256_public_t *received_public_encryption_key, sgx_ec256_public_t *received_public_signature_key)
{
    sgx_ecc_state_handle_t p_ecc_handle;

    // Open context.
    sgx_status_t result = sgx_ecc256_open_context(&p_ecc_handle);
    if (SGX_SUCCESS != result)
    {
        return result;
    }

    // Compute the shared key.
    result = sgx_ecc256_compute_shared_dhkey(&enclave_private_encryption_key, received_public_encryption_key, &enclave_shared_key, p_ecc_handle);
    if (SGX_SUCCESS != result)
    {
        sgx_ecc256_close_context(p_ecc_handle);
        return result;
    }

    // Close context.
    result = sgx_ecc256_close_context(p_ecc_handle);
    if (SGX_SUCCESS != result)
    {
        return result;
    }

    // Hash the key.
    sgx_sha256_hash_t hash[SGX_SHA256_HASH_SIZE];
    result = sgx_sha256_msg(enclave_shared_key.s, SGX_ECP256_KEY_SIZE, hash);
    if (SGX_SUCCESS != result)
    {
        return result;
    }

    // Save the public signature key of the other.
    enclave_received_public_signature_key = *received_public_signature_key;

    // Take the relevant bits.
    memcpy(enclave_shared_key_hashed, hash, SGX_AESCTR_KEY_SIZE);

    return SGX_SUCCESS;
}

int ecall_compsecEnclave_encrypt_data(unsigned int *encrypted_data, sgx_ec256_signature_t *data_signature)
{
    sgx_ecc_state_handle_t p_ecc_handle;

    int ctr_inc_bits = 32;
    uint8_t p_ctr[SGX_AESCTR_KEY_SIZE] = {0};

    // Encrypt the data.
    sgx_status_t result = sgx_aes_ctr_encrypt(&enclave_shared_key_hashed, (uint8_t*)enclave_data, MAX_DATA_SIZE, p_ctr, ctr_inc_bits, (uint8_t*)encrypted_data);
    if (SGX_SUCCESS != result)
    {
        return result;
    }

    // Open context.
    result = sgx_ecc256_open_context(&p_ecc_handle);
    if (SGX_SUCCESS != result)
    {
        return result;
    }

    // Sign the data.
    result = sgx_ecdsa_sign((uint8_t*)encrypted_data, MAX_DATA_SIZE, &enclave_private_signature_key, data_signature, p_ecc_handle);
    if (SGX_SUCCESS != result)
    {
        sgx_ecc256_close_context(p_ecc_handle);
        return result;
    }

    // Close context.
    result = sgx_ecc256_close_context(p_ecc_handle);
    if (SGX_SUCCESS != result)
    {
        return result;
    }

    return SGX_SUCCESS;
}

int ecall_compsecEnclave_write_encrypted(unsigned int* encrypted_data, sgx_ec256_signature_t data_signature){
    for (int i = 0; i < MAX_DATA; i++){
        enclave_received_data_encrypted[i] = encrypted_data[i];
    }

    enclave_received_signature = data_signature;
    return SGX_SUCCESS;
}

int ecall_compsecEnclave_decrypt_data()
{
    sgx_ecc_state_handle_t p_ecc_handle;

    int ctr_inc_bits = 32;
    uint8_t p_ctr[SGX_AESCTR_KEY_SIZE] = {0};

    // Clear the data before reading.
    memset(enclave_received_data_decrypted, 0, MAX_DATA_SIZE);

    // Decrypt the received data.
    sgx_status_t result = sgx_aes_ctr_decrypt(&enclave_shared_key_hashed, (uint8_t*)enclave_received_data_encrypted, MAX_DATA_SIZE, p_ctr, ctr_inc_bits, (uint8_t*)enclave_received_data_decrypted);
    if (SGX_SUCCESS != result)
    {
        return result;
    }

    // The size is stored in the first member.
    enclave_received_num_customers = enclave_received_data_decrypted[0];

    // Open context.
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

    if (SGX_EC_VALID != output)
    {
        sgx_ecc256_close_context(p_ecc_handle);
        return SGX_ERROR_INVALID_SIGNATURE; // TODO
    }

    // Close context.
    result = sgx_ecc256_close_context(p_ecc_handle);
    if (SGX_SUCCESS != result)
    {
        return result;
    }

    return SGX_SUCCESS;
}

int ecall_compsecEnclave_calculate_avg(int *result, sgx_ec256_signature_t *result_signature)
{
    sgx_ecc_state_handle_t p_ecc_handle;
    unsigned int sum = 0, num_shared_customers = 0;

    // Iterating over the data to find shared customers. The data contains names & values so the increase will be 2 at a time.
    for (int i = 1; i < enclave_num_customers * 2; i += 2)
    {
        for (int j = 1; j < MAX_DATA * 2; j += 2)
        {
            if (enclave_data[i] == enclave_received_data_decrypted[j])
            {
                if (enclave_data[i] == 0)
                {
                    continue;
                }

                // The value is stored in the next member.
                sum += enclave_data[i + 1];
                ++num_shared_customers; break;
            }
        }
    }

    if (0 == num_shared_customers)
    {
        *result = 0;
    } else {
        *result = sum / num_shared_customers;
    }

    // Open context.
    sgx_status_t res = sgx_ecc256_open_context(&p_ecc_handle);
    if (SGX_SUCCESS != res)
    {
        return res;
    }

    // Sign the result.
    res = sgx_ecdsa_sign((uint8_t*)result, sizeof(result), &enclave_private_signature_key, result_signature, p_ecc_handle);
    if (SGX_SUCCESS != res) // TODO
    {
        sgx_ecc256_close_context(p_ecc_handle);
        return res;
    }

    // Close the context.
    res = sgx_ecc256_close_context(p_ecc_handle);
    if (SGX_SUCCESS != res)
    {
        return res;
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
    // ocall_compsecEnclave_sample(buf); // Not found
}