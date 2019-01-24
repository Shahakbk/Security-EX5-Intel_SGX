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

#include "sample.h"
#include "compsecEnclave_u.h"

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

        // PCL errors removed.
};

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    if (3 != argc)
    {
        cout << "Error: Expected two arguments." << endl;
        return -1;
    }

    // Getting the absolute path using stdlib's realpath.
    char path[MAX_PATH];
    char *path_ptr = NULL;
    char *dir = dirname(argv[0]);
    path_ptr = realpath(dir, path);

    // Try to change the working directory based on the path.
    if (0 != chdir(path))
    {
        abort();
    }

    char *sender = argv[1];
    char *file_path = argv[2];

/** Initialize the enclave. **/

    debug(sender, "Initializing the enclave.");

    if (0 > initEnclave())
    {
        printf("Enclave initialization has failed.\n");
        return ENCLAVE_FAILURE;
    }

/** Opening a socket between Alice & Bob where Alice is the server and Bob is the client. **/

    debug(sender, "Opening a socket.");

    int socketFD;
    if (isAlice(sender))
    {
        socketFD = openSocketServer();
        if (0 > socketFD) {
            printf("Could not open a socket successfully.\n");
            abort();
        }
    } else if (isBob(sender))
    {
        socketFD = openSocketClient();
        if (0 > socketFD)
        {
            printf("Could not open a socket successfully.\n");
            abort();
        }
    } else {
        printf("User not found.\n");
        abort();
    }

/** Reading the sender's data from the file. **/
    debug(sender, "Reading from a file to the enclave.");

    unsigned int* data = readDataFromFile(file_path);
    if (NULL == data){
        printf("Error reading from file.\n");
        close(socketFD);
        abort();
    }

/** Write the data to the enclave. **/
    debug(sender, "Writing data to the enclave.");

    int ecall_return = 0;
    ecall_compsecEnclave_write(global_eid, &ecall_return, data);
    if (SGX_SUCCESS != ecall_return)
    {
        printf("Writing to enclave was not successful.\n");
        close(socketFD);
        abort();
    }

    // After writing the data to the enclave, we would like to erase it from the untrusted app.
    memset(data, 0, MAX_DATA * sizeof(unsigned int));

/** Creating public & private key pairs. **/
    debug(sender, "Creating public & private keys.");

    sgx_ec256_public_t public_encryption_key, get_public_encryption_key;
    sgx_ec256_public_t public_signature_key, get_public_signature_key;
    ecall_compsecEnclave_generate_keys(global_eid, &ecall_return, &public_encryption_key, &public_signature_key);
    if (SGX_SUCCESS != ecall_return)
    {
        printf("Keys generation process was not successful.\n");
        close(socketFD);
        abort();
    }

/** Exchanging keys. **/
    debug(sender, "Exchanging keys.");

    // Bob sends his public keys to Alice.
    debug(sender, "Bob sends his keys to Alice.");

    if (isBob(sender))
    {
        // Write the public keys to the socket.
        if (0 > writeToSocket(socketFD, &public_encryption_key, sizeof(public_encryption_key)) ||
            0 > writeToSocket(socketFD, &public_signature_key, sizeof(public_signature_key)))
        {
            printf("Writing the public key to the socket has failed.\n");
            close(socketFD);
            abort();
        }
    } else if (isAlice(sender))
    {
        // Read the public keys from the socket.
        if (0 > readFromSocket(socketFD, &get_public_encryption_key, sizeof(get_public_encryption_key)) ||
            0 > readFromSocket(socketFD, &get_public_signature_key, sizeof(get_public_signature_key)))
        {
            printf("Reading the public key to the socket has failed.\n");
            close(socketFD);
            abort();
        }
    }

    // Alice sends her public keys to Bob.
    debug(sender, "Alice sends her keys to Bob");

    if (isBob(sender))
    {
        // Read the public keys from the socket.
        if (0 > readFromSocket(socketFD, &get_public_encryption_key, sizeof(get_public_encryption_key)) ||
            0 > readFromSocket(socketFD, &get_public_signature_key, sizeof(get_public_signature_key)))
        {
            printf("Reading the public key to the socket has failed.\n");
            close(socketFD);
            abort();
        }
    } else if (isAlice(sender))
    {
        // Write the public keys to the socket.
        if (0 > writeToSocket(socketFD, &public_encryption_key, sizeof(public_encryption_key)) ||
            0 > writeToSocket(socketFD, &public_signature_key, sizeof(public_signature_key)))
        {
            printf("Writing the public key to the socket has failed.\n");
            close(socketFD);
            abort();
        }
    }

/** Generate a shared key using DH and ECC256. **/
    debug(sender, "Generating a shared key.");

    ecall_compsecEnclave_generate_shared_key(global_eid, &ecall_return, &get_public_encryption_key, &get_public_signature_key);
    if (SGX_SUCCESS != ecall_return)
    {
        printf("Shared key generation has failed.\n");
        close(socketFD);
        abort();
    }

/** Both Alice and Bob will now encrypt their own data on their personal enclave. **/
    debug(sender, "Encrypting the data on the enclave.");

    unsigned int encrypted_data[MAX_DATA], get_encrypted_data[MAX_DATA];
    sgx_ec256_signature_t data_signature, get_data_signature;
    memset(get_encrypted_data, 0, MAX_DATA_SIZE);

    ecall_compsecEnclave_encrypt_data(global_eid, &ecall_return, encrypted_data, &data_signature);
    if (SGX_SUCCESS != ecall_return)
    {
        printf("Data encryption in the enclave has failed.\n");
        close(socketFD);
        abort();
    }

/** Exchanging encrypted data and signatures. **/
    debug(sender, "Exchanging encrypted data.");

    // Alice sends her signature and encrypted data to Bob.
    debug(sender, "Alice sends encrypted data and signature to Bob.");

    if (isAlice(sender))
    {
        if (0 > writeToSocket(socketFD, &data_signature, sizeof(data_signature)) ||
            0 > writeToSocket(socketFD, encrypted_data, sizeof(encrypted_data)))
        {
            printf("Writing encrypted data to the enclave has failed.\n");
            close(socketFD);
            abort();
        }
    } else if (isBob(sender))
    {
        if (0 > readFromSocket(socketFD, &get_data_signature, sizeof(get_data_signature)) ||
            0 > readFromSocket(socketFD, get_encrypted_data, sizeof(get_encrypted_data)))
        {
            printf("Reading encrypted data to the enclave has failed.\n");
            close(socketFD);
            abort();
        }
    }

    // Bob sends his signature and encrypted data to Alice.
    debug(sender, "Bob sends encrypted data and signature to Alice.");

    if (isBob(sender))
    {
        if (0 > writeToSocket(socketFD, &data_signature, sizeof(data_signature)) ||
            0 > writeToSocket(socketFD, encrypted_data, sizeof(encrypted_data)))
        {
            printf("Writing encrypted data to the enclave has failed.\n");
            close(socketFD);
            abort();
        }
    } else if (isAlice(sender))
    {
        if (0 > readFromSocket(socketFD, &get_data_signature, sizeof(get_data_signature)) ||
            0 > readFromSocket(socketFD, get_encrypted_data, sizeof(get_encrypted_data)))
        {
            printf("Reading encrypted data to the enclave has failed.\n");
            close(socketFD);
            abort();
        }
    }

/** Both Alice and Bob write the write signatures and encrypted data into their own enclave. **/
    debug(sender, "Writing the encrypted data into the enclave.");

    ecall_compsecEnclave_write_encrypted(global_eid, &ecall_return, get_encrypted_data, get_data_signature);
    if (SGX_SUCCESS != ecall_return)
    {
        printf("Writing the received encrypted data to the enclave has failed.\n");
        close(socketFD);
        abort();
    }

/** Both Alice and Bob decrypt the encrypted data in their own enclave using the shared key. **/
    debug(sender, "Decrypting encrypted data in the enclave.");

    ecall_compsecEnclave_decrypt_data(global_eid, &ecall_return);
    if (SGX_SUCCESS != ecall_return)
    {
        printf("Decrypting data on the enclave has failed.\n");
        close(socketFD);
        abort();
    }

/** Both Alice and Bob calculate the average in their own enclave **/
    debug(sender, "Calculating the average in the enclave.");

    sgx_ec256_signature_t result_signature;
    int result = 0;

    ecall_compsecEnclave_calculate_avg(global_eid, &ecall_return, &result, &result_signature);
    if (SGX_SUCCESS != ecall_return)
    {
        printf("Calculating the average on the enclave has failed.\n");
        close(socketFD);
        abort();
    }

    if (isBob(sender))
    {
        printf("Bob average is: %d\n", result);
    } else if (isAlice(sender))
    {
        printf("Alice average is: %d\n", result);
    }

    debug(sender, "Calculation is done without errors");


    // Close the socket.
    close(socketFD);

    // Destroy the enclave.
    if (SGX_SUCCESS != sgx_destroy_enclave(global_eid))
    {
        abort();
    }

    return ecall_return;
}


/** Auxillary Functions **/

bool isBob(const char* name)
{
    return (strcmp(name, "bob") == 0);
}

bool isAlice(const char* name)
{
    return (strcmp(name, "alice") == 0);
}

void debug(const char *sender, const char *str)
{
    if (IS_DEBUG)
    {
        printf("%s:\t", sender);
        printf("%s\n", str);
    }
}

unsigned int* readDataFromFile(char* data_path){

    fstream file;

    // Try to open the file.
    file.open(data_path, fstream::in);

    // Check if file opening was successful.
    if(file.fail()){
        printf("File opening has encountered an error.\n");
        return NULL;
    }

    // Set an array for the data.
    unsigned int* data = new unsigned int[MAX_DATA];

    // Clear the array.
    memset(data, 0, MAX_DATA_SIZE);

    // Start reading the data from the file.
    unsigned int id, n, size = 0;
    int i = 1;
    while(file >> id >> n){
        // First value is the ID and the second value is the number.
        data[i] = id;
        data[i+1] = n;

        // Move to the next pair.
        i += 2;
        size++;
    }

    // Save the number of customers as the first member.
    data[0] = size;

    return data;
}

int openSocketServer()
{
    int socketFD, newsocketFD;
    struct sockaddr_in server_address, client_address;

    // Open the socket.
    socketFD = socket(AF_INET,SOCK_STREAM,0);

    // Check if the call was successful.
    if (0 > socketFD){
        printf("Socket was not opened successfully.\n");
        return SOCKET_FAILURE;
    }

    // Set socket options.
    int enable = 1;
    int set_socket_res = setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));

    // Check if the socket options were set successfully.
    if (set_socket_res < 0){
        printf("Socket options were not set successfully.\n");
        return SOCKET_FAILURE;
    }

    // Reset server address data.
    bzero((char *) &server_address, sizeof(server_address));

    // Set server parameters.
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(PORT);

    // Bind the server.
    int bind_socket_res = bind(socketFD, (struct sockaddr *)&server_address,sizeof(server_address));

    // Check if binding was successfull.
    if (0 > bind_socket_res){
        printf("Socket was not bound successfully.\n");
        close(socketFD);
        return SOCKET_FAILURE;
    }

    // Listen on the socket.
    int listen_socket_res = listen(socketFD,1);
    if(0 > listen_socket_res){
        printf("Listening on socket was not successful.\n");
        close(socketFD);
        return SOCKET_FAILURE;
    }

    socklen_t clilen = sizeof(client_address);

    // Accept the socket.
    newsocketFD = accept(socketFD, (struct sockaddr*)&client_address, &clilen);
    if (0 > newsocketFD){
        printf("Socket accepting was not successful.\n");
        close(socketFD);
        return SOCKET_FAILURE;
    }

    close(socketFD);
    return newsocketFD;
}

int openSocketClient(){
    int socketFD;
    struct sockaddr_in server_address;
    struct hostent *server;

    // Open the socket.
    socketFD = socket(AF_INET, SOCK_STREAM, 0);

    // Check if the call was successful.
    if (0 > socketFD){
        printf("Socket was not opened successfully.\n");
        return SOCKET_FAILURE;
    }

    // Set socket options.
    int enable = 1;
    int set_socket_res = setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));

    // Check if the socket options were set successfully.
    if (set_socket_res < 0){
        printf("Socket options were not set successfully.\n");
        return SOCKET_FAILURE;
    }

    const char* local_host = "localhost";
    server = gethostbyname(local_host);

    // Check local host.
    if (NULL == server) {
        return SOCKET_FAILURE;
    }

    // Get the right size of server address.
    bzero((char *) &server_address, sizeof(server_address));
    server_address.sin_family = AF_INET;

    bcopy((char *)server->h_addr, (char *)&server_address.sin_addr.s_addr, server->h_length);
    server_address.sin_port = htons(PORT);

    // Try to connect.
    while (0 > connect(socketFD,(struct sockaddr*)&server_address, sizeof(server_address)))
        sleep(1);

    return socketFD;
}

int writeToSocket(int socketFD, void* data, int size){
    // Try to write on the socket.
    int socket_write_res = (int)write(socketFD, data, (size_t)size);

    // Check if writing on the socket was successful.
    if (size != socket_write_res){
        close(socketFD);
        return SOCKET_FAILURE;
    }

    return SOCKET_SUCCESS;
}

int readFromSocket(int socketFD, void* data, int size){
    // Clear the data before reading.
    size_t ssize = (size_t)size;
    bzero(data,ssize);
    size_t total_read = 0;

    // Read the entire data from the socket.
    while (total_read < ssize){

        int socket_read_res = (int)read(socketFD, data + total_read, ssize - total_read);
        if (0 > socket_read_res)
        {
            close(socketFD); // TODO
            return SOCKET_FAILURE;
        }

        total_read += (size_t)socket_read_res;
    }

    return SOCKET_SUCCESS;
}

/* Check error conditions for loading enclave */
void printErrorMessage(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if (ret == sgx_errlist[idx].err) {
            if (NULL != sgx_errlist[idx].sug)
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
int initEnclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    size_t read_num = 0;

    /* Step 1: try to retrieve the launch token saved by last transaction
     *         if there is no token, then create a new one.
     *
     * try to get the token saved in $HOME */
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
    if (IS_DEBUG)
    {
        printf("The token path is %s.\n", token_path);
    }

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

    ret = sgx_create_enclave(COMPSECENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        printErrorMessage(ret);
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
