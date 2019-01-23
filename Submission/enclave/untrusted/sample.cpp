//
// Created by Shahak on 17/01/2019.
//

#include <iostream>
#include <string>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <libgen.h>
#include <pwd.h>
#include <fstream>
#include <sgx_urts.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>

#include "sample.h"
#include "compsecEnclave_u.h"

#define MAX_USERS 10000
#define MAX_DATA ((2 * MAX_USERS) + 1)
#define MAX_DATA_SIZE ((sizeof(unsigned int)) * MAX_DATA)
#define PORT (5765)
#define MAX_PATH FILENAME_MAX

using std::string;

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

    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
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

/* OCall functions */
void debug(const char *sender, const char *str)
{
    if (DEBUG)
    {
        printf("%s:\t%s\n", sender, str);
    }
}

int openSocketServer()
{
    int socketFD, newsocketFD;
    struct sockaddr_in server_address, client_address;

    // Open the socket.
    socketFD = socket(AF_INET,SOCK_STREAM,0);

    // Check if the call was successful.
    if (socketFD < 0){
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
    if (bind_socket_res < 0){
        printf("Socket was not bound successfully.\n");
        close(socketFD);
        return SOCKET_FAILURE;
    }

    // Listen on the socket.
    int listen_socket_res = listen(socketFD,1);
    if(listen_socket_res < 0){
        printf("Listening on socket was not successful.\n");
        close(socketFD);
        return SOCKET_FAILURE;
    }

    socklen_t clilen = sizeof(client_address);

    // Accept the socket.
    newsocketFD = accept(socketFD, (struct sockaddr*)&client_address, &clilen);
    if (newsocketFD < 0){
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
    if (socketFD < 0){
        printf("Socket was not opened successfully.\n");
        return SOCKET_FAILURE;
    }

    // Set socket options.
    int enable = 1;
    int set_socket_res = setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));

    if (set_socket_res < 0){
        printf("Socket options were not set successfully.\n");
        return SOCKET_FAILURE;
    }

    // Get the local host.
    const char local_host[10] = "localhost";
    server = gethostbyname(local_host);

    // Check if local host was found.
    if (NULL == server) {
        printf("Local host was not found.\n");
        return SOCKET_FAILURE;
    }

    // Reset server address data.
    bzero((char *) &server_address, sizeof(server_address));

    server_address.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&server_address.sin_addr.s_addr, server->h_length);
    server_address.sin_port = htons(PORT);

    // Connect the socket.
    int connect_socket_res = connect(socketFD,(struct sockaddr*)&server_address,sizeof(server_address));
    if (connect_socket_res < 0){
        printf("Socket was not connected successfully.\n");
        return SOCKET_FAILURE;
    }

    return socketFD;
}

int writeToSocket(int socketFD, void* data, int size){
    // Try to write on the socket.
    int socket_write_res = write(socketFD, data, size);

    // Check if writing on the socket was successful.
    if (socket_write_res < 0){
        printf("Writing on the socket was not successful.\n");
        close(socketFD);
        return SOCKET_FAILURE;
    }

    return SOCKET_SUCCESS;
}

int readFromSocket(int socketFD, void* data, int size){
    // Clear the data before reading.
    bzero(data,size);

    // Try to read from the socket.
    int socket_read_res = read(socketFD, data, size);

    // Check if reading from the socket was successful.
    if (socket_read_res < 0){
        printf("Reading from the socket was not successful.\n");
        close(socketFD);
        return SOCKET_FAILURE;
    }

    return SOCKET_SUCCESS;
}

int readDataFromFile(char* file_path, unsigned int* data){

    // If file opening fails, an exception may be thrown.
    try
    {
        int idx = 0;
        unsigned int id, sum, customers_num = 0;
        std::fstream input;

        // Try to open the file.
        input.open(file_path,std::fstream::in);

        // Read ID & sum.
        while(input >> id >> sum)
        {
            ++customers_num;
            data[idx++] = id;
            data[idx++] = sum;
        }

        // Save the number of customers as the first member.
        data[0] = customers_num;

    } catch (...) {
        return FILE_READ_FAILURE;
    }

    return FILE_READ_SUCCESS;
}

bool isBob(const char* name)
{
    return strcmp(name, "bob") == 0;
}

bool isAlice(const char* name)
{
    return strcmp(name, "alice") == 0;
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

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

    if (initEnclave() < 0)
    {
        return ENCLAVE_FAILURE;
    }

    /** Opening a socket between Alice & Bob where Alice is the server and Bob is the client. **/
    debug(sender, "Opening a socket.");

    int socketFD;
    if (isAlice(sender))
    {
        socketFD = openSocketServer();
        if (0 > socketFD) {
            abort();
        }
    } else if (isBob(sender))
    {
        socketFD = openSocketClient();
        if (0 > socketFD)
        {
            abort();
        }
    }

    /** Reading the sender's data from the file. **/
    debug(sender, "Reading from a file to the enclave.");

    unsigned int data[MAX_DATA];
    if (FILE_READ_FAILURE == readDataFromFile(file_path, data))
    {
        printf("Error reading from file.\n");
        close(socketFD);
        abort();
    }

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /** Write the data to the enclave. **/
    debug(sender, "Writing data to the enclave.");

    int ecall_return = 0;
    ret = ecall_compsecEnclave_write(global_eid, &ecall_return, data);
    if (SGX_SUCCESS != ret)
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
    ret = ecall_compsecEnclave_generate_keys(global_eid, &ecall_return, &public_encryption_key, &public_signature_key);
    if (SGX_SUCCESS != ret)
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

    ret = ecall_compsecEnclave_generate_shared_key(global_eid, &ecall_return, &get_public_encryption_key, &get_public_signature_key);
    if (SGX_SUCCESS != ret)
    {
        printf("Shared key generation has failed.\n");
        close(socketFD);
        abort();
    }

    /** Both Alice and Bob will now encrypt their own data on their personal enclave. **/
    debug(sender, "Encrypting the data on the enclave.");

    unsigned int encrypted_data[MAX_DATA], get_encrypted_data[MAX_DATA];
    unsigned int encrypted_num_customers = 0, get_encrypted_num_customers = 0;
    sgx_ec256_signature_t data_signature, get_data_signature;

    ret = ecall_compsecEnclave_encrypt_data(global_eid, &ecall_return, encrypted_data, &encrypted_num_customers, &data_signature);
    if (SGX_SUCCESS != ret)
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
            0 > writeToSocket(socketFD, encrypted_data, sizeof(encrypted_data)) ||
            0 > writeToSocket(socketFD, &encrypted_num_customers, sizeof(encrypted_num_customers)))
        {
            printf("Writing encrypted data to the enclave has failed.\n");
            close(socketFD);
            abort();
        }
    } else if (isBob(sender))
    {
        if (0 > readFromSocket(socketFD, &get_data_signature, sizeof(get_data_signature)) ||
            0 > readFromSocket(socketFD, get_encrypted_data, sizeof(get_encrypted_data)) ||
            0 > readFromSocket(socketFD, &get_encrypted_num_customers, sizeof(get_encrypted_num_customers)))
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
            0 > writeToSocket(socketFD, encrypted_data, sizeof(encrypted_data)) ||
            0 > writeToSocket(socketFD, &encrypted_num_customers, sizeof(encrypted_num_customers)))
        {
            printf("Writing encrypted data to the enclave has failed.\n");
            close(socketFD);
            abort();
        }
    } else if (isAlice(sender))
    {
        if (0 > readFromSocket(socketFD, &get_data_signature, sizeof(get_data_signature)) ||
            0 > readFromSocket(socketFD, get_encrypted_data, sizeof(get_encrypted_data)) ||
            0 > readFromSocket(socketFD, &get_encrypted_num_customers, sizeof(get_encrypted_num_customers)))
        {
            printf("Reading encrypted data to the enclave has failed.\n");
            close(socketFD);
            abort();
        }
    }

    /** Both Alice and Bob write the write signatures and encrypted data into their own enclave. **/
    debug(sender, "Writing the encrypted data into the enclave.");

    ret = ecall_compsecEnclave_write_encrypted(global_eid, &ecall_return, get_encrypted_data, &get_encrypted_num_customers, get_data_signature);
    if (SGX_SUCCESS != ret)
    {
        printf("Writing the received encrypted data to the enclave has failed.\n");
        close(socketFD);
        abort();
    }

    /** Both Alice and Bob decrypt the encrypted data in their own enclave using the shared key **/
    debug(sender, "Decrypting encrypted data in the enclave.");

    ret = ecall_compsecEnclave_decrypt_data(global_eid, &ecall_return);
    if (SGX_SUCCESS != ret)
    {
        printf("Decrypting data on the enclave has failed.\n");
        close(socketFD);
        abort();
    }

    /** Both Alice and Bob calculate the average in their own enclave **/
    debug(sender, "Calculating the average in the enclave.");

    sgx_ec256_signature_t result_signature;
    double result = 0;

    ret = ecall_compsecEnclave_calculate_avg(global_eid, &ecall_return, &result, &result_signature);
    if (SGX_SUCCESS != ret)
    {
        printf("Calculating the average on the enclave has failed.\n");
        close(socketFD);
        abort();
    }

    string sender_print;
    if (isBob(sender))
    {
        sender_print = "Bob";
    } else if (isAlice(sender))
    {
        sender_print = "Alice";
    }

    printf("%s average is: %f\n", sender_print, result);

    // Close the socket and destroy the enclave.
    close(socketFD);
    sgx_destroy_enclave(global_eid);

    return ecall_return;
}
