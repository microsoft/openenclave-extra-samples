// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <mbedtls/aes.h>
#include <mbedtls/certs.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/x509.h>
#include <openenclave/enclave.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "../../common/utility.h"

extern "C"
{
    int setup_tls_server(char* server_port);
};

#define MAX_ERROR_BUFF_SIZE 256
char error_buf[MAX_ERROR_BUFF_SIZE];
unsigned char buf[1024];

// mbedtls debug levels
// 0 No debug, 1 Error, 2 State change, 3 Informational, 4 Verbose
#define DEBUG_LEVEL 1
#define SERVER_IP "0.0.0.0"

#define HTTP_RESPONSE                                    \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n"                  \
    "<p>Successful connection using: %s</p>\r\n"         \
    "A message from TLS server inside enclave\r\n"

static void my_debug(
    void* ctx,
    int level,
    const char* file,
    int line,
    const char* str)
{
    ((void)level);

    mbedtls_fprintf((FILE*)ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE*)ctx);
}

int configure_server_ssl(
    mbedtls_ssl_context* ssl,
    mbedtls_ssl_config* conf,
    mbedtls_ssl_cache_context* cache,
    mbedtls_ctr_drbg_context* ctr_drbg,
    mbedtls_x509_crt* server_cert,
    mbedtls_pk_context* pkey)
{
    int ret = 1;
    oe_result_t result = OE_FAILURE;

    printf(TLS_SERVER "Generating the certificate and private key\n");
    result = generate_certificate_and_pkey(server_cert, pkey);
    if (result != OE_OK)
    {
        printf(TLS_SERVER "failed with %s\n", oe_result_str(result));
        goto exit;
    }

    printf(TLS_SERVER "\nSetting up the SSL configuration....\n");
    if ((ret = mbedtls_ssl_config_defaults(
             conf,
             MBEDTLS_SSL_IS_SERVER,
             MBEDTLS_SSL_TRANSPORT_STREAM,
             MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        printf(
            TLS_SERVER
            "failed\n  ! mbedtls_ssl_config_defaults returned failed %d\n",
            ret);
        goto exit;
    }

    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, ctr_drbg);
    mbedtls_ssl_conf_dbg(conf, my_debug, stdout);
    mbedtls_ssl_conf_session_cache(
        conf, cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);

    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_ca_chain(conf, server_cert->next, NULL);

    if ((ret = mbedtls_ssl_conf_own_cert(conf, server_cert, pkey)) != 0)
    {
        printf(
            TLS_SERVER "failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n",
            ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_setup(ssl, conf)) != 0)
    {
        printf(TLS_SERVER "failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }
    ret = 0;
exit:
    fflush(stdout);
    return ret;
}

int generate_keypair(mbedtls_rsa_context* rsa)
{
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    int res = -1;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    res = mbedtls_ctr_drbg_seed(
        &ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (res != 0)
    {
        printf(TLS_SERVER "Failed to seed mbedtls rng.\n");
        goto done;
    }

    res = mbedtls_rsa_gen_key(
        rsa, mbedtls_ctr_drbg_random, &ctr_drbg, 2048, 65537);
    if (res != 0)
    {
        printf(TLS_SERVER "Failed to generate RSA public/private key pair.\n");
        goto done;
    }

    res = 0;

done:
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    return res;
}

int ssl_read_all(mbedtls_ssl_context* ssl, unsigned char* buf, size_t size)
{
    size_t bytes_read = 0;

    while (bytes_read < size)
    {
        int ret = mbedtls_ssl_read(ssl, buf + bytes_read, size - bytes_read);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (ret <= 0)
        {
            switch (ret)
            {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    printf(TLS_SERVER "connection was closed gracefully\n");
                    return -1;

                case MBEDTLS_ERR_NET_CONN_RESET:
                    printf(TLS_SERVER "connection was reset by peer\n");
                    return -1;

                default:
                    printf(
                        TLS_SERVER "mbedtls_ssl_read returned -0x%x\n", -ret);
                    return -1;
            }
            return -1;
        }
        bytes_read += (size_t)ret;
    }
    return 0;
}

int ssl_write_all(
    mbedtls_ssl_context* ssl,
    const unsigned char* buf,
    size_t size)
{
    size_t bytes_written = 0;

    while (bytes_written < size)
    {
        int ret =
            mbedtls_ssl_write(ssl, buf + bytes_written, size - bytes_written);
        if (ret <= 0)
        {
            if (ret == MBEDTLS_ERR_NET_CONN_RESET)
            {
                printf(TLS_SERVER "failed\n  ! peer closed the connection\n\n");
                return -1;
            }
            if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
                ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                printf(
                    TLS_SERVER "failed\n  ! mbedtls_ssl_write returned %d\n\n",
                    ret);
                return -1;
            }
        }
        bytes_written += (size_t)ret;
    }

    return 0;
}

int handle_get_key(mbedtls_ssl_context* ssl, mbedtls_rsa_context* rsa)
{
    protocol_header hdr;

    // Read the GETKEY request from the client.
    printf(TLS_SERVER "<---- Read from client:\n");
    if (ssl_read_all(ssl, (unsigned char*)&hdr, sizeof(hdr)) != 0)
    {
        printf(TLS_SERVER "ssl_read_all failed!\n");
        return -1;
    }
    printf(TLS_SERVER "<---- read GETKEY request from client\n");

    // Generate the RSA public/private key pair.
    printf(TLS_SERVER "Generating public/private key pair.\n");
    mbedtls_rsa_init(rsa, MBEDTLS_RSA_PKCS_V15, 0);
    if (generate_keypair(rsa) != 0)
    {
        printf(TLS_SERVER "ERROR: Failed to generate RSA keys.\n");
        return -1;
    }

    return 0;
}

int write_key(mbedtls_ssl_context* ssl, mbedtls_rsa_context* rsa)
{
    // First, we need to convert to pk to get the PEM file.
    mbedtls_pk_context pk;
    protocol_header hdr;
    uint8_t send_buf[4096];
    size_t send_buf_size = sizeof(send_buf) - sizeof(hdr);
    int ret = -1;

    mbedtls_pk_init(&pk);

    if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0)
    {
        printf(TLS_SERVER "ERROR: Failed to setup pk from rsa context\n");
        goto done;
    }

    if (mbedtls_rsa_copy(mbedtls_pk_rsa(pk), rsa) != 0)
    {
        printf(TLS_SERVER "ERROR: failed to copy rsa key\n");
        goto done;
    }

    if (mbedtls_pk_write_pubkey_pem(
            &pk, send_buf + sizeof(hdr), send_buf_size) != 0)
    {
        printf(TLS_SERVER "ERROR: failed to write public key to PEM\n");
        goto done;
    }

    hdr.cmd = GETKEYRESPONSE;
    hdr.payload_size = strlen((const char*)send_buf + sizeof(hdr)) + 1;
    memcpy(send_buf, &hdr, sizeof(hdr));

    // Now, we just write the buffer to the client.
    if (ssl_write_all(ssl, send_buf, sizeof(hdr) + hdr.payload_size) != 0)
    {
        printf(TLS_SERVER "ERROR: failed to ssl_write_all.\n");
        goto done;
    }

    ret = 0;

done:
    mbedtls_pk_free(&pk);
    return ret;
}

int decrypt_key(
    mbedtls_rsa_context* rsa,
    unsigned char* input,
    unsigned char* output,
    size_t* outlen)
{
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    int res = -1;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    res = mbedtls_ctr_drbg_seed(
        &ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (res != 0)
    {
        printf(TLS_SERVER "Failed to seed mbedtls rng.\n");
        goto done;
    }

    res = mbedtls_rsa_pkcs1_decrypt(
        rsa,
        mbedtls_ctr_drbg_random,
        &ctr_drbg,
        MBEDTLS_RSA_PRIVATE,
        outlen,
        input,
        output,
        *outlen);
    if (res != 0)
    {
        printf(TLS_SERVER "Failed to decrypt encryption key: %d\n", res);
        goto done;
    }

    res = 0;

done:
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    return res;
}

int decrypt_data(
    unsigned char* key,
    size_t keysize,
    unsigned char* iv,
    unsigned char* data,
    size_t datasize)
{
    mbedtls_aes_context ctx;
    unsigned char output[32];
    int ret = -1;

    mbedtls_aes_init(&ctx);

    ret = mbedtls_aes_setkey_dec(&ctx, key, keysize * 8);
    if (ret != 0)
    {
        printf(TLS_SERVER "Failed mbedtls_aes_setkey_dec: %d\n", ret);
        goto done;
    }

    ret = mbedtls_aes_crypt_cbc(
        &ctx, MBEDTLS_DECRYPT, datasize, iv, data, output);
    if (ret != 0)
    {
        printf(TLS_SERVER "Failed mbedtls_aes_crypt_cbc: %d\n", ret);
        goto done;
    }

    // mbedtls does not remove padding. Check the last byte and removing
    // padding.
    output[sizeof(output) - output[sizeof(output) - 1]] = 0;

    printf(TLS_SERVER "Decrypted secret data = %s\n", (const char*)output);
    ret = 0;

done:
    mbedtls_aes_free(&ctx);
    return ret;
}

int read_payload(mbedtls_ssl_context* ssl, mbedtls_rsa_context* rsa)
{
    protocol_header hdr;
    payload_header phdr;
    unsigned char payload[512];
    unsigned char output[256];
    size_t outlen = sizeof(output);
    int ret = -1;

    // Load all the data from the ssl connection.
    if (ssl_read_all(ssl, (unsigned char*)&hdr, sizeof(hdr)) != 0)
    {
        printf(TLS_SERVER "ERROR: failed to ssl_read_all.\n");
        goto done;
    }

    if (ssl_read_all(ssl, (unsigned char*)&phdr, sizeof(phdr)) != 0)
    {
        printf(TLS_SERVER "ERROR: failed to ssl_read_all.\n");
        goto done;
    }

    printf(
        TLS_SERVER "read_payload: got sizes %zu %zu\n",
        hdr.payload_size,
        phdr.data_size);
    if (ssl_read_all(ssl, payload, phdr.data_size) != 0)
    {
        printf(TLS_SERVER "ERROR: failed to ssl_read_all.\n");
        goto done;
    }

    printf(TLS_SERVER "CLIENT SENT PAYLOAD DATA =\n");
    for (size_t i = 0; i < sizeof(hdr); i++)
    {
        printf("%x ", *((unsigned char*)&hdr + i));
    }
    for (size_t i = 0; i < sizeof(phdr); i++)
    {
        printf("%x ", *((unsigned char*)&phdr + i));
    }
    for (size_t i = 0; i < phdr.data_size; i++)
    {
        printf("%x ", payload[i]);
    }
    printf("\n");

    // Decrypt the key using the rsa private key.
    printf(TLS_SERVER "now decrypting the AES key.\n");
    ret = decrypt_key(rsa, phdr.key, output, &outlen);
    if (ret != 0)
    {
        printf(TLS_SERVER "ERROR: failed to decrypt_key.\n");
        goto done;
    }

    printf(TLS_SERVER "DUMPING AES KEY.\n");
    for (size_t i = 0; i < outlen; i++)
        printf("%d ", output[i]);
    printf("\n");

    // Decrypt the payload data with the key and IV.
    printf(TLS_SERVER "now decrypting payload with AES key.\n");
    ret = decrypt_data(output, outlen, phdr.iv, payload, phdr.data_size);

done:
    return ret;
}

// This routine conducts a simple protocol for sending client encrypted data
// to the server. The protocol is the following:
//      1. Client sends public key request to the enclave server.
//      2. Enclave generates a private/public key pair and sends the public key
//      to the client.
//      3. Client encrypts the client encryption key with the public key and
//      sends the data + key to server.
//      4. Server uses the private key to decrypt the encryption key and then
//      uses that key to decrypt the data.
int handle_communication_protocol(mbedtls_ssl_context* ssl)
{
    mbedtls_rsa_context rsa;
    int ret;

    // Step 1: Get the key request from the client and generate the key pair.
    if (handle_get_key(ssl, &rsa) != 0)
    {
        printf(TLS_SERVER "ERROR: failed to handle_get_key.\n");
        return -1;
    }

    // Step 2: Send the public key back to the client.
    if (write_key(ssl, &rsa) != 0)
    {
        printf(TLS_SERVER "ERROR: failed to write_key.\n");
        goto done;
    }

    // Step 3: Server recevies the encrypted data from the client and decrypts
    // the secret.
    if (read_payload(ssl, &rsa) != 0)
    {
        printf(TLS_SERVER "ERROR: failed to read payload.\n");
        goto done;
    }

    ret = 0;

done:
    mbedtls_rsa_free(&rsa);
    return ret;
}

// This routine was created to demonstrate a simple communication scenario
// between a TLS client and an TLS server. In a real TLS server app, you
// definitely will have to do more that just receiving a single message
// from a client.
int handle_communication_until_done(
    mbedtls_ssl_context* ssl,
    mbedtls_net_context* listen_fd,
    mbedtls_net_context* client_fd)
{
    int ret = 0;
    int len = 0;

waiting_for_connection_request:

    if (ret != 0)
    {
        mbedtls_strerror(ret, error_buf, MAX_ERROR_BUFF_SIZE);
        printf("Last error was: %d - %s\n", ret, error_buf);
    }

    // reset ssl setup and client_fd to prepare for the new TLS connection
    mbedtls_net_free(client_fd);
    mbedtls_ssl_session_reset(ssl);

    printf(TLS_SERVER "Waiting for a client connection request...\n");
    if ((ret = mbedtls_net_accept(listen_fd, client_fd, NULL, 0, NULL)) != 0)
    {
        char errbuf[512];
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        printf(
            TLS_SERVER " failed\n  ! mbedtls_net_accept returned %d\n %s\n",
            ret,
            errbuf);
        goto done;
    }
    printf(
        TLS_SERVER
        "mbedtls_net_accept returned successfully.(listen_fd = %d) (client_fd "
        "= %d) \n",
        listen_fd->fd,
        client_fd->fd);

    // set up bio callbacks
    mbedtls_ssl_set_bio(
        ssl, client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    printf(TLS_SERVER "Performing the SSL/TLS handshake...\n");
    while ((ret = mbedtls_ssl_handshake(ssl)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            printf(
                TLS_SERVER "failed\n  ! mbedtls_ssl_handshake returned -0x%x\n",
                -ret);
            goto done;
        }
    }

    printf(TLS_SERVER "mbedtls_ssl_handshake done successfully\n");

    // Handle the custom procotol between server and client.
    if (handle_communication_protocol(ssl) != 0)
    {
        printf(TLS_SERVER "Failed! handle_communication_protocol failed.\n");
        goto done;
    }

    // Write a close back to the client
    printf(TLS_SERVER "Closing the connection...\n");
    while ((ret = mbedtls_ssl_close_notify(ssl)) < 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            printf(
                TLS_SERVER "failed! mbedtls_ssl_close_notify returned %d\n\n",
                ret);
            goto waiting_for_connection_request;
        }
    }

    ret = 0;
    // comment out the following line if you want the server in a loop
    // goto waiting_for_connection_request;

done:
    return ret;
}

int setup_tls_server(char* server_port)
{
    int ret = 0;
    oe_result_t result = OE_FAILURE;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt server_cert;
    mbedtls_pk_context pkey;
    mbedtls_ssl_cache_context cache;
    mbedtls_net_context listen_fd, client_fd;
    const char* pers = "tls_server";

    // Explicitly enabling features
    if ((result = oe_load_module_host_resolver()) != OE_OK)
    {
        printf(
            TLS_SERVER "oe_load_module_host_resolver failed with %s\n",
            oe_result_str(result));
        goto exit;
    }
    if ((result = oe_load_module_host_socket_interface()) != OE_OK)
    {
        printf(
            TLS_SERVER "oe_load_module_host_socket_interface failed with %s\n",
            oe_result_str(result));
        goto exit;
    }

    // init mbedtls objects
    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ssl_cache_init(&cache);
    mbedtls_x509_crt_init(&server_cert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_debug_set_threshold(DEBUG_LEVEL);

    printf(
        TLS_SERVER "Setup the listening TCP socket on SERVER_IP= [%s] "
                   "server_port = [%s]\n",
        SERVER_IP,
        server_port);
    if ((ret = mbedtls_net_bind(
             &listen_fd, SERVER_IP, server_port, MBEDTLS_NET_PROTO_TCP)) != 0)
    {
        printf(TLS_SERVER "failed\n  ! mbedtls_net_bind returned %d\n", ret);
        goto exit;
    }

    printf(
        TLS_SERVER "mbedtls_net_bind returned successfully. (listen_fd = %d)\n",
        listen_fd.fd);

    printf(TLS_SERVER "Seeding the random number generator (RNG)\n");
    if ((ret = mbedtls_ctr_drbg_seed(
             &ctr_drbg,
             mbedtls_entropy_func,
             &entropy,
             (const unsigned char*)pers,
             strlen(pers))) != 0)
    {
        printf(
            TLS_SERVER "failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    // Configure server SSL settings
    ret = configure_server_ssl(
        &ssl, &conf, &cache, &ctr_drbg, &server_cert, &pkey);
    if (ret != 0)
    {
        printf(TLS_SERVER "failed\n  ! mbedtls_net_connect returned %d\n", ret);
        goto exit;
    }

    // handle communication
    ret = handle_communication_until_done(&ssl, &listen_fd, &client_fd);
    if (ret != 0)
    {
        printf(TLS_SERVER "server communication error %d\n", ret);
        goto exit;
    }

exit:

    if (ret != 0)
    {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        printf(TLS_SERVER "Last error was: %d - %s\n\n", ret, error_buf);
    }

    // free resource
    mbedtls_net_free(&client_fd);
    mbedtls_net_free(&listen_fd);
    mbedtls_x509_crt_free(&server_cert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ssl_cache_free(&cache);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    fflush(stdout);
    return (ret);
}
