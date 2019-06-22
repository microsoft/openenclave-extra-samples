## Prerequisites
 The audience is assumed to be familiar:
 [What is an Attested TLS channel](AttestedTLSREADME.md#what-is-an-attested-tls-channel)

# The tls_upload_encrypted_data sample

It has the following properties:

- Demonstrates the attested TLS feature between an enclave application and an non-enclave application.
  - Use of mbedTLS in the enclave and OpenSSL in the non-enclave.
  - Enclave APIs used:
    - `oe_generate_attestation_certificate`
    - `oe_free_attestation_certificate`
    - `oe_verify_attestation_certificate`
  - Host APIs used:
    - `oe_verify_attestation_certificate`
- Demonstrates a simple protocol of sending client AES encrypted data to the enclave.

**Note: Currently this sample only works on SGX-FLC systems.** The underlying SGX library support for end-to-end remote attestation is required but available only on SGX-FLC system. There is no plan to back port those libraries to either SGX1 system or software emulator.

## Sample Details

The sample contains a non-enclave TLS client and an enclave application that hosts an TLS server as shown in the picture below.

 ![Attested TLS channel between a non enclave application and an enclave](tls_between_non_enclave_enclave.png)

Note: Both of them can run on the same machine or separate machines.

### Sample Protocol for Uploading Encrypted Data

The sample contains an example protocol for uploading client encrypted data to an enclave on top of the attested TLS channel. Here are the steps to the protocol:
  1. The client sends a request to the server to generate a public/private key.
  2. The server receives the request and generates a key pair. It then sends the public key to the client.
  3. The client uses an AES key to encrypt its data, and then uses the public key to encrypt the AES key. It sends the encrypted AES key and the data to the server.
  4. The server uses its private key to decrypt the AES key. Then, it uses the AES key to decrypt the data.

The sample will log the steps in the protocol with the `PROTOCOL:` prefix as shown below:
```
TLS client:
====== PROTOCOL START =====.

TLS client: PROTOCOL: Writing key request to server.
TLS server: PROTOCOL: Waiting for client key request.
TLS server: PROTOCOL: Got key request. Generating key pair.
TLS server: PROTOCOL: Sending public key. Value of public key is:
```

### Server Application
  - Host part (`tls_server_host`)
    - Instantiates an enclave before transitioning the control into the enclave via an ecall.
  - Enclave (`tls_server_enclave.signed`)
    - Calls `oe_generate_attestation_certificate` to generate an certificate.
    - Uses mbedTLS API to configure a TLS server using the generated certificate.
    - Launches a TLS server and wait for a client's connection request.
    - Accepts a client connection and then performs the protocol for uploading client encrypted data as mentioned before.
  - The server can be launched through the following command:
```
./server/host/tls_server_host ./server/enc/tls_server_enc.signed -port:12341
```

### Non-enclave Client Application
 - The non-enclave application does the following :
   -  Connects to the server port via a socket.
   - Uses the OpenSSL API to configure a TLS client.
   - Calls `oe_verify_attestation_certificate` to validate the server's certificate.
   - Performs the protocol for uploading client encrypted data as mentioned before.
 - The client can be launched through the following command:
```
./client/tls_client -server:localhost -port:12341
```

## Build and Run

You can build and run from the sample's root directory using `make` as shown below:
```bash
# Build sample.
make

# Run sample.
make run
```