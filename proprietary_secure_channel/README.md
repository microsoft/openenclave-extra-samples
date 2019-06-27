# The Proprietary Secure Channel Sample

This sample demonstrates how to implement a "proprietary" secure channel after remote attestation between two enclaves when TLS is not available.

It has the following properties:

- Written in C++
- Demonstrates an implementation of remote attestation
- Use of mbedTLS within the enclave
- Generate an ephemeral symmetric key in one enclave and use Asymmetric / Public-Key Encryption to establish a secure channel between the two enclaves
- Use symmetric key cryptography to communicate secrets between the two enclaves with root of trust being remote attestation
- Enclave APIs used:
  - oe_get_report
  - oe_verify_report,
  - oe_is_within_enclave

**Note: Currently this sample only works on SGX-FLC systems.** The underlying SGX library support for end-to-end remote attestation is available only on SGX-FLC systems. There is no plan to back port those libraries to either SGX1 system or software emulator.

## Attestation primer

### What is Attestation

Attestation is the process of demonstrating that a software component (such as an enclave image) has been properly instantiated on an Trusted Execution Environment (TEE, such as the SGX enabled platform).

A successfully attested enclave proves:

- The enclave is running in a valid Trusted Execution Environment (TEE), which is Intel SGX in this case (trustworthiness).

- The enclave has the correct identity and runtime properties that has not been tampered with (identity).

  In the context of Open Enclave, when an enclave requests confidential information from a remote entity, the remote entity will issue a challenge to the requesting enclave to prove its identity and trustworthiness before provisioning any confidential information to the enclave. This process of proving its identity and trustworthiness to a challenger is known as attestation.

Please refer to the [Open Enclave Remote Attestation Sample README.md](https://github.com/openenclave/openenclave/tree/master/samples/remote_attestation) for complete details on establishing mutual remote attestation.

### Secure Communication Channel

Remote Attestation alone is not enough for the remote party to be able to securely deliver their secrets to the requesting enclave. Securely delivering services requires a secure communication channel which is often guaranteed by Transport Layer Security (TLS). An alternate mechanism for establishing such a non-TLS secure channel could be to generate an ephemeral symmetric key in one enclave and use Asymmetric / Public-Key Encryption to send the key to the other enclave. Symmetric key cryptography can be used after that point to communicate secrets between the two enclaves with the root of trust being remote attestation.

## Proprietary Secure Channel sample

In a typical Open Enclave application, it's common to see multiple enclaves working together to achieve common goals. Once an enclave verifies the counterpart is trustworthy, they can exchange information on a protected channel, which typically provides confidentiality, integrity and replay protection.

This is why instead of attesting an enclave to a remote (mostly cloud) service, this sample demonstrates how to attest two enclaves to each other by using Open Enclave APIs `oe_get_report` and `oe_verify_report` which takes care of all remote attestation operations.

To simplify this sample without losing the focus in explaining how the remote attestation works, host1 and host2 are combined into one single host to eliminate the need for additional socket code logic to deal with communication between two hosts. This is similar to the Open Enclave remote attestation sample.

![Proprietary Secure Channel](images/remoteattestation_sample.png)

### Authoring the Host

The host process is what drives the enclave app. It is responsible for managing the lifetime of the enclave and invoking enclave ECALLs but should be considered an untrusted component that is never allowed to handle plaintext secrets intended for the enclave.

![Proprietary Secure Channel](images/remoteattestation_sample_details.png)

The host does the following in this sample:

   1. Create two enclaves for attesting each other, let's say they are enclave_a and enclave_b

      ```c
      oe_create_proprietarysecurechannel_enclave( enclaveImagePath, OE_ENCLAVE_TYPE_SGX, OE_ENCLAVE_FLAG_DEBUG, NULL, 0, &enclave);
      ```

   2. Ask enclave_a for a remote report and a public key, which is returned in a `RemoteReportWithPKey` structure.

      This is done through a call into the enclave_a `GetRemoteReportWithPKey` `OE_ECALL`

      ```c
      oe_call_enclave(enclave, "GetRemoteReportWithPKey", &args);

      struct RemoteReportWithPKey
      {
          uint8_t pem_key[512]; // public key information
          uint8_t* remote_report;
          size_t remote_report_size;
      };
      ```

      Where:

        - `pem_key` holds the public key that identifies enclave_a and will be used for establishing a secure communication channel between the enclave_a and the enclave_b once the attestation is done.

        - `remote_report` contains a remote report signed by the enclave platform for use in remote attestation

   3. Ask enclave_b to attest (validate) enclave_a's remote report (remote_report from above)

      This is done through the following call:
      ```c
      oe_call_enclave(enclave, "verify_report_and_set_pubkey", &args);
      ```

      In the enclave_b's implementation of `verify_report_and_set_pubkey`, it calls `oe_verify_report`, which will be described in the enclave section to handle all the platform specfic report validation operations (including PCK certificate chain checking). If successful the public key in `RemoteReportWithPKey.pem_key` will be stored inside the enclave for future use

   4. Repeat step 2 and 3 for asking enclave_a to validate enclave_b
  
   5. After both enclaves successfully attest each other, request enclave_a to establish a secure channel. In `establish_secure_channel`, enclave_a generates an ephemeral symmetric key, encrypts the symmetric key with enclave_b's public key, computes a SHA256 hash or digest of the encrypted key, signs the digest with its own private key and sends the digest and signature to enclave_b. Enclave_a initializes the sequence_number to 0.
  
   6. Request enclave_b to decrypt the symmetric key. In `acknowledge_secure_channel`, enclave_b verifies enclave_a's signature and decrypts the key using its own private key. Secure communication channel has been established as the symmetric key is only known to both the enclaves and the root of trust is in the remote attestation.
  
   7. Send encrypted messages securely between enclaves using the symmetric key to encrypt/decrypt the secret message using AES_GCM to communicate after this point for confidentiality and authentication.
   GCM Parameters used: Random IV, sequence number as additional authenticated ata to prevent replay attacks and secret message is the input data to the authenticated encryption function. The output tag, a cryptographic checksum on the data is verified during decryption phase.

      ```c
      // Ask enclave_a to encrypt an internal data with the secret symmetric key and output encrypted message in encrypted_msg
      // enclave_a increments the sequence number which is used as additional data with the AES_GCM crypto encrypt function (see encrypt_gcm() routine for details)
      generate_encrypted_message(enclave_a, &encrypted_msg, &encrypted_msg_size);

      // Send encrypted_msg to the enclave_b, which will decrypt it and comparing with its internal data,
      // In this sample, it starts both enclaves with the exact same data contents for the purpose of
      // demonstrating that the encryption works as expected
      process_encrypted_msg(enclave_b, encrypted_msg, encrypted_msg_size);
      ```

   8. Free the resources used, including the host memory allocated by the enclaves and the enclaves themselves
  
      For example:

      ```c
      oe_terminate_enclave(enclave_a);
      oe_terminate_enclave(enclave_b);
      ```

### Authoring the Enclave

#### Attesting an Enclave

Please refer to the [Open Enclave Remote Attestation Sample README.md](https://github.com/openenclave/openenclave/tree/master/samples/remote_attestation) for details.

## Using Cryptography in an Enclave

The attestation proprietary_secure_channel/common/crypto.cpp file from the sample illustrates how to use mbedTLS inside the enclave for cryptographic operations such as:

- RSA key generation, encryption and decryption
- SHA256 hashing

In general, the Open Enclave SDK provides default support for mbedTLS layered on top of the Open Enclave core runtime with a small integration surface so that it can be switched out by open source developers in the future for your choice of crypto libraries.

See [here](https://github.com/Microsoft/openenclave/tree/master/docs/MbedtlsSupport.md) for supported mbedTLS functions

## Build and run

Note that there are two different build systems supported, one using GNU Make and
`pkg-config`, the other using CMake.

### CMake

This uses the CMake package provided by the Open Enclave SDK.

```bash
cd proprietary_secure_channel
mkdir build && cd build
cmake ..
make run
```

### GNU Make

```bash
cd proprietary_secure_channel
make build
make run
```
