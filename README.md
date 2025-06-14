# Triple Handshake Attack Demo using miTLS

This project demonstrates the [Triple Handshake Attack](https://www.mitls.org/pages/attacks/3SHAKE) using a customized build of the [miTLS FlexTLS framework](https://github.com/mitls/mitls-flex).


## Requirements

- Docker (Docker Desktop)
- OpenSSL (for manual testing)

---

For both options you need to start off by opening Docker Desktop.

## Semi-Automated (Handshake 1 & 2 Only)
This way will only be able to show the first 2 handshakes as openssl can't do the renegotiation by itself.

### Run
```bash
# Build everything
docker-compose build --no-cache

# Launch all services (MITM, server, and client)
docker-compose up
```

- Logs in `mitm`, `server`, and `client` show the attack progress in the same terminal.
- MITM injects `HelloRequest` for handshake 3, but OpenSSL client does not complete renegotiation. - So this will end in error. (But can be used to demonstrate the first two handshakes)


## All 3 Handshakes

Use this to demonstrate **all three handshakes**, including certificate reuse in handshake 3.

### Step-by-Step Instructions

1. Start MITM and server:

    ```bash
    docker-compose up mitm server
    ```

2. Open a new terminal. Run the OpenSSL **server**:

    ```bash
    openssl s_server -accept 4433 \
      -cert certs/server.crt -key certs/server.key \
      -CAfile certs/ca.crt -Verify 1 -www
    ```

3. Open another terminal. Run the OpenSSL **client**:

    ```bash
    openssl s_client -connect localhost:8443 \
    -cert certs/client.crt -key certs/client.key \
    -CAfile certs/ca.crt -reconnect -tls1_2

    ```
When the MITM sends the HelloRequest to trigger renegotiation:

- If prompted or if nothing happens, press Enter in the OpenSSL client terminal to trigger the renegotiation.

- Alternatively, restart the OpenSSL client with the same command to manually simulate the reused certificate.

### What To Expect

- **Handshake 1**: Initial RSA connection.
- **Handshake 2**: Session resumption.
- **Handshake 3**: MITM triggers renegotiation using `HelloRequest`. If the client reuses its original certificate, the attack succeeds.
