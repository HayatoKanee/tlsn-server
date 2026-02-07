#!/bin/bash
set -euo pipefail

# Run on Azure DCsv3 VM with Intel SGX hardware
docker run -d \
  --device /dev/sgx_enclave \
  --device /dev/sgx_provision \
  -v /var/run/aesmd:/var/run/aesmd \
  -p 7047:7047 \
  --name tlsn-server-sgx \
  tlsn-server-sgx

echo "==> tlsn-server-sgx container started"
echo "    Port: 7047 (TLS with RA-TLS certificate)"
echo "    Test: curl -k https://localhost:7047/health"
