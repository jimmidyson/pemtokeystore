#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR

cat >cfssl-config.json <<EOF
{
  "signing": {
    "default": {
      "expiry": "87600h"
    },
    "profiles": {
      "intermediate": {
        "ca_constraint": {
          "is_ca": true
        },
        "usages": [
          "cert sign",
          "crl sign"
        ],
        "expiry": "87600h"
      },
      "server": {
        "usages": [
          "server auth"
        ],
        "expiry": "87600h"
      }
    }
  }
}
EOF

cat >root-ca-csr.json <<EOF
{
  "CN": "PEMToKeystore Root CA",
  "key": {
    "algo": "ecdsa",
    "size": 256
  },
  "names": [
    {
    }
  ]
}
EOF

cfssl gencert -initca -config cfssl-config.json root-ca-csr.json | cfssljson -bare root-ca

cat >intermediate-ca-csr.json <<EOF
{
  "CN": "PEMToKeystore Intermediate CA",
  "hosts": [
    ""
  ],
  "key": {
    "algo": "ecdsa",
    "size": 256
  },
  "names": [
    {
    }
  ]
}
EOF

cfssl gencert -ca root-ca.pem -ca-key root-ca-key.pem -config=cfssl-config.json -profile=intermediate intermediate-ca-csr.json | cfssljson -bare intermediate-ca

cat >server-csr.json <<EOF
{
  "CN": "localhost",
  "hosts": [
    "pemtokeystore.tld",
    "127.0.0.1",
    "localhost"
  ],
  "key": {
    "algo": "ecdsa",
    "size": 256
  },
  "names": [
    {
    }
  ]
}
EOF

cfssl gencert -ca root-ca.pem -ca-key root-ca-key.pem -config=cfssl-config.json -profile=server server-csr.json | cfssljson -bare server-from-root
cfssl bundle -cert server-from-root.pem -ca-bundle root-ca.pem | jq '. | {"result": {"bundle": .}}' | cfssljson -bare server-from-root
cfssl gencert -ca intermediate-ca.pem -ca-key intermediate-ca-key.pem -config=cfssl-config.json -profile=server server-csr.json | cfssljson -bare server-from-intermediate
cfssl bundle -cert server-from-intermediate.pem -ca-bundle root-ca.pem -int-bundle intermediate-ca.pem | jq '. | {"result": {"bundle": .}}' | cfssljson -bare server-from-intermediate
