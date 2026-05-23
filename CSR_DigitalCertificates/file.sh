#!/bin/bash -x

openssl genpkey -algorithm RSA -out chave_privada.pem -pkeyopt rsa_keygen_bits:2048
# generates a private key using RSA 2048-bits

openssl req -new -key chave_privada.pem -out pedido.csr

openssl req -in pedido.csr -noout -text

openssl req -in pedido.csr -noout -verify

openssl x509 -req -in pedido.csr \
 -signkey chave_privada.pem -out certificado.crt -days 365

 openssl x509 -in certificado.crt -noout -text

# go drinking