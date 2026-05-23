

# a) Gera um certificado auto assinado CA ROOT:
openssl req -x509 -newkey rsa:2048 -keyout ca_key.pem -out ca_cert.pem -days 365 -nodes -subj "/C=BR/ST=Parana/L=Curitiba/O=PUCPR/OU=Informatica/CN=www.pucpr.org" \
-addext "basicConstraints=CA:TRUE" -addext "keyUsage=keyCertSign, cRLSign"

# b) Gera um CSR para um servidor Web
penssl req -newkey rsa:2048 -keyout web_key.pem -out web_csr.pem -nodes -subj "/C=BR/ST=Parana/L=Curitiba/O=PUCPR/OU=Politecnica/CN=politecnica.pucpr.org"

# c) Assina o CSR com o certificado CA ROOT
openssl x509 -req -in web_csr.pem -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial -out web_cert.pem -days 365

# d) Verifica se o certificado do servidor Web foi assinado pela CA ROOT
openssl verify -CAfile ca_cert.pem web_cert.pem

# e) Imprime as seguintes informações do certificado:  Issuer, Subject e Validade
openssl x509 -in web_cert.pem -noout -issuer -subject -dates

# f) Extrai a chave pública do certificado do servidor Web
openssl x509 -in web_cert.pem -pubkey -noout > web_pubkey.pem


# g) Criptografa o segredo "Seu Nome" usando a chave pública do servidor Web
# desafia o servidor web a provar que ele é de fato o servidor que eu quero, prova que ele tem a chave privada
echo -n "AMBATUKAN" > segredo.txt
openssl pkeyutl -encrypt -pubin -inkey web_pubkey.pem -in segredo.txt -out segredo.bin
# se ele tiver a chave privada ele consegue descrpitografar essa msg!


# h) Descriptografa o segredo usando a chave privada do servidor Web
openssl pkeyutl -decrypt -inkey web_key.pem -in segredo.bin -out segredo.txt