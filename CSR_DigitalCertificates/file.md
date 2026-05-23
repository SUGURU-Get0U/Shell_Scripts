# Syntax for generating a Private Key

Gerar uma chave privada
Sintaxe:

openssl genpkey -algorithm <ALGORITMO> -out <ARQUIVO_CHAVE> [opções]
<ALGORITMO>: tipo de chave (ex.: RSA, EC).

-out: nome do arquivo de saída.

-pkeyopt: define parâmetros adicionais, como o tamanho da chave.