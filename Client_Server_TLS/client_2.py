#!/usr/bin/env python3
import socket, ssl

HOST_ADDR = "127.0.0.1"
HOST_PORT = 40232
PEER_NAME = "server.bcc.com"
PEER_CERT = "server.crt"
MY_CERT = "./client2/client2.crt"
MY_KEY = "./client2/client2.key"

# Cria o contexto como CLIENTE TLS
# -- carrega o certificado e chaves locais
# -- indica como o PEER (servidores) serão autenticados

def prepara_contexto():
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.verify_mode = ssl.CERT_REQUIRED # Não pode ser removido no HTTPs (viola a especificação)!
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT # permite certificados auto-assinados (cuidado)
    ctx.load_cert_chain(certfile=MY_CERT, keyfile=MY_KEY)
    ctx.load_verify_locations(cafile=PEER_CERT)
    ctx.check_hostname = False  # desabilitado porque nossa prática não tem DNS!!!
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    return ctx

# Extrai a identidade a partir do certificado enviado pelo cliente
# -- utilizado apenas em cenário de autenticação-mutua
# -- por default, o cliente não envia certificados

def verifica_conexao(ssock: ssl.SSLSocket):
    print("Cipher:", ssock.cipher())
    cert = ssock.getpeercert()
    subject = dict(x[0] for x in cert.get("subject", ()))
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    identidade = subject.get("commonName", "?")
    print(f"Recebi certificado de {identidade} emitido por {issuer.get('commonName','?')}")
    return identidade

# Função que faz a conexão TCP e cria a sessão TLS
# -- observe sock é EMBRULHADO em ssock
# -- todo handshake TLS acontece aqui

def faz_conexao(ctx: ssl.SSLContext):
    with socket.create_connection((HOST_ADDR, HOST_PORT)) as raw:
        with ctx.wrap_socket(raw, server_hostname=PEER_NAME) as ssock:
            sid = verifica_conexao(ssock)
            print("Conectado, enviando dados...")
            ssock.send(b"Mensagem de teste via TLS\n")
            print(ssock.recv(4096).decode())
            return sid

# --------------------------------------------------------------------

# Corpo principal do programa cliente

# - cria um contexto
# - faz uma conexão TCP e cria a sessão TLS com o servidor
# - faz conexão envia uma mensagem de teste (sem identidade) mas o servidor irá identificar pelo certificado!!!

if __name__ == "__main__":
    ctx = prepara_contexto()
    faz_conexao(ctx)