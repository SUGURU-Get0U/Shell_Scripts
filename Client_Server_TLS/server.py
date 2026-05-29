#!/usr/bin/env python3
import socket, ssl, threading

SERVER_IP = "127.0.0.1" # Localhost
SERVER_PORT = 40232 # avoids conflict with other computer PORTS
MY_CERT = "server.crt" # server self signed certificate
MY_KEY = "server.key" # server private key
PEER_CERT = "allclients.crt" # client certificate

 

# Cria o contexto como SERVIDOR TLS
# -- carrega o certificado e chaves locais
# -- indica como o PEER (clientes) serão autenticados

# Says which Algorithms he can use
def prepara_contexto():
    # sets context to default, uses every possible crypt algorithm on cipher suite.
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH) # Says this file is a SERVER (cause it authenticates a User)

    ctx.verify_mode = ssl.CERT_REQUIRED # Exige certificado do cliente!

    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT # permite certificados auto-assinados (cuidado)
    ctx.load_cert_chain(certfile=MY_CERT, keyfile=MY_KEY)
    ctx.load_verify_locations(cafile=PEER_CERT)
    # optional hardening
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False # avoids DNS connection error
    return ctx

# Extrai a identidade a partir do certificado enviado pelo cliente
# -- utilizado apenas em cenário de autenticação-mutua
# -- por default, o cliente não envia certificados

def verifica_conexao(ssock: ssl.SSLSocket) -> str:
    print("Cipher:", ssock.cipher())
    cert = ssock.getpeercert()
    subject = dict(x[0] for x in cert.get("subject", ()))
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    identidade = subject.get("commonName", "?")
    print(f"Recebi certificado de {identidade} emitido por {issuer.get('commonName','?')}")
    return identidade

# Função que responde a mensagens recebidas pelo canal TLS
# -- observe que ssock.recv DESCRIPTOGRAFA automaticamente
# -- observe que ssock.send CRIPTOGRAFA AUTOMATICAMENTE

def trata_cliente(ssock: ssl.SSLSocket, cid: str):
    try:
        while True:
            data = ssock.recv(4096)
            if not data:
                break
            ssock.send(f"Prezado {cid}, recebi {len(data)} bytes\n".encode())
    except Exception as e:
        print("Erro:", e)
    finally:
        print(f"O cliente {cid} encerrou")
        try:
            ssock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        ssock.close()

# Função que recebe a conexão TCP e cria a sessão TLS
# -- observe sock é EMBRULHADO em ssock
# -- todo handshake TLS acontece aqui

def recebe_conexao(sock: socket.socket, ctx: ssl.SSLContext):
    conn, addr = sock.accept()
    try:
        ssock = ctx.wrap_socket(conn, server_side=True) # handles all the TLS.
        cid = verifica_conexao(ssock)
        ssock.send(f"OLA {cid} bem vindo ao servidor TLS\n".encode())
        return ssock, cid
    except ssl.SSLError as e:
        print("Falha TLS:", e)
        conn.close()
        return None, "LIAR!!!"

# --------------------------------------------------------------------

# Corpo principal do programa servidor

# - cria um contexto
# - recebe uma conexão TCP e cria a sessão TLS com o cliente
# - cria uma thread para conversar com o cliente em modo criptografado

if __name__ == "__main__":
    ctx = prepara_contexto()
    with socket.create_server((SERVER_IP, SERVER_PORT)) as s:
        print("Servidor TLS aguardando conexões ...")
        while True:
            ssock, cid = recebe_conexao(s, ctx)
            if ssock:
                threading.Thread(target=trata_cliente, args=(ssock, cid), daemon=True).start()
            else:
                print("Conexão inválida rejeitada.")