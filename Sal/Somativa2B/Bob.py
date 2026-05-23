import socket
import MyHashLib as HL
import time

def autenticar(login, senha):

    # 1) BOB envia HELLO
    msg = HL.formataMensagem(['HELLO', login])
    s.sendto(msg, ALICE)

    # 2) BOB recebe CHALLENGE com cs_ALICE e salt
    try:
        data, addr = s.recvfrom(1024)
    except:
        print('Alice não está sendo executada: aguardando 10 segundos ...')
        time.sleep(10)
        return False

    print('RECEBI: ', data)
    msg = HL.separaMensagem(data)

    if len(msg) < 3 or msg[0] != 'CHALLENGE':
        print('recebi uma mensagem inválida')
        return False

    cs_ALICE = msg[1]
    salt = msg[2]

    # 3) BOB calcula a senha salgada e responde ao challenge
    # senha_salgada = hash(senha + salt)  — mesmo cálculo feito no cadastro
    _, senha_salgada = HL.calculaHASH(senha + salt)

    # cs_BOB: nonce gerado por Bob (imunidade a replay)
    cs_BOB = HL.geraNonce(128)[1].decode()

    # prova_para_alice = hash(senha_salgada + cs_ALICE)
    _, prova_para_alice = HL.calculaHASH(senha_salgada + cs_ALICE)

    msg = HL.formataMensagem(['CHALLENGE_RESPONSE', cs_BOB, prova_para_alice])
    s.sendto(msg, ALICE)

    # 4) BOB recebe SUCCESS/FAILURE e verifica a prova de Alice
    data, addr = s.recvfrom(1024)
    print('RECEBI: ', data)
    msg = HL.separaMensagem(data)

    resultado = msg[0]
    prova_de_alice = msg[1]

    if resultado == 'SUCCESS':
        # Verifica se Alice realmente conhece a senha: hash(senha_salgada + cs_BOB)
        _, esperado = HL.calculaHASH(senha_salgada + cs_BOB)
        if prova_de_alice == esperado:
            print(f'Alice autenticada com sucesso! Servidor legítimo confirmado.')
        else:
            print(f'AVISO: Alice não provou conhecer a senha — possível ataque!')
    else:
        print('Autenticação NEGADA pelo servidor.')

    print('Resultado:', resultado)
    print('Mensagem recebida:', prova_de_alice)

    # 5) BOB aguarda mensagem assinada de Alice
    try:
        s.settimeout(5)
        data, addr = s.recvfrom(1024)
        print('RECEBI MENSAGEM ASSINADA: ', data)
        valida = HL.verificaMensagem(data, senha_salgada)
        print('Assinatura válida:', valida)
    except:
        print('Nenhuma mensagem assinada recebida.')
    finally:
        s.settimeout(None)


if __name__ == "__main__":

    ALICE = HL.CHARLES if HL.ativar_MiTM else HL.ALICE

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print('ESTA TELA PERTENCE A BOB')

    while True:
        login = input('digite seu LOGIN: ')
        senha = input('digite sua SENHA: ')
        autenticar(login, senha)