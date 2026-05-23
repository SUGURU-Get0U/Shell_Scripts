import socket
import MyHashLib as HL

def fase1_Autenticacao(senhas, salts):
    global s

    # 1) ALICE AGUARDA UM PEDIDO DE LOGIN
    print('Aguardando solicitação de LOGIN ...')
    
    data, addr = s.recvfrom(1024) 
    print('RECEBI: ', data)
    msg = HL.separaMensagem(data)  # ['HELLO', 'USUARIO']

    if len(msg) < 2 or msg[0] != 'HELLO': 
        print('recebi uma mensagem inválida')
        return False, False
    else:
        user = msg[1]
        user_addr = addr
        if user not in senhas.keys():
            print('Usuario desconhecido')
            return False, False

    # 2) ALICE responde ao HELLO com um CHALLENGE
    cs_ALICE = HL.geraNonce(128)[1].decode()   # nonce de Alice em base64
    salt = salts[user]                          # salt cadastrado do usuário
    
    data = HL.formataMensagem(['CHALLENGE', cs_ALICE, salt]) 
    s.sendto(data, addr)

    # 3) ALICE recebe a resposta do CHALLENGE
    data, addr = s.recvfrom(1024)  # ['CHALLENGE_RESPONSE', cs_BOB, hash(senha_salgada + cs_ALICE)]
    print('RECEBI: ', data)

    if addr != user_addr:
        print('mensagem de origem desconhecida')
        return False, False

    msg = HL.separaMensagem(data) 

    if len(msg) < 3 or msg[0] != 'CHALLENGE_RESPONSE': 
        print('recebi uma mensagem inválida')
        return False, False
    else:
        cs_BOB = msg[1]
        prova_do_bob = msg[2]

    # 4) ALICE verifica se a senha está correta
    # senhas[user] já é hash(senha + salt), ou seja, a senha salgada armazenada
    senha_salgada = senhas[user]

    # Recalcula o que BOB deveria ter enviado: hash(senha_salgada + cs_ALICE)
    local_HASH = HL.calculaHASH(senha_salgada + cs_ALICE)[1]

    # Prova que Alice envia de volta: hash(senha_salgada + cs_BOB)
    prova_para_bob = HL.calculaHASH(senha_salgada + cs_BOB)[1]

    print(f'ALICE compara local_hash={local_HASH} e prova_do_bob={prova_do_bob}')

    if prova_do_bob == local_HASH:
        resposta = 'SUCCESS'
        print(f'Este usuário é {user}')       
        msg = HL.formataMensagem([resposta, prova_para_bob])
        s.sendto(msg, addr)
        return user, addr 
    else:
        resposta = 'FAILURE'
        print(f'Ataque detectado: Pedido de LOGIN NEGADO!!!')
        msg = HL.formataMensagem([resposta, 'SAI FORA, CHARLES ...'])
        s.sendto(msg, addr)
        return None, None 


def fase2_MensagensAssinadas(user, addr):

    if HL.ativar_MiTM:
        msg = f'Ola {user}, voce esta autenticado na Alice'
        data = HL.assinaMensagem(msg, senhas[user]) 
        s.sendto(data, addr)
    else:
        while True:
            msg = input('Digite a mensagem: ')
            data = HL.assinaMensagem(msg, senhas[user]) 
            s.sendto(data, addr)


if __name__ == "__main__":

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(HL.ALICE)

    print('ESTA TELA PERTENCE A ALICE')

    senhas, salts = HL.carregarSenhas()

    while True:
        user, addr = fase1_Autenticacao(senhas, salts)
        if user is not None:
            fase2_MensagensAssinadas(user, addr)