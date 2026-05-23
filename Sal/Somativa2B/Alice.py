import socket
import MyHashLib as HL


# Crie uma estratégia para que ALICE receba a autenticação de usuários pela rede.
# A solução deve ser imune a ataques de REPETIÇÃO (REPLAY)

def fase1_Autenticacao(senhas, salts):

    global s
    
    #------------------------------------------------------------------------------------------------------------
    # 1) ALICE AGUARDA UM PEDIDO DE LOGIN
    # -- não precisa modificar essa seção

    print('Aguardando solicitação de LOGIN ...')
    
    data, addr = s.recvfrom(1024) 
    print('RECEBI: ', data)
    msg = HL.separaMensagem(data)  # mensagem esperada: [ 'HELLO', 'USUARIO' ]

    if len(msg) < 2 or msg[0] != 'HELLO': 
        print('recebi uma mensagem inválida')
        return False
    else:
        user = msg[1]   # O LOGIN USUARIO ESTÁ NESTA VARIAVEL
        user_addr = addr
        if user not in senhas.keys():
            print('Usuario desconhecido')
            return False

    #------------------------------------------------------------------------------------------------------------
    # 2) ALICE responde ao HELLO com um CHALLENGE 
    # -- troque 'NONCE' por um nonce gerado pela função geraNonce da biblioteca
    # -- utilize o segundo parâmetro (base64) e converta para string com decode()
    # -- troque SALT pelo salt do usuário salvo no dicionário de salts (já carregado)
        
    cs_ALICE = HL.geraNonce(128)[1].decode() # TODO: modifique essa linha
    salt = salts[user] # TODO: modifique essa linha
    
    data = HL.formataMensagem(['CHALLENGE', cs_ALICE, salt]) 
    s.sendto(data, addr )


    #------------------------------------------------------------------------------------------------------------
    # 3) ALICE recebe a resposta do CHALLENGE
    # -- não precisa modificar essa seção.

    data, addr = s.recvfrom(1024) # mensagem esperada: ['CHALLENGE_RESPONSE', 'NONCE', 'HASH_SENHA' ]
    print('RECEBI: ', data)

    if addr != user_addr:
        print('mensagem de origem desconhecida')
        return False

    msg = HL.separaMensagem(data) 

    if len(msg) < 3 or msg[0] != 'CHALLENGE_RESPONSE': 
        print('recebi uma mensagem inválida')
        return False
    else:
        cs_BOB = msg[1]
        prova_do_bob = msg[2]

    #------------------------------------------------------------------------------------------------------------    
    # 4) ALICE verifica se a senha está correta
    # -- substitua local_HASH pelo hash calculado com a senha cadastrada e o CHALLENGE enviado por ALICE
    # -- utilize o segundo parâmetro (base64) retornado pela função calculaHASH
    # -- substitua PROVA_PARA_BOB pelo hash calculado com a senha cadastrada e o CHALLENGE enviado por BOB

    # local_HASH = senhas[user]  Todo : modifique essa linha
    local_HASH = HL.calculaHASH(senha_salgada + cs_ALICE)[1]

    # prova_para_bob = senhas[user]  Todo: modifique essa linha
    prova_para_bob = HL.calculaHASH(senha_salgada + cs_BOB)[1]

    print(f'ALICE compara local_hash={local_HASH} e prova_do_bob={prova_do_bob}')

    if prova_do_bob == local_HASH:
        resposta = 'SUCCESS'
        print(f'Este usuário é {user}')       
        msg = HL.formataMensagem([ resposta, prova_para_bob ])
        s.sendto(msg, addr )
        return user, addr 

    else:
        resposta = 'FAILURE'
        print(f'Ataque detectado: Pedido de LOGIN NEGADO!!!')
        msg = HL.formataMensagem([ resposta, 'SAI FORA, CHARLES ...' ])
        s.sendto(msg, addr )
        return None, None 
 
    

def fase2_MensagensAssinadas(user, addr):
        
    #------------------------------------------------------------------------------------------------------------
    # 5) ALICE envia uma mensagem assinada para BOB
    # -- não precisa modificar essa seção.


        if HL.ativar_MiTM:
            msg = f'Ola {user}, voce esta autenticado na Alice'
            data = HL.assinaMensagem(msg, senhas[user]) 
            s.sendto(data, addr )
        else:
            while True:
                msg = input('Digite a mensagem: ')
                data = HL.assinaMensagem(msg, senhas[user]) 
                s.sendto(data, addr )


if __name__ == "__main__":

    #------------------------------------------------------------------------------------------------------------
    # ALICE tem uma base de senhas cadastradas
    # -- ATENCAO: as senhas foram cadastradas anteriormente na Somativa1A
    # -- Copie o seu arquivo senhas.json para a pasta do projeto

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(HL.ALICE)

    print('ESTA TELA PERTENCE A ALICE')

    senhas, salts = HL.carregarSenhas()

    while True:
        user, addr = fase1_Autenticacao(senhas, salts)
        if user is not None:
            fase2_MensagensAssinadas(user, addr)

