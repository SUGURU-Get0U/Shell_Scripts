import socket
import MyHashLib as HL


def cria_usuario(user, user_addr):

    global senhas, salts

    #------------------------------------------------------------------------------------------------------------
    # 1) ALICE envia um novo SALT para o USUARIO remoto
    # -- gere o SALT no formato base64 usando a chamada geraNonce da HASHLIB
    # -- observe que geraNonce retorna uma tupla com dois parâmetros
    # -- o SALT é o segundo parâmetro (base64) e precisa ser convertido para string com decode()

    _, salt_bytes = HL.geraNonce(128)   # geraNonce retorna (bytes, base64)
    salt = salt_bytes.decode()          # converte base64 -> str para poder transmitir

    # -- SALGAR_SENHA é o nome da mensagem e salt é o parâmetro 
    data = HL.formataMensagem(['SALGAR_SENHA', salt])
    s.sendto(data, user_addr)


    #------------------------------------------------------------------------------------------------------------
    #  2) ALICE recebe a SENHA_SALGADA e salva no arquivo JSON
    # -- não precisa modificar essa seção.

    # mensagem esperada: ['SENHA_SALGADA', 'HASH_DA_SENHA_COM_O_SALT' ]
    data, addr = s.recvfrom(1024) 
    print('RECEBI: ', data)

    if addr != user_addr:
        print('mensagem de origem desconhecida')
        return False

    msg = HL.separaMensagem(data) 

    if len(msg) < 2 or msg[0] != 'SENHA_SALGADA': 
        print('recebi uma mensagem inválida')
        return False
    else:
        senha_salgada = msg[1]
        
    senhas[user] = senha_salgada
    salts[user] = salt

    HL.salvarSenhas(senhas, salts)  # Salva o novo usuário no arquivo JSON

    resposta = 'SUCCESS' 
    print(f'USUARIO {user} cadastrado com SUCESSO ...')
    msg = HL.formataMensagem([resposta, f'Prezado {user}, faça novo login para testar sua senha!'])
    s.sendto(msg, addr)
    return True 


def autentica_usuario(user, user_addr):

    global senhas, salts

    #------------------------------------------------------------------------------------------------------------    
    # 3) ALICE envia o SALT previamente cadastrado
    # -- utilize o SALT que está cadastrado no dicionário

    salt = salts[user]   # busca o salt já gerado no cadastro deste usuário

    # -- SALGAR_SENHA é o nome da mensagem e salt é o parâmetro 
    data = HL.formataMensagem(['SALGAR_SENHA', salt])
    s.sendto(data, user_addr)
    

    #------------------------------------------------------------------------------------------------------------    
    # 4) ALICE verifica se a senha está correta        
    # -- alice compara a SENHA_SALGADA com a senha salva no dicionário
    # -- não precisa modificar esta seção
    
    # mensagem esperada: ['SENHA_SALGADA', 'HASH_DA_SENHA_COM_O_SALT' ]    
        
    try:
        s.settimeout(5)
        data, addr = s.recvfrom(1024) 
        print('RECEBI: ', data)
        s.settimeout(None)
    except:
        print('Autenticacao abortada: usuario não respondeu')
        s.settimeout(None)
        return


    if addr != user_addr:
        print('mensagem de origem desconhecida')
        return False

    msg = HL.separaMensagem(data) 

    if len(msg) < 2 or msg[0] != 'SENHA_SALGADA': 
        print('recebi uma mensagem inválida')
        return False
    else:
        senha_salgada = msg[1]

    senha_cadastrada = senhas[user] 

    if senha_salgada == senha_cadastrada:
        resposta = 'SUCCESS' 
        print(f'USUARIO {user} autenticado com SUCESSO ...')
        msg = HL.formataMensagem([resposta, f'Prezado {user}, bem vindo ao SERVIDOR ALICE!'])
        s.sendto(msg, addr)
        return True 

    else:
        resposta = 'FAILURE'
        print(f'Ataque detectado: Pedido de LOGIN NEGADO!!!')
        msg = HL.formataMensagem([resposta, 'SAI FORA, CHARLES ...'])
        s.sendto(msg, addr)
        return False 
 
    

if __name__ == "__main__":

    #------------------------------------------------------------------------------------------------------------
    #  ALICE irá criar uma base de usuários e senhas cadastradas
    # -- Utilize o conceito de senha salgada para esconder as senhas dos usuários

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(HL.ALICE)

    print('ESTA TELA PERTENCE A ALICE')

    senhas, salts = HL.carregarSenhas()


    #------------------------------------------------------------------------------------------------------------
    # ALICE AGUARDA UM PEDIDO DE LOGIN
    # -- não precisa modificar essa seção

    while True:
        print('Aguardando solicitação de LOGIN ...')
        
        data, addr = s.recvfrom(1024) 
        print('RECEBI: ', data)
        msg = HL.separaMensagem(data)  # mensagem esperada: [ 'HELLO', 'LOGIN_DO_USUARIO' ]

        if len(msg) < 2 or msg[0] != 'HELLO': 
            print('recebi uma mensagem inválida')
            continue
        else:
            user = msg[1]
            user_addr = addr
            if user not in senhas.keys():
                print('Usuario novo')
                cria_usuario(user, user_addr)
            else:
                print('Usuario cadastrado')
                autentica_usuario(user, user_addr)