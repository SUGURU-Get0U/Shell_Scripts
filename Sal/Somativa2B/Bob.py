import socket
import MyHashLib as HL
import time



def fase1_Autenticacao():
    global s

    login = input('digite seu LOGIN: ')
    senha = input('digite sua SENHA: ')

#------------------------------------------------------------------------------------------------------------
# 1) BOB ENVIA UM HELLO PARA ALICE
# -- não precisa modificar essa seção.

    msg = HL.formataMensagem(['HELLO', login])
    s.sendto( msg, ALICE )  

#------------------------------------------------------------------------------------------------------------
# 2) BOB RECEBE UM CHALLENGE    
# -- não precisa modificar essa seção.
    try:
        data, addr = s.recvfrom(1024) 
    except:
        print('Alice não está sendo executada: aguardando 10 segundos ...')
        time.sleep(10)
        return False

    print('RECEBI: ', data)

    msg = HL.separaMensagem(data) 
    if len(msg) < 2 or msg[0] != "CHALLENGE": 
        print('recebi uma mensagem inválida')
        return False

    cs_ALICE = msg[1]
    salt = msg[2]

#------------------------------------------------------------------------------------------------------------
# 3) BOB responde ao CHALLENGE com um novo CHALLENGE e o HASH da sua senha 
# - calcule a senha salgada fazendo um HASH da senha com o SALT recebido usando calculaHASH (use o segundo valor retornado)  
# - determine o challenge do BOB trocando NONCE usnado a função geraNonce()
# -- o challenge é o segundo valor retornado convertido para string com .decode()        
# -- determine a prova_para_ALICE de forma similar a senha salgada, mas usando senha_salgada + cs_ALICE

    # senha_salgada = senha # todo: modifique essa linha
    senha_salgada = HL.calculaHASH(senha + salt)[1]

    # cs_BOB = 'NONCE' # TODO: modifique essa linha
    cs_BOB = HL.geraNonce(128)[1].decode()

    # prova_para_ALICE = senha # Todo modifique essa linha
    prova_para_ALICE = HL.calculaHASH(senha_salgada + cs_ALICE)[1]
    

    data = HL.formataMensagem(['CHALLENGE_RESPONSE', cs_BOB, prova_para_ALICE ]) 

    s.sendto(data, addr )

#------------------------------------------------------------------------------------------------------------
# 4) BOB recebe o resultado da autenticaçao e a prova enviada por ALICE
# -- não precisa modificar essa seção.

    data, addr = s.recvfrom(1024)
    print('RECEBI: ', data)
    msg = HL.separaMensagem(data) 
    resultado = msg[0]
    prova_da_alice = msg[1]


#------------------------------------------------------------------------------------------------------------
# 5) BOB se a senha está correta
# - calcule o local_hash fazendo um hash da string formada pela senha_salgada e o challenge gerado por Bob
# -- o local_hash é o segundo valor retornado pela função calculaHASH
    
    # local_hash = senha_salgada # Todo: modifique essa linha
    local_hash = HL.calculaHASH(senha_salgada + cs_BOB)[1]

    print(f'BOB compara local_hash={local_hash} e prova_da_Alice={prova_da_alice}')
    if resultado == 'SUCCESS' and local_hash == prova_da_alice:
        print('Este servidor é ALICE')
        return senha_salgada
    else:
        print('Este servidor não é ALICE')
        return None

def fase2_MensagensAssinadas(senha_salgada):
    #------------------------------------------------------------------------------------------------------------    
    # 6) BOB recebe uma mensagem autenticada de ALICE
    # -- não precisa modificar essa seção
        
        print('Aguardando mensagens do Servidor')

        while True:
            data, addr = s.recvfrom(1024)
            print('RECEBI: ', data)

            msg = HL.separaMensagem(data) 
            if msg[0] == 'HMAC':
                resultado = HL.verificaMensagem(data, senha_salgada) 
                if resultado: 
                    print('Mensagem válida')
                else:
                    print('Mensagem inválida')

        
if __name__ == "__main__":

    ALICE = HL.CHARLES if HL.ativar_MiTM else HL.ALICE
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while True:
        senha_salgada = fase1_Autenticacao()
        if senha_salgada is not None:
            fase2_MensagensAssinadas(senha_salgada)

