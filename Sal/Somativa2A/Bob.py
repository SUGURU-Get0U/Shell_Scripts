import socket
import MyHashLib as HL
import time

def salgar_senha(login, senha):

    #------------------------------------------------------------------------------------------------------------
    # 1) BOB ENVIA UM HELLO PARA ALICE
    # -- não precisa modificar essa seção.

    msg = HL.formataMensagem(['HELLO', login])
    s.sendto(msg, ALICE)

    #------------------------------------------------------------------------------------------------------------
    # 2) BOB RECEBE UM SALT    
    # -- não precisa modificar essa seção.
    try:
        data, addr = s.recvfrom(1024) 
    except:
        print('Alice não está sendo executada: aguardando 10 segundos ...')
        time.sleep(10)
        return False

    print('RECEBI: ', data)

    msg = HL.separaMensagem(data) 
    if len(msg) < 1 or msg[0] != "SALGAR_SENHA": 
        print('recebi uma mensagem inválida')
        return False

    salt = msg[1]

    #------------------------------------------------------------------------------------------------------------
    # 3) BOB gera a SENHA_SALGADA e transmite para alice    
    # -- calcule a senha salgada fazendo um HASH da senha com o salt recebido.
    # -- utilize a função calculaHASH da biblioteca. 
    # -- utilize o segundo parâmetro (str) retornado pela biblioteca
    # -- concatene a senha com o salt usando '+', mas ambos precisam ser string.

    _, senha_salgada = HL.calculaHASH(senha + salt)   # hash(senha + salt), pega a string hexadecimal

    msg = HL.formataMensagem(['SENHA_SALGADA', senha_salgada])
    s.sendto(msg, ALICE)


    #------------------------------------------------------------------------------------------------------------
    # 4) BOB recebe o resultado da autenticação e a prova enviada por ALICE
    # -- não precisa modificar essa seção.

    data, addr = s.recvfrom(1024)
    print('RECEBI: ', data)
    msg = HL.separaMensagem(data) 
    resultado = msg[0]
    mensagem = msg[1]

    print('Resultado da autenticação: ', resultado)
    print('Mensagem recebida: ', mensagem)


        
if __name__ == "__main__":

    ALICE = HL.CHARLES if HL.ativar_MiTM else HL.ALICE

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while True:
        login = input('digite seu LOGIN: ')
        senha = input('digite sua SENHA: ')
        salgar_senha(login, senha)