# ESSA BIBLIOTECA É USADA PARA DEMONSTRAR O MECANISMO SCRAM
# SCRAM: SALTED CHALLENGE RESPONSE MECHANISM

import hashlib
import hmac
import os
from base64 import b64encode, b64decode
import json


CHARLES = ('127.0.0.1', 9998)
ALICE = ('127.0.0.1', 9999)

# Após completar os códigos de ALICE e BOB altere ativar_MiTM para True para fazer o ataque de REPETIÇÃO (REPLAY)
# -- Quando ativar o MiTM, você deve executar os programas nessa ordem: CHARLES, ALICE e BOB por último.
ativar_MiTM = False

if ativar_MiTM:
    print('Este cenário está usando MiTM, o cliente está falando com um servidor falso')
else:
    print('Este cenário não tem MiTM, o cliente está falando diretamente com o servidor')



def calculaHASH(msg:str):
    '''
    Calcula o hash de uma string   

    Parameters:
    msg : str (string que será calculado o hash)

    Output:
    tuple: bytes, str
    '''
    m = hashlib.md5()
    m.update(msg.encode())
    return m.digest(), m.hexdigest() 

def geraNonce(tamanho : int):
    '''
    Gera um nonce com tamanho definido em bits

    Parameters:
    tamanho : int (quantidade de bits do nonce)

    Output:
    tuple: bytes, base64
    '''
    embytes = int(tamanho/8)
    nonce = os.urandom(embytes)
    nonceB64 = b64encode(nonce)
    return nonce, nonceB64

def separaMensagem(mensagem : bytes, separador='\n'):
    '''
    Separa em componentes uma mensagem recebida pela rede (em bytes) usando \\n como separador (default)

    Parameters:
    mensagem : bytes (mensagem recebida pela rede)
    separador : str (caractere usado como separador - \\n por default)

    Output:
    list : lista de componentes da mensagem em formato string
    '''    
    msg = mensagem.decode()
    return msg.split('\n')

def formataMensagem(componentes : list, separador='\n'):
    '''
    Junta os componentes de uma mensagem usando \\n como separador (default)

    Parameters:
    componentes : lista (lista de componentes em formato string)
    separador : str (caractere usado como separador - \\n por default)

    Output:
    bytes: mensagem formatada para ser transmitida pela rede
    '''  
    mensagem = "\n".join(componentes)
    return mensagem.encode()

def assinaMensagem(mensagem : str, segredo : str):
    '''
    Cria uma mensagem assinada com HMAC

    Parameters:
    mensagem : str (mensagem que será assinada)
    segredo : str (segredo usado para criar o HMAC)

    Output:
    bytes: mensagem formatada, com assinatura HMAC, pronta para ser transmitida pela rede
    '''  
    meuHMAC = hmac.HMAC(segredo.encode(), mensagem.encode(), hashlib.md5 )
    digest = meuHMAC.hexdigest() # esse resultado e uma string
    return formataMensagem(['HMAC', mensagem, digest])



def verificaMensagem(data : bytes, segredo : str):
    '''
    Verifica uma mensagem assinada com HMAC recebida pela rede

    Parameters:
    data : bytes (mensagem assinada com HMAC recebida pela rede)
    segredo : str (segredo usado para verificar o HMAC)

    Output:
    bool: True se o HMAC verificar a mensagem corretamente caso contrário False
    ''' 
    tipo, mensagem, digest = separaMensagem(data)   
    if tipo != 'HMAC': raise Exception('MENSAGEM INVÁLIDA')

    meuHMAC = hmac.HMAC(segredo.encode(), mensagem.encode(), hashlib.md5 )
    localdigest = meuHMAC.hexdigest()

    if digest == localdigest:
        return True
    else:
        return False

def carregarSenhas():
    '''
    Carrega o arquivo com as senhas e os salts 
    - retorna dicionários vazios caso o arquivo não exista ou esteja corrompido

    Output: 
    tuple: (senhas, salt) dicionários com os dados de autenticação do usuário
    '''

    nome_arquivo = 'senhas.json'
    if os.path.exists(nome_arquivo):    
        with open(nome_arquivo, "r") as arquivo:
            dados = json.load(arquivo)
        
        if 'senhas' in dados and 'salts' in dados:
            return dados['senhas'], dados['salts']
        else:
            print('arquivo de senhas corrompido')
    
    return {}, {}


def salvarSenhas(senhas: dict, salts: dict):
    '''
    Salva os dicionários com dados de autenticação

    Paramenters: 
    senhas: dicionário com as senhas (salgadas) do usuário
    salts: dicionário com os salts (nonce) dos usuários
    
    '''

    nome_arquivo = 'senhas.json'
    with open(nome_arquivo, "w") as arquivo_json:
        json.dump({'senhas' : senhas, 'salts' : salts}, arquivo_json, indent=4) 


    

# Use essa porção do código para testar as funções da biblioteca

if __name__ == "__main__":
   
    hash, strhash = calculaHASH('segredo')
    cs, cs64 = geraNonce(128)

    hash_bytes, hash_string = calculaHASH('segredo' + cs64.decode())
    print(hash_string)

    print(formataMensagem(['HELLO','BOB']))

    print(separaMensagem(b'HELLO\nBOB'))

    msgassinada = assinaMensagem('teste','segredo')

    print(verificaMensagem(msgassinada, 'segredo'))
    print(verificaMensagem(msgassinada, 'nao sei o segredo'))



