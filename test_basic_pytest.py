from server import server_class
from client import client_class
from multiprocessing import Process, active_children, Queue
import threading
import os
import random
from my_crypto import elipt_key, generate_shared_key, BlockCipherAdapter, mult_P_k
import my_crypto
import my_config
import asyncio

SERVER_IP="127.0.0.1"
SERVER_PORT=51237
BUFSIZE=1024

test_serv_conf="test_s_conf.json"


def old_client_says_hi():
    
    serv=server_class(test_serv_conf)
    client=client_class(BUFSIZE, SERVER_IP, SERVER_PORT)

    # t = threading.Thread(target=serv.listen_for_connections, daemon=True)
    # t.start() 
    p = Process(target=serv.listen_for_connections)
    p.daemon=True
    p.start()

    for i in range(10):
        n=random.randint(1, 1024)
        data = os.urandom(n)
        assert client.test_connect(data)

    p.kill()

def worker(func, q : Queue, *args):
    q.put(func(*args))

def async_worker(func, q, *args):
    q.put(asyncio.run(func(*args)))


def old_much_clients_says_hi():
    N=20 #clients

    serv=server_class(test_serv_conf)
    p = Process(target=serv.listen_for_connections)
    p.daemon=True
    p.start()
    q=Queue()

    CLIENTS, PROCS=[], []

    for i in range(N):
        CLIENTS.append(client_class(BUFSIZE, SERVER_IP, SERVER_PORT))
        n=random.randint(1, 1024)
        data = os.urandom(n)
        PROCS.append(Process(target=worker, args=(CLIENTS[i].test_connect, q, data)))
        PROCS[i].start()
    
    for i in range(N):
        PROCS[i].join()
        result=q.get()
        assert result == True
        PROCS[i].kill()
    
    p.kill()

def test_shared_keys_gen():
    mem={}
    num=100
    percent=num//100
    for i in range(num):
        if i%percent==0:
            print(f'\rcalculating {i}/{num}. {str(i/num)[:4]}', flush=True, end="")
        test1=elipt_key() #клиент
        test2=elipt_key() #сервер
        rand_r=int.from_bytes(os.urandom(31))
        p_r=test1.mul_pub_int(rand_r)
        
        y=my_crypto.cv.y_recover(int.from_bytes(test2.export_public()))
        serv_pub_point=my_crypto.Point(int.from_bytes(test2.export_public()), y, my_crypto.cv)

        key_server=mult_P_k(p_r, test2.s_key)
        key_client=mult_P_k(my_crypto.cv.encode_point(serv_pub_point), test1.s_key*rand_r)
        if key_server!=key_client:
            raise Exception("shared keys dont match")
        if key_server in mem:
            raise "Keys not a randoms"
        mem[key_server]=i

def old_test_shared_keys_gen():
    mem={}
    num=100
    percent=num//100
    for i in range(num):
        if i%percent==0:
            print(f'\rcalculating {i}/{num}. {str(i/num)[:4]}', flush=True, end="")
        test1=elipt_key()
        test2=elipt_key()
        rand=os.urandom(16)
        key1=generate_shared_key(test1.export_public(), test2.export_secret(), rand)
        key2=generate_shared_key(test2.export_public(), test1.export_secret(), rand) 
        if key1!=key2:
            raise Exception("shared keys dont match")
        if key1 in mem:
            raise "Keys not a randoms"
        mem[key1]=i

def test_c_config_import_export():
    num=100
    filename='test.json'
    server_conf=my_config.s_Config('test_s_conf.json')
    if os.path.isfile(filename):
        os.remove(filename)
    for i in range(num):
        s_key=elipt_key()
        conf=my_config.c_Config(filename=filename, peer_key=s_key.export_public(), s_conf=server_conf)
        sec_conf=my_config.c_Config(filename=filename)
        
        assert conf.settings==sec_conf.settings #checs that conf saves and imports correctly
        #assert generate_shared_key()
        print(sec_conf.export_to_str())
        try:
            os.remove(filename)
        except:
            print("not removed a config")

def test_Cipher():
    num=1000
    percent=num//100
    for i in range(10):
        key1=elipt_key()
        key2=elipt_key()
        random_seed=os.urandom(16)
        shared1=generate_shared_key(key1.export_public(), key2.export_secret(), random_seed)
        shared2=generate_shared_key(key2.export_public(), key1.export_secret(), random_seed)
        assert shared1==shared2
        Cipher1=BlockCipherAdapter(shared1[0:32], shared1[33:49])
        Cipher2=BlockCipherAdapter(shared2[0:32], shared2[33:49])
        for j in range(num//10):
            if j%percent==0:
                print(f'\rcalculating ciphers {i*100+j}/{num}. {str((i*100+j)/num)[:4]}', flush=True, end="")
            len=random.randint(1, 1024)
            random_data=os.urandom(len)
            ciphertext=Cipher1.encrypt(random_data)
            plaintext=Cipher2.decrypt(ciphertext)
            assert random_data==plaintext

def serv_worker(N):
    serv=server_class(test_serv_conf)
    for i in range(N):
        c_conf=serv.create_client(filename=f'./clients/test/{i}.json')
    serv.listen_for_connections()

def old_test_handshake(): #because read write test making handshake too
    N=10 #clients
    CONFIGS=[]
    for i in range(N):
        CONFIGS.append(f'./clients/test/{i}.json')

    p = Process(target=serv_worker, args=(N))
    p.daemon=True
    p.start()
    q=Queue()

    CLIENTS, PROCS=[], []

    for i in range(N):
        CLIENTS.append(client_class(CONFIGS[i], test_mode=True))
        n=random.randint(1, 1024)
        data = os.urandom(n)
        PROCS.append(Process(target=async_worker, args=(CLIENTS[i].client_loop, q)))
        PROCS[i].start()
    


    for i in range(N):
        PROCS[i].join()
        result=q.get()
        assert result == True
        PROCS[i].kill()
    
    p.kill()

def old_test_sends_reads():
    N=10 #clients
    CONFIGS=[]
    for i in range(N):
        CONFIGS.append(f'./clients/test/{i}.json')

    p = threading.Thread(target=serv_worker, args=(N,))
    p.daemon=True
    p.start()
    q=Queue()

    CLIENTS, PROCS=[], []

    for i in range(N):
        CLIENTS.append(client_class(CONFIGS[i], test_mode=True))
        n=random.randint(1, 1024)
        data = os.urandom(n)
        PROCS.append(Process(target=async_worker, args=(CLIENTS[i].client_loop, q)))
        PROCS[i].start()
    
    for i in range(N):
        PROCS[i].join()
        result=q.get()
        assert result == True
        PROCS[i].kill()

if __name__=="__main__":
    pass