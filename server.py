import asyncio
import socket
from datetime import datetime
from socket import AF_INET, SOCK_STREAM
from my_logs import slogger
from my_config import s_Config, c_Config, clients
from os import urandom
from random import randint
from database import ByteDictDB, commands, users_cache
import my_crypto
import time
import json




class server_class():
    def __init__(self, conf_filename="server-conf.json", clients_filename="clients.json", test_mode=False):
        self.conf_filename=conf_filename
        self.clients_filename=clients_filename
        self.read_s_conf()
        self.sock_client_binding={}
        self.clients=clients(self.clients_filename)
        self.test_mode=test_mode
        self.slogger=slogger
        self.DB=ByteDictDB('data.sqlite')
        self.commands=commands(self.DB)
        self.USERS=users_cache(self.DB)
        #self.web=web(self.conf.settings['SERVER_IP'], self.conf.settings['SERVER_PORT']-1)

    def get_status(self, category, optional="") -> list:
        try:
            if category=='clients_for_exec':
                ret=[]
                h=['Alias', 'Client Pub', 'Remote addr']
                for client_pub in self.clients.dict.keys():
                    temp=[]
                    temp.append(f'{self.clients.dict[client_pub]['alias']}')
                    temp.append(f'{client_pub.hex()}')
                    for addr in self.sock_client_binding.keys():
                        if self.sock_client_binding[addr]==client_pub:
                            temp.append(f'{addr}')
                            break
                    else:
                        temp.append('Not connected')
                    ret.append(temp)
            elif category=='users':#returns a tuple (headers, table)
                ret=[]
                h=['User', 'PC Name']
                users=self.USERS.read_all()
                for user in users:
                    temp=[]
                    temp.append(user[1])
                    temp.append(f'{self.clients.dict[user[0]]['alias']}')
                    ret.append(temp)
            elif category=='clients':#returns a tuple (headers, table)
                ret=[]
                h=['Alias', 'Pub', 'Remote addr', 'Client stats', 'Server addr']
                for client_pub in self.clients.dict.keys():
                    temp=[]
                    temp.append(f'{self.clients.dict[client_pub]['alias']}')
                    temp.append(f'{client_pub.hex()[:2]}***{client_pub.hex()[-4:]}')
                    for addr in self.sock_client_binding.keys():
                        if self.sock_client_binding[addr]==client_pub:
                            temp.append(f'{addr}')
                            break
                    else:
                        temp.append('Not connected')
                    temp_stats=''
                    if not self.clients.dict[client_pub]['temp_stats']:
                        temp_stats+='Нет данных'
                    else:
                        stats_dict=self.clients.dict[client_pub]['temp_stats']
                        try:
                            temp_stats+=f'ЦП'
                            for j in stats_dict['load_prct']:
                                temp_stats+=f' {j:.2f}'
                            
                        except:
                            temp_stats+=' err'
                        try:
                            temp_stats+=f' ПАМЯТЬ'
                            temp_stats+=f' {stats_dict['mem_usage']:.1f}%'
                        except:
                            temp_stats+=' err'
                        try:
                            temp_stats+=f' ОБНОВЛЕНО'
                            temp_stats+=f' {datetime.fromtimestamp(stats_dict['timestamp']).strftime("%H:%M")}'
                        except Exception as E:
                            temp_stats+=f' err'
                    temp.append(temp_stats)
                    temp.append(f'{self.clients.dict[client_pub]['SERVER_IP']}:{self.clients.dict[client_pub]['SERVER_PORT']}')
                    ret.append(temp)
            elif category=='tasks':
                ret=[]
                h=['', 'Client', 'Type']
                tasks=self.commands.read_many()
                task={}
                for t in tasks:
                    try:
                        temp=[]
                        temp.append(t[0].hex())
                        cli_pub=t[1]
                        try:
                            alias=self.clients.dict[cli_pub]['alias']
                        except:
                            alias=f'Client was removed or ERR'
                        temp.append(alias)
                        server_sends=json.loads(t[3])
                        task_type=list(server_sends.items())[0][1]
                        temp.append(task_type)
                        ret.append(temp)
                    except Exception as E:
                        slogger.error(f'ERR {E} in get_status tasks')
                ret.reverse()
            
            elif category=='task':
                ret=[]
                h=['Команды сервера', 'Результат выполнения']
                if optional=='':
                    ret.append('ОШИБКА в айди задания')
                    return (h, ret)
                main_key=bytearray.fromhex(optional)
                peer_pub=bytes(main_key[:-4])
                task_id=bytes(main_key[-4:])
                task=self.commands.read(peer_pub, task_id)
                left_len=len(task[0][1])
                right_len=len(task[0][2])
                max_rows=max(left_len, right_len)
                left=list(task[0][1].items())
                right=list(task[0][2].items())
                for i in range(max_rows):
                    temp=[]
                    if i>=left_len:
                        temp.append('')
                    else:
                        item=left[i]
                        text=''
                        for s in item[1]:
                            text+=s
                        temp.append(f'{datetime.fromtimestamp(float(item[0])).strftime("%m-%d %H:%M:%S")} - {text}')
                    if i>=right_len:
                        temp.append('')
                    else:
                        item=right[i]
                        text=''
                        for s in item[1]:
                            text+=s+'\n'
                        temp.append(f'{datetime.fromtimestamp(float(item[0])).strftime("%m-%d %H:%M:%S")} - {text}')
                        ret.append(temp)
                pass

                    


            return (h, ret)
        except Exception as E:
            self.slogger.error(f'ERR returning status to web {E}')
            return ([f'ERR returning status to web {E}',''],[f'ERR returning status to web {E}', ''])
    def pull_users(self):
        try:
            slogger.info(f'Pulling Users')
            for c in self.clients.dict.keys():
                if c in self.sock_client_binding.values():
                    slogger.info(f'Pulling Users from {self.clients.dict[c]['alias']}')
                    self.add_command(c, 'usrs')
        except Exception as E:
            slogger.error(f'Error pulling users {E}')
            return False
        return True

    def add_command(self, peer_pub:bytes, task_type:str, payload=b''):
        if task_type=='exec' and type(payload)==str:
            payload=bytes(payload, encoding="UTF-8")
        task_dict={
            'type':task_type,
            'payload':payload
        }
        if 'temp_tasks' not in list(self.clients.dict[peer_pub].keys()):
            self.clients.dict[peer_pub]['temp_tasks']=[]
        self.clients.dict[peer_pub]['temp_tasks'].append(task_dict)
        slogger.info(f'task appended to internal clients dict')
        pass

    def read_s_conf(self, filename=""):
        if filename!="":
            self.conf=s_Config(filename)
        else:
            self.conf=s_Config(self.conf_filename)
        self.SERVER_IP=self.conf.settings['SERVER_IP']
        self.SERVER_PORT=self.conf.settings['SERVER_PORT']
        self.BUF_SIZE=self.conf.settings['BUF_SIZE']
        self.server_public_ip=self.conf.settings['s_pub_ip']
        if self.conf.settings['priv_key']=='':
            self.s_key=my_crypto.elipt_key()
            self.conf.settings['priv_key']=self.s_key.export_secret()
        else:
            key_bytes=bytes(self.conf.settings['priv_key'])
            self.s_key=my_crypto.elipt_key(key_bytes)
        self.conf.save()

    def create_client(self, alias="", filename=""):
        temp_conf=c_Config(alias=alias, filename=filename, peer_key=self.s_key.export_public(), s_conf=self.conf)
        # self.clients.dict[temp_conf.key.export_public()]={
        #     'timestamp': time.time(),
        #     'alias': temp_conf.settings['alias'],
        #     'SERVER_IP':temp_conf.settings['SERVER_IP'],
        #     'SERVER_PORT':temp_conf.settings['SERVER_PORT']
        # }
        self.clients.dict[temp_conf.key.export_public()]['timestamp']=time.time()
        self.clients.dict[temp_conf.key.export_public()]['alias']=temp_conf.settings['alias']
        self.clients.dict[temp_conf.key.export_public()]['SERVER_IP']=temp_conf.settings['SERVER_IP']
        self.clients.dict[temp_conf.key.export_public()]['SERVER_PORT']=temp_conf.settings['SERVER_PORT']
        self.clients.save()
        return temp_conf

    async def _create_command(self, loop : asyncio.AbstractEventLoop,  sock : socket.socket, command_type:str, payload=b''):
        peer_pub=self.check_sock_pub(sock.getpeername())
        if peer_pub==None:
            slogger.error(f'Unable to send command {command_type} because peer pub not found in connected peers')
            return False
        if command_type=='echo' or command_type=='stat' or command_type=='usrs':
            s=json.dumps({time.time():command_type})
            command_id=self.commands.new(peer_pub, server_write=s)
        else:
            s=json.dumps({time.time():[str(payload, encoding="UTF-8")]})
            command_id=self.commands.new(peer_pub, server_write=s)
        
        try:
            command_bytes=bytearray(b'1')+bytearray(command_id)+bytearray(command_type, encoding="UTF-8")+bytearray(payload)
        except Exception as E:
            slogger.error(f'ERR {E} encoding command')
            return False
        status = await self.send_encrypted(loop, sock, bytes(command_bytes))
        if not status:
            self.slogger.error(f'ERR Sending {command_type}')
            return False
        return command_id

    async def parse_command_out(self, peer_pub:bytes, data:bytes) -> bool:
        data_array=bytearray(data)
        command_id=bytes(data_array[1:5])
        command_type=bytes(data_array[5:9])
        payload=bytes(data_array[9:])
        slogger.info(f'payload={payload}')
        match command_type:
            case b'usrs':
                if payload!=b'':
                    payload=str(payload, encoding='UTF-8')
                    if payload.find('ERROR')!=-1:
                        self.commands.append(peer_pub, command_id, '', json.dumps({time.time(): payload}))
                    else:
                        try:
                            usrs=json.loads(payload)
                        except Exception as E:
                            self.commands.append(peer_pub, command_id, '', json.dumps({time.time(): [f'USERS DICT decode error {E}']}))
                            slogger.error(f'USERS DICT decode error {E}')
                            return
                        self.USERS.add_host_users(peer_pub, usrs)
                        self.commands.append(peer_pub, command_id, '', json.dumps({time.time():'USERS DICT rcv success'}))
                else:
                    slogger.error(f'ERR empty payload in parse usrs reply')
            case b'stat':
                try:
                    stats=str(payload, encoding="UTF-8")
                    stats_dict=json.loads(stats)
                except Exception as E:
                    slogger.error(f'ERR loads json {E}')
                    self.commands.append(peer_pub, command_id, '', [json.dumps({time.time():f'ERR decoding string {E}'})])
                    return False
                self.commands.append(peer_pub, command_id, '', stats)
                try:
                    keys=list(stats_dict.keys())
                    self.clients.dict[peer_pub]['temp_stats']=stats_dict[keys[0]]
                except:
                    slogger.error(f'ERR saving stats')
                pass
            case b'exec':
                try:
                    strings=payload.decode()
                except Exception as E:
                    slogger.error(f'ERR decoding exec result {E}')
                    self.commands.append(peer_pub, command_id, '', {time.time():f'ERR decoding exec result {E}'})
                    return False
                self.commands.append(peer_pub, command_id, '', strings)
            case _:
                slogger.error(f'No matching case to command type')
                return False
        return True

            

    
    async def handshake(self, loop: asyncio.AbstractEventLoop, msg:bytes, sock : socket.socket):
        """ returns a [bool, Cipher, peer_pub] """
        first_lengh=81
        if len(msg)<1:
            self.slogger.error(f'Handshake message 0 lenght')
            return [False, None]
        if msg[0]!=0x0: #type of handshake message invalid
            self.slogger.error(f"Type of hadshake message is {msg[0]} and should be {0x0}")
            return [False, None]
        if len(msg)!=first_lengh:
            self.slogger.error(f"Len of handshake message is invalid: {len(msg)} but no a {first_lengh}")
        peer_pub=msg[1:65]
        if peer_pub not in self.clients.dict:
            self.slogger.error(f'Client tried to connect but he is not in server clients {peer_pub}')
            return [False, None]
        peer_random=msg[65:81]
        a,b =len(peer_pub), len(peer_random)
        message_bytes=[]
        message_bytes.append(0x0)
        message_bytes+=my_crypto.bytes_ints(self.s_key.export_public())
        message=bytes(message_bytes)
        try:
            await loop.sock_sendall(sock, message)
        except Exception as e:
            self.slogger.error(f'ERROR {e} in handshake when sending pubkey')
            return [False, None]
        try:
            random_data = await loop.sock_recv(sock, 1024)
        except Exception as e:
            self.slogger.error(f'ERROR {e} in handshake when recieving random data')
            return [False, None]
        shared=my_crypto.generate_shared_key(peer_pub, self.s_key.export_secret(), peer_random)
        Cipher=my_crypto.BlockCipherAdapter(shared[0:32], shared[33:49])
        r=Cipher.decrypt(random_data)
        r_l=list(r)
        r_l.reverse()
        self.slogger.debug(f'reversed data is {r_l}')
        r_enc=Cipher.encrypt(bytes(r_l))
        try:
            await loop.sock_sendall(sock, r_enc)
        except Exception as e:
            self.slogger.error(f'ERROR {e} in handshake when sending reversed random data')
            return [False, None]

        try:
            confirm = await loop.sock_recv(sock, 1024)
            confirm=Cipher.decrypt(confirm)
            if confirm != b'0':
                raise Exception(f'Not a valid confirm {confirm}')
            return [True, Cipher, peer_pub]
        except Exception as e:
            self.slogger.error(f'ERROR {e} in handshake when recieveving confirm')
            return [False, None]
        
    def add_sock_bind(self, addr, peer_key):
        addr_str=f'{addr[0]}:{addr[1]}'
        self.sock_client_binding[addr_str]=peer_key
    def remove_sock_bind(self, addr):
        addr_str=f'{addr[0]}:{addr[1]}'
        try:
            _ = self.sock_client_binding.pop(addr_str)
        except:
            self.slogger.error(f'Unable to remove bind from {addr_str}')
    def check_sock_pub(self, SOCK_ADDR):
        # returns a peer_pub or None
        addr_str=f'{SOCK_ADDR[0]}:{SOCK_ADDR[1]}'
        if addr_str not in self.sock_client_binding.keys():
            return None
        else:
            return self.sock_client_binding[addr_str]

    async def send_encrypted(self, loop : asyncio.AbstractEventLoop,  sock : socket.socket, data:bytes):
        data=data
        addr_to_send=sock.getpeername()
        addr_to_send=f'{addr_to_send[0]}:{addr_to_send[1]}'
        try:
            peer_pub=self.sock_client_binding[addr_to_send]
        except:
            self.slogger.error(f'Unable to send data to addr {addr_to_send} because peer pub not saved in dict. May happen if never handshake with this addr.')
            return False
        Cipher=self.clients.dict[peer_pub]['temp_cipher']
        ciphertext=Cipher.encrypt(data)
        len_of_data=len(ciphertext)+5 #здесь при вызове функции обновляются переменные для CBC даже в словаре self.clients.dict
        data=bytearray(len_of_data.to_bytes(length=5, signed=False))+bytearray(ciphertext)
        slogger.debug(f'Sended data with len {len_of_data}')
        try:
            await loop.sock_sendall(sock, data)
        except Exception as e:
            self.slogger.error(f'ERR {e} sending encrypted data to client')
            return False
        return True

    async def read_encrypted(self, loop : asyncio.AbstractEventLoop,  sock : socket.socket, nonblock=False) -> bytes:
        try:
            addr_to_send=sock.getpeername()
            addr_to_send=f'{addr_to_send[0]}:{addr_to_send[1]}'
            try:
                peer_pub=self.sock_client_binding[addr_to_send]
            except:
                self.slogger.error(f'Unable to read data from addr {addr_to_send} because peer pub not saved in dict. May happen if never handshake with this addr.')
            Cipher=self.clients.dict[peer_pub]['temp_cipher']
            data=bytearray()
            if nonblock:
                try:
                    data_first_packet = await asyncio.wait_for(loop.sock_recv(sock, 5), timeout=0.02)
                except asyncio.TimeoutError:
                    return b''
                pass
            else:
                data_first_packet = await loop.sock_recv(sock, 5)
            if data_first_packet==None or data_first_packet==b'':
                return data_first_packet
            data_len=bytearray(data_first_packet)[:5]
            data_len=int.from_bytes(data_len, signed=False)
            data+=bytearray(data_first_packet)[5:]
            if data_len>len(data_first_packet):
                data_len-=len(data_first_packet)
                while data_len>0:
                    data_packet= await loop.sock_recv(sock, min(data_len, 1024))
                    data+=bytearray(data_packet)
                    data_len-=len(data_packet)
            try:
                plaintext=Cipher.decrypt(bytes(data))
            except Exception as E:
                self.slogger.error(f'ERR decrypt {E} {data}')
                return False
            return plaintext
        except Exception as e:
            self.slogger.error(f'ERR {e} reading from client {sock.getpeername()}')
            return None

    async def handle_client(self, loop : asyncio.AbstractEventLoop, sock : socket.socket, addr: tuple):
        try:
            handshake_complete=False
            while True:
                if not handshake_complete:
                    print(f'Waiting for first handshake message')
                    msg = await loop.sock_recv(sock, self.BUF_SIZE)
                    print(f'First message recv, starting handshake from {addr[0]}:{addr[1]}')
                    returned = await self.handshake(loop, msg, sock)
                    if returned[0]:
                        current_peer_pub=returned[2]
                        self.slogger.info(f"Handshake with {addr[0]}:{addr[1]}['{current_peer_pub.hex()[:2]}***{current_peer_pub.hex()[-4:]}'] complete")
                        self.clients.dict[current_peer_pub]['temp_cipher']=returned[1]
                        self.add_sock_bind(addr, current_peer_pub)
                        handshake_complete=True
                        if 'temp_tasks' not in list(self.clients.dict[current_peer_pub].keys()):
                            self.clients.dict[current_peer_pub]['temp_tasks']=[]
                    else: #change to debug later
                        self.slogger.info(f'Handshake with {addr[0]}:{addr[1]} failed')
                        sock.close()
                        return False
                
                    echo_len=randint(1, 10000)
                    rand_data=urandom(echo_len)
                    await self._create_command(loop, sock, 'echo', rand_data)
                    reply = await self.read_encrypted(loop, sock)
                    if reply==False:
                        slogger.error(f'Cipher was unable to decrypt')
                    if reply!=None:
                        replied_array=bytearray(reply)
                        replied_data=replied_array[9:]
                        if replied_data==bytearray(rand_data):
                            slogger.info('Echo test complete')
                        else:
                            slogger.error('Echo test failed')

                    if self.test_mode:
                        #await self._create_command(loop, sock, 'exec', 'ping 8.8.8.8'.encode())
                        pass

                    await self._create_command(loop, sock, 'stat')
                    recent_stats_requested=time.time()
                    self.slogger.info(f'Sended stats command')

                if handshake_complete:
                    msg=await self.read_encrypted(loop, sock, True)
                    print(f'Server is ticking {time.time()}', flush=True, end='\r')
                    if msg==False:
                        slogger.error(f'Cipher was unable to decrypt')
                        return
                    if msg==None:
                        break
                    if len(msg)>1:
                        if msg[0]==b'2'[0]:
                            slogger.debug(f'Parsing command reply')
                            peer_pub=self.check_sock_pub(sock.getpeername())
                            success = await self.parse_command_out(peer_pub, msg)
                    if len(self.clients.dict[current_peer_pub]['temp_tasks'])>0: #Чек если есть таски для клиента
                        task=self.clients.dict[current_peer_pub]['temp_tasks'][0]
                        id=await self._create_command(loop, sock, task['type'], task['payload'])
                        slogger.info(f'Sending task {id} {task} to client')
                        self.clients.dict[current_peer_pub]['temp_tasks'].pop(0)
                    if self.clients.dict[current_peer_pub]['temp_stats']:
                        current_time=time.time()
                        if current_time - recent_stats_requested>30.0:
                            recent_stats_requested=current_time
                            print('Added stat by timeout')
                            self.add_command(current_peer_pub, 'stat')

                    
                if msg==b'': #типа тут мы подвисаем если данных нет
                    pass
                if msg==None:
                    print('msg was None. Breaking')
                    handshake_complete=False
                    break
                self.slogger.debug(f"recv {msg}")


        finally:
            handshake_complete=False
            self.slogger.info(f'Client disconnected')
            self.remove_sock_bind(sock.getpeername())
            sock.close()

    def listen_for_connections(self):
        loop=asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        mainsock = socket.socket(AF_INET, SOCK_STREAM)
        #mainsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            mainsock.bind((self.SERVER_IP, self.SERVER_PORT))
            self.slogger.info(f"Server listening at {self.SERVER_IP}:{self.SERVER_PORT}")
        except Exception as e:
            self.slogger.fatal(f"Failed to bind to {self.SERVER_IP}:{self.SERVER_PORT} ERR: {e}")
        mainsock.listen()
        mainsock.setblocking(False)

        async def server_loop():
            while True:
                client_sock, addr = await loop.sock_accept(mainsock)
                loop.create_task(self.handle_client(loop, client_sock, addr))
        try:
            loop.run_until_complete(server_loop())
        finally:
            loop.close()


if __name__ == "__main__":
    server=server_class(test_mode=True)
    server.create_client(filename="./clients/testing_client.json")
    server.listen_for_connections()


#message types
#SERVER>CLI
#0 handshake
#1 Command to client 1[4bytes ID][4 bytes COMMAND NAME][Payload]
#2 Reply to command 2[4bytes ID][4 bytes COMMAND NAME][Payload]

#CLI>SERVER
#0 handshake
#1 Command to server 1[4bytes ID][4 bytes COMMAND NAME][Payload]
#2 Reply to command  2[4bytes ID][4 bytes COMMAND NAME][Payload]
