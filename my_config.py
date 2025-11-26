import my_crypto
import time
from json import load, dump, dumps, loads
from os import path
from hashlib import sha256

class clients():
    def __init__(self, filename="clients.json"):
        self.dict={}
        self.filename=filename
        if path.isfile(filename):
            try:
                f=open(filename, 'r')
                dict=load(f)
                f.close()
                temp={}
                for key in dict:
                    temp[bytes.fromhex(key)]=dict[key]
                    temp[bytes.fromhex(key)]['temp_stats']=False #Default value for temp option
                self.dict=temp.copy()
            except Exception as e:
                print(f"Unsuccess import clients {e}")

    def save(self):
        with open(self.filename, 'w') as f:
            temp_all_clients={}
            for key in self.dict:
                temp={}
                for subkey in self.dict[key]:
                    if str(subkey).find('temp')!=-1:
                        pass #скипаем ключи где есть темп слово
                    else:
                        temp[subkey]=self.dict[key][subkey]
                temp_all_clients[key.hex()]=temp #ТК ключ словаря это байтс
            dump(temp_all_clients, f, indent=4)
        f.close()


s_default={ 
    'SERVER_PORT': 51235,
    'SERVER_WEB_PORT':51234,
    'SERVER_WEB_IP':"0.0.0.0",
    'SERVER_IP': "0.0.0.0",
    's_pub_ip': "127.0.0.1",
    'BUF_SIZE': 1024,
    'priv_key': ""
}

c_default={
    'SERVER_PORT': 51235,
    's_pub_ip': "127.0.0.1",
    'priv_key':"",
    'alias': "",
    'peer_key':""
}

class s_Config():
    def __init__(self, filename="control_server.json") -> None:
        self.ready=False
        self.def_settings=s_default
        self.settings={}
        self.filename=filename
        self.tpm_recovery=False
        try:
            tpm_config=open('tpm.json', "r")
            self.tpm_config=load(tpm_config)
            tpm_config.close()
            if self.tpm_config['recovery-key']!='':
                self.tpm_key=bytes.fromhex(self.tpm_config['recovery-key'])
                self.tpm_recovery=True
            else:
                if self.check_tpm():
                    from tpm_support import my_tpm
                    self._tpm=my_tpm(tpm_config['path'])
                    try:
                        self.tpm_key=self._tpm.read()[0]
                    except:
                        raise Exception(f'Config was unable to read tpm key from {tpm_config['path']}')
                else:
                    raise Exception(f'Поддержки TPM нет, но конфигурации tpm не содержит recovery ключа')
            self.tpm_cipher=my_crypto.BlockCipherAdapter(self.tpm_key, b'')
            self.tpm_active=True
        except Exception as E:
            print(f'Возникла неизвестная ошибка при попытке прочитать TPM конфиг {E}')
            self.tpm_active=False

        try:
            settings_file=open(self.filename, "rb")
            if self.tpm_active:
                settings_file_data=self.tpm_cipher.decrypt(settings_file.read())
            else:
                settings_file_data=settings_file.read()
            self.settings=loads(settings_file_data.decode())
            settings_file.close()
        except:
            out_settings=open(self.filename, "w")
            dump(self.def_settings, out_settings, indent=4)
            out_settings.close()
            settings_file=open(self.filename, "r")
            self.settings=load(settings_file)
            settings_file.close()
        if self.def_settings.keys()!=self.settings.keys():
            self.load_old()
        self.set_fixing()
    
    def check_tpm(self):
        try:
            from tpm_support import my_tpm
            test=my_tpm()
            return True
        except:
            return False

    def init_tpm(self, path="/nv/Owner/system_key"):
        if self.tpm_active:
            return False, 'Ошибка, tpm уже инициализирован'
        if not self.check_tpm:
            return False, 'Ошибка, tpm не поддерживается'
        from tpm_support import my_tpm
        print('Инициальзация tpm')
        self._tpm=my_tpm()
        print('Генерация секрета')
        key=my_crypto.urandom(8)
        reserve_key=key.hex(sep='-', bytes_per_sep=4)
        key=bytes.fromhex(sha256(key).hexdigest)
        print(f'Ваш резервный ключ: {reserve_key}')
        self._tpm.save(key)
        self.tpm_cipher=my_crypto.BlockCipherAdapter(key, b'')
        print(f'Шифр создан, сохраняю файл описания')
        with open('tpm.json', 'r') as f:
            conf={
                'path':path,
                'recovery-key':""
            }
            dump(conf, f)
        print(f'Сохраняю зашифрованный конфиг.')
        self.save()
        return True, reserve_key


    def gen_keys(self):
        key=my_crypto.elipt_key()
        return key

    def set_fixing(self):
        try:
            if self.settings['chached_settings']['need_replaces'].type()==list():
                temp=self.settings['chached_settings']['need_replaces']
                self.settings['chached_settings']['need_replaces']=set()
                self.settings['chached_settings']['need_replaces'].add(temp)
        except:
            pass

    def fix_set_saving_and_bytes(self):
        #print('debug')
        temp=self.settings.copy()
        for key in temp.keys():
            if type(temp[key])==type(b''):
                temp[key]=[int(b) for b in temp[key]]
        try:
            temp['chached_settings']['need_replaces']=list(self.settings['chached_settings']['need_replaces'])
        except:
            pass
        return temp
    
    def load_old(self): #migration from older settings version
        temp={}
        for key in self.def_settings.keys():
            #print(key)
            try:
                temp[key]=self.settings[key]
            except:
                #print(key, "except")
                temp[key]=self.def_settings[key]
        self.settings=temp

    def save(self, filename="-1"):
        if filename=="-1":
            filename=self.filename
        try:
            out_settings=open(self.filename, "wb")
            plain_data=dumps(self.fix_set_saving_and_bytes(), indent=4)
            plain_data=plain_data.encode()
            if self.tpm_active and not self.tpm_recovery:
                self.tpm_cipher=my_crypto.BlockCipherAdapter(self.tpm_key, b'')
                data=self.tpm_cipher.encrypt(plain_data)
            else:
                data=plain_data
            out_settings.write(data)
            out_settings.close()
        except Exception as E:
            print(f"Error {E} while dumping server settings")

class c_Config():
    def __init__(self, alias="", filename="", peer_key=b'', s_conf="") -> None:
        self.ready=False
        self.def_settings=c_default
        self.settings={}
        if filename=="" or path.isfile(filename)==False: #if no filename given we will not try to import from filename
            if type(s_conf)!=s_Config:
                raise Exception("You must specify server config when create new client")
            print("Creating new client config")
            self.create_new(filename, peer_key, alias, s_conf)
        else:
            self.filename=filename
            try:
                settings_file=open(self.filename, "r")
                self.settings=load(settings_file)
                settings_file.close()
            except Exception as e:
                print(f"ERROR {e} opening settings file {self.filename}")
            self.key=my_crypto.elipt_key(self.settings['priv_key'])
        # if self.def_settings.keys()!=self.settings.keys():
        #     self.load_old()
        self.set_fixing()
    
    def export_b64(self) -> str:
        from base64 import b64encode
        b64=b64encode(dumps(self.fix_set_saving_and_bytes()).encode())
        s=b64.decode('ascii')
        return s

    def create_new(self, filename, peer_key, alias, s_conf:s_Config):
        if peer_key==b'':
            raise Exception("You must specify peer pub key if you dont import settings")
        ftime=time.strftime("%d-%m-%y %H-%M", time.struct_time(time.localtime()))
        self.key=self.gen_keys()
        pub_key=self.key.export_public()
        pub_key=hex(pub_key[-1])[2:]
        if filename=="":
            self.filename=f"clients/Client-{alias}{pub_key}-{ftime}.json"
        else:
            self.filename=filename
        if alias=="":
            self.settings['alias']=f"Client-{pub_key} at {ftime}"
        else:
            self.settings['alias']=alias
        self.settings['priv_key']=self.key.export_secret()
        self.settings['peer_key']=peer_key
        self.settings['SERVER_IP']=s_conf.settings['s_pub_ip']
        self.settings['SERVER_PORT']=s_conf.settings['SERVER_PORT']
        self.save()

    def gen_keys(self):
        key=my_crypto.elipt_key()
        return key

    def set_fixing(self):
        try:
            # if self.settings['chached_settings']['need_replaces'].type()==list():
            #     temp=self.settings['chached_settings']['need_replaces']
            #     self.settings['chached_settings']['need_replaces']=set()
            #     self.settings['chached_settings']['need_replaces'].add(temp)
            if type(self.settings['priv_key'])!=bytes:
                self.settings['priv_key']=bytes(self.settings['priv_key'])
            if type(self.settings['peer_key'])!=bytes:
                self.settings['peer_key']=bytes(self.settings['peer_key'])
        except:
            pass

    def fix_set_saving_and_bytes(self):
        #print('debug')
        temp=self.settings.copy()
        for key in temp.keys():
            if type(temp[key])==type(b''):
                temp[key]=[int(b) for b in temp[key]]
        try:
            temp['chached_settings']['need_replaces']=list(self.settings['chached_settings']['need_replaces'])
        except:
            pass
        return temp
    
    def load_old(self): #migration from older settings version
        temp={}
        for key in self.def_settings.keys():
            #print(key)
            try:
                temp[key]=self.settings[key]
            except:
                #print(key, "except")
                temp[key]=self.def_settings[key]
        self.settings=temp

    def save(self, filename="-1"):
        if filename=="-1":
            filename=self.filename
        try:
            out_settings=open(self.filename, "w")
            dump(self.fix_set_saving_and_bytes(), out_settings, indent=4)
            out_settings.close()
        except Exception as E:
            print(f"Error {E} While dumping client settings")

    def export_to_str(self):
        return dumps(self.fix_set_saving_and_bytes())

    
if __name__=="__main__":
    key=my_crypto.urandom(8)
    reserve_key=key.hex(sep='-', bytes_per_sep=4)
    key=sha256(key).hexdigest()
    key=bytes.fromhex(key)
    print(key)

