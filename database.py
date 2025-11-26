import sqlite3
import json


class ByteDictDB:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path)
        self.read_only = sqlite3.connect(path, check_same_thread=False)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS commands (
                main_key BLOB PRIMARY KEY,
                peer_pub BLOB,
                command_id INTEGER,
                serv_write TEXT,
                serv_read TEXT
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS usrs (
                peer_pub BLOB,
                username TEXT,
                password TEXT,
                no_login INTEGER,
                PRIMARY KEY (peer_pub, username)
            )
        """)
        #commands struct dict[peer_pubs][command_ids]=[strings][strings] with messages
        #main_key=bytes, sum of keys in LHS
        self.conn.commit()

    #users class functions
    def save_users(self, peer_pub:bytes, users:dict):
        for usr in users.keys():
            self.conn.execute(
            "REPLACE INTO usrs (peer_pub, username, password, no_login) VALUES (?,?,?,?)",
            (peer_pub, usr, users[usr]['password'], users[usr]['no_login']))
        self.conn.commit()

    def search_users(self, peer_pub=b'', username="") ->list:
        """ specify atleast 1 of peer_pub or username """
        if peer_pub!=b'' and username!="":
            cur=self.read_only.execute('SELECT peer_pub, username, password, no_login FROM usrs WHERE peer_pub = ? AND username = ?', (peer_pub, username))
            rows = cur.fetchall()
            if not rows:
                return []
            return rows
        elif peer_pub!=b'':
            cur=self.read_only.execute('SELECT peer_pub, username, password, no_login FROM usrs WHERE peer_pub = ?', (peer_pub,))
            rows = cur.fetchall()
            if not rows:
                return []
            return rows
        else:
            cur=self.read_only.execute('SELECT peer_pub, username, password, no_login FROM usrs WHERE username = ?', (username,))
            rows = cur.fetchall()
            if not rows:
                return []
            return rows
        
    def remove_users(self, peer_pub:bytes):
        cur=self.conn.execute('DELETE FROM usrs WHERE peer_pub = ?', (peer_pub,))
        res=cur.fetchall()
        print()

    def remove_users_not_this_pubs(self, pubs:list[bytes]):
        values=pubs
        placeholders = ",".join("?" for _ in values)

        query = f"DELETE FROM usrs WHERE peer_pub NOT IN ({placeholders})"
        self.read_only.execute(query, values)
        self.read_only.commit()
        
    def read_many_users(self, filter) ->list:
        iswhere=''
        if filter!='':
            flag=False
            values=[]
            if filter[0]=='1':
                iswhere+='no_login = ?'
                flag=True
                values.append(0)
            elif filter[0]=='0':
                #iswhere+='no_login = ?'
                flag=False
                #values.append(1)
        if flag:
            cur = self.read_only.execute(f'SELECT peer_pub, username, password, no_login FROM usrs WHERE {iswhere}', values)
            rows = cur.fetchall()
        else:
            cur = self.read_only.execute('SELECT peer_pub, username, password, no_login FROM usrs')
            rows = cur.fetchall()
        if not rows:
            return []
        return rows
        
    #Commands class functions
    def save_command(self, main_key:bytes, peer_pub:bytes, command_id:int, server_write:str, server_read:str):
        self.conn.execute(
            "REPLACE INTO commands (main_key, peer_pub, command_id, serv_write, serv_read) VALUES (?, ?, ?, ?, ?)",
            (main_key, peer_pub, command_id, server_write, server_read))

        self.conn.commit()
    
    def search_commands(self, peer_pub:bytes, command_id:bytes):
        if command_id==b'':
            cur=self.read_only.execute('SELECT command_id, serv_write, serv_read FROM commands WHERE peer_pub = ?', (peer_pub,))
            rows = cur.fetchall()
            if not rows:
                return []
            return rows
        else:
            command_id=int().from_bytes(command_id, signed=False)
            cur=self.read_only.execute('SELECT command_id, serv_write, serv_read FROM commands WHERE peer_pub = ? AND command_id = ?', (peer_pub, command_id))
            rows=cur.fetchall()
            if not rows:
                return []
            return rows
        
    def next_id(self, peer_pub:bytes) -> int:
        cur = self.read_only.execute("SELECT * FROM commands WHERE peer_pub = ? ORDER BY command_id DESC LIMIT 1", (peer_pub, ))
        row = cur.fetchone()
        if row==None:
            return 0
        else:
            return row[2]+1
        
    def read_all(self):
        cur = self.read_only.execute("SELECT * FROM commands WHERE serv_write NOT LIKE ? AND serv_write NOT LIKE ?", (f'%echo"%', f'%"stat"%'))
        rows = cur.fetchall()
        return rows
    def delete(self, main_key: bytes):
        self.conn.execute("DELETE FROM commands WHERE main_key = ?", (main_key,))
        self.conn.commit()

    def close(self):
        self.conn.close()

class commands:
    def __init__(self, DB : ByteDictDB):   
        self.DB=DB

    def read_many(self, n=50):

        temp=self.DB.read_all()

        return temp

    def read(self, peer_pub:bytes, command_id=b'')->list:
        """ returs a [of [id, writes, reads]] """
        results=self.DB.search_commands(peer_pub, command_id)
        if results==None:
            return []
        for i in range(len(results)):
            temp=[]
            temp.append(results[i][0])
            if results[i][1]!='':
                temp.append(json.loads(results[i][1]))
            else:
                temp.append({})
            if results[i][2]!='':
                temp.append(json.loads(results[i][2]))
            else:
                temp.append({})
            results[i]=temp
        return results

    def _write(self, peer_pub:bytes, command_id:int, server_write:str, server_read: str) -> list:
        """ appends strings to internal dict 
        returns [bool, Exception | None]"""
        main_key=bytes(bytearray(peer_pub)+bytearray(command_id.to_bytes(4, signed=False)))
        self.DB.save_command(main_key, peer_pub, command_id, server_write, server_read)

    def new(self, peer_pub:bytes, server_write='', server_read=''):
        if server_write=='' and server_read=='':
            return None
        temp_id=self.DB.next_id(peer_pub)
        self._write(peer_pub, temp_id, server_write, server_read)
        return temp_id.to_bytes(4, signed=False)

    def append(self, peer_pub:bytes, command_id:bytes, server_write='', server_read=''):
        prev=self.DB.search_commands(peer_pub, command_id)
        
        prev_write=prev[0][1]
        prev_read=prev[0][2]
        if prev_write!='':
            prev_write=json.loads(prev_write)
        else:
            prev_write={}
        if server_write=='':
            server_write=prev_write
        else:
            prev_write.update(json.loads(server_write))

        if prev_read!='':
            prev_read=json.loads(prev_read)
        else:
            prev_read={}
        if server_read=='':
            server_read=prev_read
        else:
            prev_read.update(json.loads(server_read))
        self._write(peer_pub, int().from_bytes(command_id, signed=False), json.dumps(prev_write), json.dumps(prev_read))

class users_cache:
    def __init__(self, DB:ByteDictDB):
        self.DB=DB

    def add_host_users(self, peer_pub:bytes, usrs:dict):
        #maybe add existing users check
        #dict of users {username:{password:PASSHASH}}
        self.DB.remove_users(peer_pub)
        self.DB.save_users(peer_pub, usrs)

    def read_saved_users(self, peer_pub:bytes, username:str):
        return self.DB.search_users(peer_pub, username)
    
    def read_all(self, filter):
        return self.DB.read_many_users(filter)
    
    def delete_users_old_hosts(self, hosts:list[bytes]):
        self.DB.remove_users_not_this_pubs(hosts)

if __name__=='__main__':
    from os import urandom
    from time import time
    import json
    DB=ByteDictDB('data.sqlite')
    test=commands(DB)
    r={
        time():['SERVER READS THIS', 'And second']
    }
    w={
        time():['SERVER WRITE THIS', 'And second']
    }
    peer_pub=bytes([i for i in range(64)])
    id_byte=test.new(peer_pub=peer_pub, server_write=json.dumps(w), server_read=json.dumps(r))
    r={
        time():['SERVER READS THIS2', 'And second']
    }
    w={
        time():['SERVER WRITE THIS2', 'And second']
    }
    print(test.append(peer_pub=peer_pub, command_id=id_byte, server_write=json.dumps(w), server_read=json.dumps(r)))
    print(test.read(peer_pub))
                                