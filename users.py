from json import dumps
class users():
    def __init__(self):
        self.users={}
        self.ready=False

    def scrap(self, data:str):
        if len(data)<3:
            return [False, 'Cannot scrap file; len<3']
        lines=data.split('\n')
        if len(lines)==0:
            return [False, 'Cannot scrap file; lines==0']
        for line in lines:
            args=line.split(':')
            if len(args)<2:
                return [False, 'Cannot scrap file; lines==0']
            if args[1]=='!' or args[1]=='!!' or args[1]=='*' or args[1]=='!*':
                continue
            self.users[args[0]]={
                'password': args[1]
            }
        return [True, '']
    
    def export_str(self) -> str:
        return dumps(self.users)


if __name__=="__main__":
    test="root:*:19212:0:99999:7:::\ndaemon:*:19212:0:99999:7:::\nbin:*:19212:0:99999:7:::\nsys:*:19212:0:99999:7:::\nsync:*:19212:0:99999:7:::\ngames:*:19212:0:99999:7:::\nman:*:19212:0:99999:7:::\nlp:*:19212:0:99999:7:::\nmail:*:19212:0:99999:7:::\nnews:*:19212:0:99999:7:::\nuucp:*:19212:0:99999:7:::\nproxy:*:19212:0:99999:7:::\nwww-data:*:19212:0:99999:7:::\nbackup:*:19212:0:99999:7:::\nlist:*:19212:0:99999:7:::\nirc:*:19212:0:99999:7:::\ngnats:*:19212:0:99999:7:::\nnobody:*:19212:0:99999:7:::\n_apt:!:19212::::::\nsystemd-network:!:19212::::::\nsystemd-resolve:!:19212::::::\nsystemd-timesync:!:19212::::::\nmessagebus:!:19212::::::\ntss:!:19212::::::\nstrongswan:!:19212::::::\ntcpdump:!:19212::::::\nusbmux:!:19212::::::\nsshd:!:19212::::::\ndnsmasq:!:19212::::::\navahi:!:19212::::::\nrtkit:!:19212::::::\nspeech-dispatcher:!:19212::::::\nnm-openvpn:!:19212::::::\nnm-openconnect:!:19212::::::\nlightdm:!:19212::::::\npulse:!:19212::::::\nsaned:!:19212::::::\ncolord:!:19212::::::\nmysql:!:19212::::::\nstunnel4:!*:19212::::::\n_rpc:!:19212::::::\ngeoclue:!:19212::::::\nDebian-snmp:!:19212::::::\nsslh:!:19212::::::\nntpsec:!:19212::::::\nredsocks:!:19212::::::\nrwhod:!:19212::::::\niodine:!:19212::::::\nmiredo:!:19212::::::\nstatd:!:19212::::::\npostgres:!:19212::::::\ninetsim:!:19212::::::\nking-phisher:!:19212::::::\nkali:$y$j9T$CPuhZ1MKX1L2Vm2uVVdYD0$tpZjsmkPG6ONRswn789aImhMu5c8Ymtmh18Do8BtYY5:19304:0:99999:7:::\n_chrony:!:19451::::::\nsecureuser:$y$j9T$OpUjQ9yVzeAieXzlhT70D/$lMGU9cTgS4WyWcbyMKWDTZ1kLdB/fdg7RhtwyPGQuX7:19527:0:99999:7:::\nredis:!:19635::::::\n_galera:!:19988::::::\nDebian-exim:!:20057::::::\nuser1:$y$j9T$YRgXl4Xro442th7VQan2f/$TCwq9wZsDbts9GOXvcLXbI5x47o4SiKyK8hl1zYjHG6:20057:0:99999:7:::\nuser2:$y$j9T$o9dw/1rnvb11vF8F.BL35.$s8zEujGSPiJyGn43LrE4orJG9b3Hj43H/PeNyuCp7yC:20057:0:99999:7:::"
    U=users()
    U.scrap(test)