from json import dumps
class users():
    def __init__(self):
        self.users={}
        self.ready=False

    def scrap(self, data:str):
        atleast_one_user=False
        if len(data)<3:
            return [False, 'Cannot scrap file; len<3']
        lines=data.split('\n')
        if len(lines)==0:
            return [False, 'Cannot scrap file; lines==0']
        for line in lines:
            no_login=0
            args=line.split(':')
            if len(args)<2:
                continue
            if args[1]=='!' or args[1]=='!!' or args[1]=='*' or args[1]=='!*':
                no_login=1
            self.users[args[0]]={
                'password': args[1],
                'no_login':no_login
            }
            atleast_one_user=True
        if not atleast_one_user:
            return [False, 'There was no users']
        return [True, '']
    
    
    def export_str(self) -> str:
        return dumps(self.users)


if __name__=="__main__":
    test='root:!::0:99999:7:::\nbin:*:20047:0:99999:7:::\ndaemon:*:20047:0:99999:7:::\nadm:*:20047:0:99999:7:::\nlp:*:20047:0:99999:7:::\nsync:*:20047:0:99999:7:::\nshutdown:*:20047:0:99999:7:::\nhalt:*:20047:0:99999:7:::\nmail:*:20047:0:99999:7:::\noperator:*:20047:0:99999:7:::\ngames:*:20047:0:99999:7:::\nftp:*:20047:0:99999:7:::\nnobody:*:20047:0:99999:7:::\ndbus:!!:20409::::::\nrtkit:!!:20409::::::\ngeoclue:!!:20409::::::\npipewire:!!:20409::::::\ntss:!!:20409::::::\nsystemd-oom:!*:20409::::::\nsystemd-resolve:!*:20409::::::\npolkitd:!!:20409::::::\navahi:!!:20409::::::\nsstpc:!!:20409::::::\nunbound:!!:20409::::::\nopenvswitch:!!:20409::::::\nsshd:!!:20409::::::\nnm-openconnect:!!:20409::::::\ngluster:!!:20409::::::\nrpc:!!:20409:0:99999:7:::\nusbmuxd:!!:20409::::::\nopenvpn:!!:20409::::::\nnm-openvpn:!!:20409::::::\nwsdd:!!:20409::::::\ncolord:!!:20409::::::\npostfix:!!:20409::::::\nabrt:!!:20409::::::\ngdm:!!:20409::::::\nrpcuser:!!:20409::::::\nchrony:!!:20409::::::\ndnsmasq:!!:20409::::::\ntcpdump:!!:20409::::::\ngnome-remote-desktop:!*:20409::::::\nsystemd-coredump:!*:20409::::::\nsystemd-timesync:!*:20409::::::\nvboxadd:!*:20409::::::\nadmin:$y$j9T$j4dNpk0eAHgevjW/qyyJpLVM$acRavqrkVmPquhHUaJ90ornRlvxy.R3PgyoNjtlwcVB::0:99999:7:::\n'
    U=users()
    print(U.scrap(test))
    print(U.export_str())