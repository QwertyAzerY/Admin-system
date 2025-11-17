from server import server_class
from webserver import web

class wrapper():
    def __init__(self):
        self.server=server_class(test_mode=True)
        self.webserver=web(self.server.conf.settings['SERVER_IP'], self.server.conf.settings['SERVER_PORT']-1)

    def run(self):
        self.server.create_client(filename="./clients/testing_client.json")
        self.server.listen_for_connections()


if __name__=='__main__':
    test=wrapper().run()
