import struct
import socketserver
from time import time
from dns import resolver

class DNSQuery:
    def __init__(self, data):
        i = 1
        self.name = ''
        while True:     #ugly!!!
            d = data[i]
            if d == 0:
                break
            if d < 32:
                self.name = self.name + '.'
            else:
                self.name = self.name + chr(d)
            i = i + 1
        self.querybytes = data[0:i + 1]
        self.type, self.classify = struct.unpack('>HH', data[i + 1:i + 5])
        self.len = i + 5
    def get_bytes(self):
        return self.querybytes + struct.pack('>HH', self.type, self.classify)

class DNSAnswer:
    def __init__(self, ip):
        self.name = 0xc00c
        self.type = 1
        self.classify = 1
        self.timetolive = 190
        self.datalength = 4
        self.ip = ip
    def get_bytes(self):
        """ip -> DNS response: bytes"""
        res = struct.pack('>HHHLH', self.name, self.type, self.classify, self.timetolive, self.datalength)
        s = self.ip.split('.')
        res = res + struct.pack('BBBB', int(s[0]), int(s[1]), int(s[2]), int(s[3]))
        return res

# must be initialized by a DNS query frame
class DNSFrame:
    def __init__(self, data):
        self.id, self.flags, self.quests, self.answers, self.author, self.addition = struct.unpack('>HHHHHH', data[0:12])
        self.query = DNSQuery(data[12:])
    def get_name(self):
        return self.query.name
    def generate_answer(self, ip):
        self.answer = DNSAnswer(ip)
        self.answers = 1
        self.flags = 0x8180
    def get_bytes(self):
        """bytes of the answer"""
        res = struct.pack('>HHHHHH', self.id, self.flags, self.quests, self.answers, self.author, self.addition)
        res = res + self.query.get_bytes()
        if self.answers != 0:
            res = res + self.answer.get_bytes()
        return res

class DNSUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        start_time = time()
        data = self.request[0].strip()
        dns = DNSFrame(data)
        socket = self.request[1]
        namemap = DNSServer.namemap

        name = dns.get_name()
        print('%+50s'%name,end='\t')
        if name in namemap:
            ip = namemap[name]
            dns.generate_answer(ip)
            socket.sendto(dns.get_bytes(), self.client_address)
            if ip == '0.0.0.0':
                print('INTERCEPT','%15s'%ip,'%fs'%(time()-start_time),sep='\t')
            else:
                print(' RESOLVED','%15s'%ip,'%fs'%(time()-start_time),sep='\t')
        else:
            try:
                answer = DNSServer.res.query(name)
            except Exception:
                ip = '0.0.0.0'
                socket.sendto(data, self.client_address)    #ignore
            else:
                ip = answer[0].address
                dns.generate_answer(ip)
                socket.sendto(dns.get_bytes(), self.client_address)
            finally:
                print('    RELAY','%15s'%ip,'%fs'%(time()-start_time),sep='\t')

class DNSServer:
    def __init__(self, port=53, config = 'config'):
        DNSServer.config = config
        DNSServer.namemap = {} #dict<str,str>
        DNSServer.read_config()
        DNSServer.res = resolver.Resolver()
        DNSServer.res.nameservers = ['114.114.114.114']
        self.port = port
    @classmethod
    def read_config(cls):
        with open(cls.config, 'r') as f:
            for line in f:
                ip, name = line.split(' ')
                cls.namemap[name.strip()] = ip.strip()
    @classmethod
    def add_name(cls, name, ip):
        cls.namemap[name] = ip
    def start(self):
        HOST, PORT = "0.0.0.0", self.port     #run server on localhost???
        server = socketserver.UDPServer((HOST, PORT), DNSUDPHandler)
        server.serve_forever()

# Now, test it
if __name__ == "__main__":
    sev = DNSServer()
    sev.start() # start DNS server
