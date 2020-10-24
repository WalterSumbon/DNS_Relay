import socketserver
import struct
from dns import resolver
# DNS Query
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
    def getbytes(self):
        return self.querybytes + struct.pack('>HH', self.type, self.classify)

# DNS Answer RRS
# this class is also can be use as Authority RRS or Additional RRS
class DNSAnswer:
    def __init__(self, ip):
        self.name = 0xc00c
        self.type = 1
        self.classify = 1
        self.timetolive = 190
        self.datalength = 4
        self.ip = ip
    def getbytes(self):
        """ip -> DNS response: bytes"""
        res = struct.pack('>HHHLH', self.name, self.type, self.classify, self.timetolive, self.datalength)
        s = self.ip.split('.')
        res = res + struct.pack('BBBB', int(s[0]), int(s[1]), int(s[2]), int(s[3]))
        return res

# DNS frame
# must initialized by a DNS query frame
class DNSFrame:
    def __init__(self, data):
        self.id, self.flags, self.quests, self.answers, self.author, self.addition = struct.unpack('>HHHHHH', data[0:12])
        self.query = DNSQuery(data[12:])
    def getname(self):
        return self.query.name
    def setip(self, ip):
        self.answer = DNSAnswer(ip)
        self.answers = 1
        self.flags = 0x8180
    def getbytes(self):
        res = struct.pack('>HHHHHH', self.id, self.flags, self.quests, self.answers, self.author, self.addition)
        res = res + self.query.getbytes()
        if self.answers != 0:
            res = res + self.answer.getbytes()
        return res
# A UDPHandler to handle DNS query
class DNSUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        dns = DNSFrame(data)
        socket = self.request[1]
        namemap = DNSServer.namemap
        if(dns.query.type==1):
            # If this is querying an A record, then response it
            name = dns.getname()
            if name in namemap:
                # If have record, response it
                dns.setip(namemap[name])
                socket.sendto(dns.getbytes(), self.client_address)
            else:
                try:
                    answer = DNSServer.res.query(name)
                except Exception:
                    socket.sendto(data, self.client_address)    #ignore
                else:
                    dns.setip(answer[0].address)
                    socket.sendto(dns.getbytes(), self.client_address)
        else:
            # If this is not query a A record, ignore it
            socket.sendto(data, self.client_address)

# DNS Server
# It only support A record query
# user it, U can create a simple DNS server
class DNSServer:
    def __init__(self, port=53):
        DNSServer.namemap = {}
        DNSServer.res = resolver.Resolver()
        DNSServer.res.nameservers = ['114.114.114.114']
        self.port = port
    def addname(self, name, ip):
        DNSServer.namemap[name] = ip
    def start(self):
        HOST, PORT = "0.0.0.0", self.port
        server = socketserver.UDPServer((HOST, PORT), DNSUDPHandler)
        server.serve_forever()

# Now, test it
if __name__ == "__main__":
    sev = DNSServer()
    sev.addname('www.aa.com', '192.168.0.1')    # add a A record
    sev.addname('www.bb.com', '192.168.0.2')    # add a A record
    sev.addname('www.ckms.com', '192.168.0.3') # add a A record
    sev.addname("img-home.csdnimg.cn",'0.0.0.0')
    sev.start() # start DNS server

# Now, U can use "nslookup" command to test it
# Such as "nslookup www.aa.com"