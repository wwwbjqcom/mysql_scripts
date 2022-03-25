#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@author: xiao cai niao
'''
import struct,sys
from socket import *
from contextlib import closing
import hashlib,os
from functools import partial

sha1_new = partial(hashlib.new, 'sha1')
SHA1_HASH_SIZE = 20
MULTI_RESULTS = 1 << 17
SECURE_CONNECTION = 1 << 15
CLIENT_PLUGIN_AUTH = 1 << 19
CLIENT_CONNECT_ATTRS = 1<< 20
CLIENT_PROTOCOL_41 = 1 << 9
CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 1<<21
CLIENT_DEPRECATE_EOF = 1 << 24
LONG_PASSWORD = 1
LONG_FLAG = 1 << 2
PROTOCOL_41 = 1 << 9
TRANSACTIONS = 1 << 13

CAPABILITIES = (
    LONG_PASSWORD | LONG_FLAG | PROTOCOL_41 | TRANSACTIONS
    | SECURE_CONNECTION | MULTI_RESULTS
    | CLIENT_PLUGIN_AUTH | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA | CLIENT_CONNECT_ATTRS | CLIENT_DEPRECATE_EOF)


CLIENT_CONNECT_WITH_DB = 9
max_packet_size = 2 ** 24 - 1
charset_id = 45


class PreparPacket(object):
    def __init__(self):
        pass

    def __null_bitmap(self,num_params):
        _bytes = int((num_params + 7) / 8)
        if _bytes == 1:
            return bytearray(struct.pack('B',0))
        elif _bytes == 2:
            return bytearray(struct.pack('H', 0))
        elif _bytes == 3:
            return bytearray(struct.pack('HB', 0,0))
        elif _bytes == 4:
            return bytearray(struct.pack('I', 0))

    def is_null(self,null_bytes,pos):
        bit = null_bytes[int(pos / 8)]
        if type(bit) is str:
            bit = ord(bit)
        return bit & (1 << (pos % 8))


    def COM_Query(self, sql):
        """
        Type	    Name	Description
        int<1>	    command	0x03: COM_QUERY
        string<EOF>	query	the text of the SQL query to execute
        """
        return struct.pack('B', 3) + sql.encode('utf8')

    def Prepar_head(self,playload_length,seq_id):
        return struct.pack('<I', playload_length)[:3] + struct.pack('!B', seq_id)

    def handshakeresponsepacket(self,server_packet_info,user,password,database=None):
        """
        组装Protocol::HandshakeResponse数据包
        :return:
        """
        client_flag = 0
        client_flag |= CAPABILITIES
        if database:
            client_flag |= CLIENT_CONNECT_WITH_DB
        server_version = (server_packet_info['server_version']).decode()
        if int(server_version.split('.', 1)[0]) >= 5:
            client_flag |= MULTI_RESULTS

        response_packet = struct.pack('<iIB23s',client_flag,max_packet_size,charset_id,b'')
        response_packet += user.encode() + b'\0'
        sha1_password = self.sha1_password(password=password,auth_plugin_data=server_packet_info['auth_plugin_data'])

        if server_packet_info['capability_flags'] & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA:
            response_packet += struct.pack('!B',len(sha1_password)) + sha1_password
        elif server_packet_info['capability_flags'] & SECURE_CONNECTION:
            response_packet += struct.pack('B',len(sha1_password)) + sha1_password
        else:
            response_packet += sha1_password + b'\0'

        if server_packet_info['capability_flags'] & CLIENT_CONNECT_WITH_DB:
            if database:
                response_packet += database.encode()
            response_packet += b'\0'
        if server_packet_info['capability_flags'] & CLIENT_PLUGIN_AUTH:
            response_packet += b'' + b'\0'
        if server_packet_info['capability_flags'] & CLIENT_CONNECT_ATTRS:
            _connect_attrs = {
                '_client_name': 'pymysql',
                '_pid': str(os.getpid()),
                '_client_version': '3.6.5',
                'program_name' : sys.argv[0]
            }
            connect_attrs = b''
            for k, v in _connect_attrs.items():
                k = k.encode('utf8')
                connect_attrs += struct.pack('B', len(k)) + k
                v = v.encode('utf8')
                connect_attrs += struct.pack('B', len(v)) + v
            response_packet += struct.pack('B', len(connect_attrs)) + connect_attrs

        return response_packet

    def authswitchrequest(self,packet,offset,capability_flags,password):
        """
        服务端通知客户端连接方式更改(Protocol::AuthSwitchRequest)，重新组装验证方法
        :return:
        """
        end_pos = packet.find(b'\0', offset)
        auth_name = packet[offset:end_pos].decode()

        offset = end_pos + 1

        auth_plugin_data = packet[offset:]
        if capability_flags & CLIENT_PLUGIN_AUTH and auth_name:
            data = self.sha1_password(password,auth_plugin_data)

        return data

    def sha1_password(self,password,auth_plugin_data):
        _pass1 = sha1_new(password.encode()).digest()
        _pass2 = sha1_new(_pass1).digest()
        s = sha1_new()
        s.update(auth_plugin_data[:SHA1_HASH_SIZE])
        s.update(_pass2)
        t = bytearray(s.digest())
        for i in range(len(t)):
            t[i] ^= _pass1[i]

        return t

    def PackeByte(self,server_id,binlog_pos,binlog_file):
        '''
        Format for mysql packet position
        file_length: 4bytes
        dump_type: 1bytes
        position: 4bytes
        flags: 2bytes
            0: BINLOG_DUMP_BLOCK
            1: BINLOG_DUMP_NON_BLOCK
        server_id: 4bytes
        log_file
        :return:
        '''
        COM_BINLOG_DUMP = 0x12

        if self._log_file is None:
            if self._log_pos is None:
                self._log_file, self._log_pos = self.GetFile()
            else:
                self._log_file, _ = self.GetFile()
        elif self._log_file and self._log_pos is None:
            self._log_pos = 4

        prelude = struct.pack('<i', len(self._log_file) + 11) \
                  + struct.pack("!B", COM_BINLOG_DUMP)

        prelude += struct.pack('<I', self._log_pos)
        if self.block:
            prelude += struct.pack('<h', 0)
        else:
            prelude += struct.pack('<h', 1)

        prelude += struct.pack('<I', self.server_id)
        prelude += self._log_file.encode()
        return prelude

class UnpackPacket(PreparPacket):
    def __init__(self):
        super(UnpackPacket,self).__init__()

    def unpack_handshake(self,packet):
        """
        解析Protocol::Handshake数据包
        :return:
        """
        PLUGIN_AUTH = 1 << 19
        server_packet_info = {}
        #数据包内容
        offset = 0
        server_packet_info['packet_header'] = packet[offset]
        offset += 1

        _s_end = packet.find(b'\0', offset)
        server_packet_info['server_version'] = packet[offset:_s_end]
        offset = _s_end + 1
        server_packet_info['thread_id'] = struct.unpack('<I',packet[offset:offset+4])
        offset += 4
        server_packet_info['auth_plugin_data'] = packet[offset:offset+8]
        offset += 8 + 1
        server_packet_info['capability_flags'] = struct.unpack('<H',packet[offset:offset+2])[0]
        offset += 2
        server_packet_info['character_set_id'],\
        server_packet_info['status_flags'],\
        capability_flags_2,auth_plugin_data_len = struct.unpack('<BHHB',packet[offset:offset+6])

        server_packet_info['capability_flags'] |= capability_flags_2 << 16
        offset += 6
        offset += 10
        auth_plugin_data_len = max(13,auth_plugin_data_len-8)
        if len(packet) - 4 >= offset + auth_plugin_data_len:
            server_packet_info['auth_plugin_data'] += packet[offset:offset + auth_plugin_data_len]
            offset += auth_plugin_data_len

        if server_packet_info['capability_flags'] & PLUGIN_AUTH and len(packet) - 4 >= offset:
            _s_end = packet.find(b'\0',offset)
            server_packet_info['auth_plugin_name'] = packet[offset:_s_end]

        return server_packet_info

class TcpClient(UnpackPacket):
    def __init__(self,host_content,user_name,password,databases):
        super(TcpClient,self).__init__()
        _host_content = host_content.split(':')

        self.user = user_name
        self.password = password
        self.database = databases
        HOST = _host_content[0]
        PORT = int(_host_content[1])
        self.ADDR = (HOST, PORT)
        self.client = create_connection(self.ADDR)
        self.client.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        self.client.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)
        self.client.settimeout(None)
        self.socket_file = self.client.makefile('rb')


        self.server_packet_info = {}

        self.packet = b''

    def header(self,packet=None):
        """
        处理包头部分
        :param offset:
        :return:
        """
        self.payload_length = packet[2] << 16 | packet[1] << 8 | packet[0]
        self.seq_id = packet[3]
        self.offset = 0

    def check_packet(self):
        """
        检查连接时返回数据包类型
        :return:
        """
        packet_header = self.packet[self.offset]
        self.offset += 1
        if packet_header == 0x00:
            print('connection ok')
        elif packet_header in (0xfe,0xff):
            print(self.packet[self.offset:])

    def Send(self):
        self.recv_data()
        self.server_packet_info = self.unpack_handshake(packet=self.packet)
        self.response_packet = self.handshakeresponsepacket(server_packet_info=self.server_packet_info,
                                                            user=self.user,password=self.password,
                                                            database=self.database)
        response_payload = len(self.response_packet)
        self.client.send(self.Prepar_head(response_payload,self.seq_id + 1) + self.response_packet)
        self.recv_data()
        packet_header = self.packet[self.offset]
        self.offset += 1
        if packet_header == 0xff:
            error_code = struct.unpack('<H', self.packet[self.offset:self.offset + 2])
            self.offset+= 2
            print(error_code,self.packet[self.offset:])
        elif packet_header == 0xfe:
            """AuthSwitchRequest"""
            if len(self.packet) < 9:
                print('this is eof packet')
            else:
                _data = self.authswitchrequest(packet=self.packet,offset=self.offset,password=self.password,
                                               capability_flags=self.server_packet_info['capability_flags'])
                self.client.send(struct.pack('<I', len(_data))[:3] + struct.pack('!B', 3) + _data)
                self.recv_data()
                self.check_packet()

        elif packet_header == 0x00:
            if len(self.packet) > 7:
                print('ok packet')


    def recv_data(self):
        """
        接收数据
        :param result:
        :return:
        """
        _packet = b''
        while 1:
            _packet = self.socket_file.read(4)
            self.header(packet=_packet)
            _packet = self.socket_file.read(self.payload_length)
            if self.payload_length == 0xffffff:
                continue
            self.packet = _packet
            break

class Replication(TcpClient):
    def __init__(self,**kwargs):
        args = [kwargs['host_info'],kwargs['user'],kwargs['passwd'],kwargs['db']]
        super(Replication,self).__init__(*args)

        self.binlog_pos = kwargs['binlog_pos'] if 'binlog_pos' in kwargs else None
        self.binlog_file = kwargs['binlog_file'] if 'binlog_file' in kwargs else None
        self.repl_block = kwargs['repl_block'] if 'repl_block' in kwargs else None
        self.server_id = kwargs['server_id']
        self.gtid = kwargs['gtid'] if 'gtid' in kwargs else None

    def PackeByte(self):
        '''
        Format for mysql packet position
        dump_type: 1bytes
        position: 4bytes
        flags: 2bytes
            0: BINLOG_DUMP_BLOCK
            1: BINLOG_DUMP_NON_BLOCK
        server_id: 4bytes
        log_file
        :return:
        '''
        COM_BINLOG_DUMP = 0x12

        _packet = struct.pack("B", COM_BINLOG_DUMP)

        _packet += struct.pack('<I', self.binlog_pos)
        if self.repl_block:
            _packet += struct.pack('<h', 0)
        else:
            _packet += struct.pack('<h', 1)

        _packet += struct.pack('<I', self.server_id)
        _packet += self.binlog_file.encode()
        return self.Prepar_head(len(_packet),0) + _packet

    def regist_slave(self):
        self.Send()
        self.client.send(self.PackeByte())



    def close(self):
        self.client.close()



kwargs = {
    'host_info':'10.0.1.24:3306',
    'user':'potato_test_GRUD',
    'passwd':'X6D.J14ng-sFdyqbG5Z7kPNWQhCMxGUT',
    'db':'',
    'repl_block':True,
    'binlog_file':'bin.000127',
    'binlog_pos':764271025,
    'server_id':1111
}
# with closing(Replication('192.168.10.128:3306','root','bsrt_123,./&^%','')) as tcpclient:
#     tcpclient.Send()
with closing(Replication(**kwargs)) as rpl:
    rpl.regist_slave()