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
LONG_PASSWORD = 1
LONG_FLAG = 1 << 2
PROTOCOL_41 = 1 << 9
TRANSACTIONS = 1 << 13

CAPABILITIES = (
    LONG_PASSWORD | LONG_FLAG | PROTOCOL_41 | TRANSACTIONS
    | SECURE_CONNECTION | MULTI_RESULTS
    | CLIENT_PLUGIN_AUTH | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA | CLIENT_CONNECT_ATTRS)


CLIENT_CONNECT_WITH_DB = 9
max_packet_size = 2 ** 24 - 1
charset_id = 45


class TcpClient:
    def __init__(self,host_content,user_name,password,databases):
        _host_content = host_content.split(':')
        self.user = user_name
        self.password = password
        self.database = databases
        HOST = _host_content[0]
        PORT = int(_host_content[1])
        self.BUFSIZ = 1024
        self.ADDR = (HOST, PORT)

        self.client=socket(AF_INET, SOCK_STREAM)
        self.client.connect(self.ADDR)
        self.client.settimeout(1)

        self.server_packet_info = {}

        self.packet = None
    def header(self):
        self.offset = 0
        self.payload_length = self.packet[2] << 16 | self.packet[1] << 8 | self.packet[0]
        self.sequence_id = self.packet[3]
        print(self.payload_length, self.sequence_id)
        self.offset += 4

    def check_packet(self):
        self.header()
        packet_header = self.packet[self.offset]
        self.offset += 1
        if packet_header == 0x00:
            print('connection ok')
        elif packet_header in (0xfe,0xff):
            print(self.packet[self.offset:])

    def Send(self):
        self.packet=self.client.recv(self.BUFSIZ)
        self.header()
        self.__read_server_info()
        self.__handshakeresponsepacket()
        response_payload = len(self.response_packet)
        self.client.send(struct.pack('<I',response_payload)[:3] + struct.pack('!B',1) + self.response_packet)

        self.packet = self.client.recv(self.BUFSIZ)
        self.header()
        packet_header = self.packet[self.offset]
        self.offset += 1
        if packet_header == 0xff:
            error_code = struct.unpack('<H', self.packet[self.offset:self.offset + 2])
            self.offset+= 2
            print(error_code,self.packet[self.offset:])
        elif packet_header == 0xfe:
            """AuthSwitchRequest"""
            _data = self.__authswitchrequest()
            self.client.send(struct.pack('<I', len(_data))[:3] + struct.pack('!B', 3) + _data)
            self.packet = self.client.recv(self.BUFSIZ)
            self.check_packet()

        elif packet_header in (0x00,0xfe):
            if self.payload_length > 7:
                print('ok packet')
            elif self.payload_length < 9:
                print('error packet')

        print(self.server_packet_info)

        """在这里停留一段时间，在mysql查看连接是否正常"""
        import time
        time.sleep(1000)


    def __authswitchrequest(self):
        end_pos = self.packet.find(b'\0', self.offset)
        auth_name = self.packet[self.offset:end_pos].decode()

        self.offset = end_pos + 1

        auth_plugin_data = self.packet[self.offset:]
        if self.server_packet_info['capability_flags'] & CLIENT_PLUGIN_AUTH and auth_name:
            data = self.__sha1_password(auth_plugin_data)

        return data


    def __read_server_info(self):
        PLUGIN_AUTH = 1 << 19
        #数据包内容
        self.server_packet_info['packet_header'] = self.packet[self.offset]
        print(self.server_packet_info['packet_header'])
        a = self.payload_length -1-2
        print(struct.unpack('<H{}s'.format(a), self.packet[self.offset+1:]))
        self.offset += 1

        _s_end = self.packet.find(b'\0', self.offset)
        self.server_packet_info['server_version'] = self.packet[self.offset:_s_end]
        self.offset = _s_end + 1
        self.server_packet_info['thread_id'] = struct.unpack('<I',self.packet[self.offset:self.offset+4])
        self.offset += 4
        self.server_packet_info['auth_plugin_data'] = self.packet[self.offset:self.offset+8]
        self.offset += 8 + 1
        self.server_packet_info['capability_flags'] = struct.unpack('<H',self.packet[self.offset:self.offset+2])[0]
        self.offset += 2
        self.server_packet_info['character_set_id'],\
        self.server_packet_info['status_flags'],\
        capability_flags_2,auth_plugin_data_len = struct.unpack('<BHHB',self.packet[self.offset:self.offset+6])

        self.server_packet_info['capability_flags'] |= capability_flags_2 << 16
        self.offset += 6
        self.offset += 10
        auth_plugin_data_len = max(13,auth_plugin_data_len-8)
        if len(self.packet) - 4 >= self.offset + auth_plugin_data_len:
            # salt_len includes auth_plugin_data_part_1 and filler
            self.server_packet_info['auth_plugin_data'] += self.packet[self.offset:self.offset + auth_plugin_data_len]
            self.offset += auth_plugin_data_len

        if self.server_packet_info['capability_flags'] & PLUGIN_AUTH and len(self.packet) - 4 >= self.offset:
            _s_end = self.packet.find(b'\0',self.offset)
            self.server_packet_info['auth_plugin_name'] = self.packet[self.offset:_s_end]


    def __handshakeresponsepacket(self):
        client_flag = 0
        client_flag |= CAPABILITIES
        if self.database:
            client_flag |= CLIENT_CONNECT_WITH_DB
        server_version = (self.server_packet_info['server_version']).decode()
        if int(server_version.split('.', 1)[0]) >= 5:
            client_flag |= MULTI_RESULTS

        self.response_packet = struct.pack('<iIB23s',client_flag,max_packet_size,charset_id,b'')
        self.response_packet += self.user.encode() + b'\0'
        sha1_password = self.__sha1_password()

        if self.server_packet_info['capability_flags'] & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA:
            self.response_packet += struct.pack('!B',len(sha1_password)) + sha1_password
        elif self.server_packet_info['capability_flags'] & SECURE_CONNECTION:
            self.response_packet += struct.pack('B',len(sha1_password)) + sha1_password
        else:
            self.response_packet += sha1_password + b'\0'

        if self.server_packet_info['capability_flags'] & CLIENT_CONNECT_WITH_DB:
            self.response_packet += self.database.encode() + b'\0'
        if self.server_packet_info['capability_flags'] & CLIENT_PLUGIN_AUTH:
            self.response_packet += b'' + b'\0'
        if self.server_packet_info['capability_flags'] & CLIENT_CONNECT_ATTRS:
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
            self.response_packet += struct.pack('B', len(connect_attrs)) + connect_attrs
    def __sha1_password(self,auth_plugin_data=None):
        _pass1 = sha1_new(self.password.encode()).digest()
        _pass2 = sha1_new(_pass1).digest()
        s = sha1_new()
        if auth_plugin_data is None:
            s.update(self.server_packet_info['auth_plugin_data'][:SHA1_HASH_SIZE])
        else:
            s.update(auth_plugin_data[:SHA1_HASH_SIZE])
        s.update(_pass2)
        t = bytearray(s.digest())
        for i in range(len(t)):
            t[i] ^= _pass1[i]

        return t

    def close(self):
        self.client.close()


with closing(TcpClient('192.200.1.101:3306','wang','wang@123','sys')) as tcpclient:
    tcpclient.Send()


