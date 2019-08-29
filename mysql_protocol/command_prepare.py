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

    def COM_STMT_PREPARE(self,sql):
        """
        Type	        Name	    Description
        int<1>	        command	    0x16: COM_STMT_PREPARE
        string<EOF>	    query	    The query to prepare
        """
        return struct.pack('B',0x16) + sql.encode('utf8')

    def COM_STMT_EXECUTE(self,statement_id,flags,num_params,values,column_info):
        """
        Type	        Name	                Description
        int<1>	        status	                [0x17] COM_STMT_EXECUTE
        int<4>          statement_id	        ID of the prepared statement to execute
        int<1>	        flags	                Flags. See enum_cursor_type
        int<4>	        iteration_count	        Number of times to execute the statement. Currently always 1.
        if num_params > 0 {
        binary<var>	    null_bitmap	NULL bitmap, length= (num_params + 7) / 8
        int<1>	        new_params_bind_flag	Flag if parameters must be re-bound
        if new_params_bind_flag {
        binary<var>	    parameter_types	        Type of each parameter, length: num_params * 2
        binary<var>	    parameter_values	    value of each parameter
        """
        _pack = struct.pack('<BIBI',0x17,statement_id,flags,0x01)
        if num_params > 0:
            _null_map = self.__null_bitmap(num_params)
            for i,k in enumerate(values):
                if k == None:
                    bytes_pos = int(i / 8)
                    bit_pos = int(i % 8)
                    _null_map[bytes_pos] |= 1 << bit_pos
            _pack += _null_map + struct.pack('B',1)

            _v = b''
            for col_name in values:
                col_type = 0x0f            # default string
                for col in column_info:
                    if col['name'].decode() == col_name:
                        col_type = col['type']
                _pack += struct.pack('H',col_type)


                if col_type in (0xfd,0xfe,0x0f):
                    _v += struct.pack('B',len(values[col_name]))
                    _v += values[col_name].encode('utf8')
                elif col_type == 0x01:
                    _v += struct.pack('B',values[col_name])
                elif col_type == 0x02:
                    _v += struct.pack('<H',values[col_name])
                elif col_type in (0x03,0x09):
                    _v += struct.pack('<I', values[col_name])
                elif col_type == 0x08:
                    _v += struct.pack('<Q',values[col_name])

        return _pack + _v



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

class UnpackPacket(PreparPacket):
    def __init__(self):
        super(UnpackPacket,self).__init__()

    def unpack_handshake(self,packet,offset):
        """
        解析Protocol::Handshake数据包
        :return:
        """
        PLUGIN_AUTH = 1 << 19
        server_packet_info = {}
        #数据包内容
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
            # salt_len includes auth_plugin_data_part_1 and filler
            server_packet_info['auth_plugin_data'] += packet[offset:offset + auth_plugin_data_len]
            offset += auth_plugin_data_len

        if server_packet_info['capability_flags'] & PLUGIN_AUTH and len(packet) - 4 >= offset:
            _s_end = packet.find(b'\0',offset)
            server_packet_info['auth_plugin_name'] = packet[offset:_s_end]

        return server_packet_info

    def unpack_text_values(self,packet,column_info,payload_length):
        """
        解析row数据内容
        :param packet:
        :return:
        """
        _offset = 0
        _v = {}
        _index = 0
        while 1:
            if _offset >= payload_length:
                break
            _l = packet[_offset]
            _offset += 1
            if _l == 0xfb:
                _v[column_info[_index]['name']] = None
            else:
                _v[column_info[_index]['name']] = packet[_offset:_offset+_l]
                _offset += _l
            _index += 1
        return _v

    def unpack_binary_protocol(self,packet,cols_type):
        """
        解析prepare语句返回数据
        :param packet:
        :return:
        """
        offset = 0
        _bytes = int((len(cols_type) + 7) / 8)
        null_bytes = packet[:int((len(cols_type) + 7) / 8)]
        offset += _bytes
        values = []
        for i in range(len(cols_type)):
            if self.is_null(null_bytes,i):
                values.append(None)
                continue

            if cols_type[i] in (0xfd, 0xfe, 0x0f,0xfc):
                str_len = struct.pack('B', packet[offset])[0]
                offset += 1
                values.append(packet[offset:offset+str_len].decode('utf8','ignore'))
                offset += str_len
            elif cols_type[i] == 0x01:
                values.append(struct.unpack('<B', packet[offset:offset + 1])[0])
                offset += 1
            elif cols_type[i] == 0x02:
                values.append(struct.unpack('<H', packet[offset:offset + 2])[0])
                offset += 2
            elif cols_type[i] in (0x03, 0x09):
                values.append(struct.unpack('<I', packet[offset:offset + 4])[0])
                offset += 4
            elif cols_type[i] == 0x08:
                values.append(struct.unpack('<Q', packet[offset:offset+8])[0])
                offset += 8

        return values





    def unpack_text_column(self,packet):
        """
        解析字段元数据
        :param packet:
        :return:
        """
        _dcit = {}
        _offset = 0
        _l = packet[_offset]
        _offset += 1
        _dcit['catalog'] = packet[_offset:_offset+_l]
        _offset += _l

        _l = packet[_offset]
        _offset += 1
        _dcit['schema'] = packet[_offset:_offset + _l]
        _offset += _l

        _l = packet[_offset]
        _offset += 1
        _dcit['table'] = packet[_offset:_offset + _l]
        _offset += _l

        _l = packet[_offset]
        _offset += 1
        _dcit['org_table'] = packet[_offset:_offset + _l]
        _offset += _l

        _l = packet[_offset]
        _offset += 1
        _dcit['name'] = packet[_offset:_offset + _l]
        _offset += _l

        _l = packet[_offset]
        _offset += 1
        _dcit['org_name'] = packet[_offset:_offset + _l]
        _offset += _l

        _offset += 1

        _dcit['character_set'] = struct.unpack('H',packet[_offset:_offset+2])[0]
        _offset += 2

        _dcit['column_length'] = struct.unpack('I',packet[_offset:_offset+4])[0]
        _offset += 4

        _dcit['type'] = struct.unpack('B',packet[_offset:_offset+1])[0]
        _offset += 1

        _dcit['flag'] = struct.unpack('H',packet[_offset:_offset+2])[0]

        return _dcit

    def com_prepare_ok(self,packet):
        """
        Type	Name	        Description
        int<1>	status	        0x00: OK: Ignored by cli_read_prepare_result
        int<4>	statement_id	statement ID
        int<2>	num_columns	    Number of columns
        int<2>	num_params	    Number of parameters
        int<1>	reserved_1	    [00] filler
        ....................
        """
        offset = 1
        statement_id = struct.unpack('I',packet[offset:offset+4])[0]
        offset += 4
        num_columns = struct.unpack('H',packet[offset:offset+2])[0]
        offset += 2
        num_params = struct.unpack('H',packet[offset:offset+2])[0]
        offset += 2

        return statement_id,num_columns,num_params

class TcpClient(UnpackPacket):
    def __init__(self,host_content,user_name,password,databases,sql=None,values=None,type=None):
        super(TcpClient,self).__init__()
        _host_content = host_content.split(':')

        self.sql = sql
        self.pre_values = values
        self.type = type

        self.user = user_name
        self.password = password
        self.database = databases
        HOST = _host_content[0]
        PORT = int(_host_content[1])
        self.BUFSIZ = 1024
        self.ADDR = (HOST, PORT)

        self.client=socket(AF_INET, SOCK_STREAM)
        self.client.connect(self.ADDR)
        self.client.settimeout(0.1)

        self.server_packet_info = {}

        self.packet = None

        self.column_info = []
        self.values = []
    def header(self,offset=None):
        """
        处理包头部分
        :param offset:
        :return:
        """
        self.offset = offset if offset else 0
        self.payload_length = self.packet[self.offset+2] << 16 | self.packet[self.offset+1] << 8 | self.packet[self.offset]
        self.seq_id = self.packet[self.offset+3]
        self.offset += 4

    def check_packet(self):
        """
        检查连接时返回数据包类型
        :return:
        """
        packet_header = self.packet[self.offset]
        self.offset += 1
        if packet_header == 0x00:
            print('connection ok')
            self.__command_prepare()
        elif packet_header in (0xfe,0xff):
            print(self.packet[self.offset:])

    def Send(self):
        self.__recv_data()
        self.server_packet_info = self.unpack_handshake(packet=self.packet,offset=self.offset)
        self.response_packet = self.handshakeresponsepacket(server_packet_info=self.server_packet_info,
                                                            user=self.user,password=self.password,
                                                            database=self.database)
        response_payload = len(self.response_packet)
        self.client.send(self.Prepar_head(response_payload,self.seq_id + 1) + self.response_packet)
        self.__recv_data()
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
                self.__recv_data()
                self.check_packet()

        elif packet_header == 0x00:
            if len(self.packet) > 7:
                print('ok packet')
                self.__command_prepare()


    def __unpack_text_packet(self):
        """
        获取Text Resultset并解析数据
        :return:
        """
        column_count = struct.unpack('B',self.packet[self.offset:self.offset + self.payload_length])[0]
        self.offset += self.payload_length
        for i in range(column_count):
            self.header(offset=self.offset)
            self.column_info.append(self.unpack_text_column(self.packet[self.offset:self.offset+self.payload_length]))
            self.offset += self.payload_length

        while 1:
            _v = []
            self.header(offset=self.offset)
            packet_header = self.packet[self.offset]
            if packet_header in (0xfe, 0xff, 0x00):
                break
            self.values.append(self.unpack_text_values(self.packet[self.offset:self.offset+self.payload_length],
                                                       self.column_info,self.payload_length))
            self.offset += self.payload_length

        if self.type:
            pass
        else:
            print(self.column_info)
            for row in self.values:
                print(row)


    def __prepared_statements(self):
        """
        mysql端执行prepare语句
        """
        _pre_packet = self.COM_STMT_PREPARE(sql=self.sql)
        stmt_prepare_packet = self.Prepar_head(len(_pre_packet), self.next_seq_id) + _pre_packet
        self.client.send(stmt_prepare_packet)
        self.__recv_data(result=True)

        flags = {'NO_CURSOR':0x00,'READ_ONLY':0x01,'FOR_UPDATE':0x02,'SCROLLABLE':0x04}

        if self.packet[self.offset] == 0x00:
            self.statement_id, num_columns, self.num_params = self.com_prepare_ok(self.packet[self.offset:self.offset+self.payload_length])
            self.offset += self.payload_length
            for i in range(num_columns + self.num_params):
                self.header(self.offset)
                if i >= self.num_params:
                    self.column_info.append(self.unpack_text_column(self.packet[self.offset:self.offset + self.payload_length]))
                self.offset += self.payload_length



        execute_pack = self.COM_STMT_EXECUTE(statement_id=self.statement_id,flags=flags['NO_CURSOR'],
                                             num_params=self.num_params,values=self.pre_values,column_info=self.column_info)
        execute_pack = self.Prepar_head(len(execute_pack),self.next_seq_id) + execute_pack
        self.client.send(execute_pack)
        self.__recv_data(result=True)

        column_count = struct.unpack('B', self.packet[self.offset:self.offset + self.payload_length])[0]
        self.offset += self.payload_length
        for i in range(column_count):
            self.header(self.offset)
            #self.column_info.append(self.unpack_text_column(self.packet[self.offset:self.offset + self.payload_length]))
            self.offset += self.payload_length

        values = []
        col_types = []
        for col in self.column_info:
            col_types.append(col['type'])

        while 1:
            self.header(self.offset)
            _header = struct.unpack('B',self.packet[self.offset:self.offset+1])[0]
            self.offset += 1
            if _header == 0xfe:
                break
            elif _header == 0x00:
                values.append(self.unpack_binary_protocol(self.packet[self.offset:self.offset+self.payload_length-1],col_types))
                self.offset += self.payload_length -1

        print('|'.join([col['name'].decode() for col in self.column_info]))
        for row in values:
            print(tuple(row))


    def __command_prepare(self):
        """
        执行sql
        :return:
        """
        self.next_seq_id = 0
        if self.type == 'pre':
            self.__prepared_statements()
        else:
            _com_packet = self.COM_Query(self.sql)
            com_packet = self.Prepar_head(len(_com_packet),self.next_seq_id) + _com_packet
            self.client.send(com_packet)
            self.__recv_data(result=True)
            self.__unpack_text_packet()

    def __recv_data(self,result=None):
        """
        接收数据
        :param result:
        :return:
        """
        _packet = b''
        self.packet = b''
        state = 0
        while 1:
            try:
                _packet = self.client.recv(self.BUFSIZ)
                self.packet += _packet
                if result is None:
                    break
                state = 0
            except:
                state += 1
                if state >=3:
                    break

        self.header()

    def close(self):
        self.client.close()



# prepare语句执行
sql = 'select * from information_schema.tables where table_schema=?'
values = {'table_schema':'information_schema'}
with closing(TcpClient('192.168.10.12:3306','root','root','',sql,values,'pre')) as tcpclient:
    tcpclient.Send()

# 语句直接执行
# sql = 'select * from information_schema.tables'
# values = {'table_schema':'information_schema'}
# with closing(TcpClient('192.168.10.12:3306','root','root','',sql,values,'')) as tcpclient:
#     tcpclient.Send()