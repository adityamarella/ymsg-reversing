#!/usr/bin/env python

import sys
import os
import socket
import urllib2, urllib
import hashlib, base64

TOKEN_URL='https://login.yahoo.com/config/pwtoken_get?src=ymsgr&ts='
LOGIN_URL='https://login.yahoo.com/config/pwtoken_login?src=ymsgr&ts='

class YMSG:

    _separator=chr(0xc0)+chr(0x80)

    def __init__(self, server, port):
        self.server=server
        self.port=port
        self.sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.server, self.port))
        self.session_dict={}

    def login(self, username, passwd):
        #import pdb; pdb.set_trace()

        #send auth packet to get the challenge string
        req_data=self._get_auth_data(username)
        req_header=self._get_header(0x0057, len(req_data))
        self.sock.send(req_header+req_data)
        data=self.sock.recv(4096) #TODO remove hardcoding
        chal_dict=self._data2dict(data[len(req_header):])
        print chal_dict

        # 2 https requests follow, first one fetches token, 
        # 2nd one actually gets the passwd crumb
        token_url=TOKEN_URL
        token_url+="&login=%s"%(username)
        token_url+="&passwd=%s"%(passwd)
        token_url+="&chal=%s"%urllib.quote(chal_dict['94'])
        data=urllib2.urlopen(token_url).read() #TODO catch url exception 
        if int(data[0])!=0:
           print "token error: %s"%data
           sys.exit(1)
        token_dict=self._data2dict1(data)
        print token_dict
        
        # getting the passwd crumb
        login_url=LOGIN_URL+"&token="+urllib.quote(token_dict['ymsgr'])
        data=urllib2.urlopen(login_url).read() #TODO catch url exception
        if int(data[0])!=0:
           print "token login error: %s"%data 
           sys.exit(1)
        login_dict=self._data2dict1(data)

        # encoding the passwd crumb before sending it to auth response
        m=hashlib.md5()
        m.update(login_dict['crumb'].strip())
        m.update(chal_dict['94'].strip())
        #curse yahoo why do they have to do this stupid!? string replacement
        login_dict['digest']=base64.encodestring(m.digest())[:-1].replace("+", ".").replace("/", "_").replace("=", "-")

        print login_dict

        req_data=self._get_auth_resp_data(username, login_dict)
        req_header=self._get_header(0x0054, len(req_data))
        self.sock.send(req_header+req_data)
        data=self.sock.recv(4096) #TODO remove hardcoding
        session_id=0
        for i in [16,17,18,19]:
            session_id=session_id*256+ord(data[i])

        req_data = self._toggle_status() 
        req_header=self._get_header(197, len(req_data), session_id)
        self.sock.send(req_header+req_data)

    def _get_invisible_status(self, target, username):
        d=[('1', username), ('5', target), ('13', '1')]
        data=self._array2data(d)
        data+=self._separator
        return data

    def _toggle_status(self):
        d=[('13', '2')]
        data=self._array2data(d)
        data+=self._separator
        return data

    def _get_picture_request_data(self, target, username):
        d=[('1', username), ('5', target), ('206', '1')]
        data=self._array2data(d)
        data+=self._separator
        return data

    def _get_auth_resp_data(self, username, login_dict):
        d=[('1', username), ('0', username), ('277', login_dict['Y']),
           ('278', login_dict['T']), ('307', login_dict['digest']),
           ('244', '4194239'), ('2', username), ('2', '1'),
           ('135', '9.0.0.1389')]
        data=self._array2data(d)
        data+=self._separator
        return data

    def _get_auth_data(self, username):
        msg='1' 
        msg+=self._separator # field separator
        msg+=username # un
        msg+=self._separator # field separator
        return msg

    def _get_header(self, type, data_length, session_id=0):
        '''
           type='0x0057' stands for auth request
               ='0x0054' stands for auth resp request
               ='0x00BE' stands for picture req
        '''
        msg='YMSG'
        msg+=chr(0)+chr(15) # version number 
        msg+=chr(0)+chr(0) # empty 2 bytes dont know why
        msg+=chr(data_length/256)+chr(data_length%256) # data length
        msg+=chr(type>>8)+chr(type%256) # W indicates auth request
        msg+=chr(0)+chr(0)+chr(0)+chr(0) # empty 4 bytes dont know why
        msg+=chr((session_id>>24)%256)+chr((session_id>>16)%256)+chr((session_id>>8)%256)+chr(session_id%256) # session id
        return msg

    def _array2data(self, d):
        data=''
        for k,v in d:
            if data:
                data+=self._separator
            data+=k+self._separator+v
        return data
            
    def _data2dict(self, data):
        h={}
        lst=data.split(self._separator)
        for i in range(len(lst)):
            if i%2==1:
                h[lst[i-1]]=lst[i]    
        return h

    def _data2dict1(self, data):
        h={}
        lst=data.split('\r\n')
        for item in lst:
            arr=item.split("=",1)
            if len(arr)==2:
                h[arr[0]]=arr[1]
        return h

def main():
    
    print "Initializing.. "
    p=YMSG("scs.msg.yahoo.com", 5050)
    p.login("", "")

if __name__=='__main__':
    sys.exit(main())



