#!/usr/bin/env python
# coding:utf-8
from http.server import HTTPServer, BaseHTTPRequestHandler
import base64
import re

#************⬇不要动这里⬇****************
class Resquest(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=UTF-8')
        self.end_headers()
        self.wfile.write("xia_jie".encode())

    def do_POST(self):
        req_datas = self.rfile.read(int(self.headers['content-length']))
        post_data = req_datas.decode()
        try:
            header = base64.b64decode(re.search('header=(.*?)[^&]*', post_data).group()[7:]).decode().split("\n")
            header.pop()#删除列表中最后一个元素
            body = base64.b64decode(re.search('body=(.*?)[^&]*', post_data).group()[5:]).decode()

            def data_handle(data):
                #对内容进行base64编码
                head_data = ""
                for i in data[0]:
                    head_data+=i+"\n"
                ba64_header = base64.b64encode(head_data.encode()).decode()
                ba64_body = base64.b64encode(data[1].encode()).decode()
                return "header="+ba64_header+"&body="+ba64_body

            if self.path == "/xj_encode":
                data = data_handle(xia_jie.xj_encode(self,header,body))
            elif self.path == "/xj_decode":
                data = data_handle(xia_jie.xj_decode(self,header,body))
            else:
                data = "xia_jie error:api error"
        except Exception as e:
            print(e)
            data = "xia_jie:"+str(e)
        self.send_response(200)
        self.send_header('Content-type', 'text/html;')
        self.end_headers()
        self.wfile.write(data.encode())
#************⬆不要动这里⬆****************


class xia_jie:
    def __init__(self):
        pass

    #加密
    def xj_encode(self, header, body):
        return header, body
    #解密
    def xj_decode(self,header,body):
        return header, body


def run():
    host = ('0.0.0.0', 23002)
    server = HTTPServer(host, Resquest)
    print("run:http://"+host[0]+":"+str(host[1]))
    server.serve_forever()

#启动
run()

#调试
#header = ["POST / HTTP/1.1","host: 127.0.0.1"]
#body = "1111"
#print(xia_jie.xj_encode(0,header,body))
