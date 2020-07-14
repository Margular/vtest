#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import getopt
import hashlib
import json
import re
import socket
import socketserver
import sqlite3
import struct
import sys
import threading

from flask import Flask, jsonify, request
from flask_httpauth import HTTPBasicAuth

app = Flask(__name__)
auth = HTTPBasicAuth()
ROOT_DOMAIN = ''
DB = None
REBIND_CACHE = []
LOCAL_IP = ''
PASSWORD = 'admin'


def md5(src):
    m2 = hashlib.md5()
    m2.update(src.encode())
    return m2.hexdigest()


def is_ip(ip):
    p = re.compile(r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
    if p.match(ip):
        return ip
    else:
        return '3.3.3.3'


API_TOKEN = md5("ded08972cead38d6ed8f485e5b65b4b6" + PASSWORD)


@auth.verify_password
def verify_pw(username, password):
    if username == 'admin' and password == PASSWORD:
        return 'true'
    return None


class Sqlite:
    def __init__(self):
        self.conn = sqlite3.connect('vtest.db', check_same_thread=False)
        self._init_db()

    def _init_db(self):
        cursor = self.conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS xss(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name varchar(30) NOT NULL,
            source_ip varchar(20) NOT NULL,
            location text,
            toplocation text,
            opener text,
            cookie text,
            insert_time datetime
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS mock(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name varchar(254) NOT NULL,
            code integer,
            headers text,
            body text,
            insert_time datetime
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS dns_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name text,
            domain text,
            ip text,
            "from" text,
            insert_time datetime
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS http_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url text,
            headers text,
            data text,
            ip text,
            "from" text,
            insert_time datetime
        )
        ''')
        cursor.close()
        self.conn.commit()

    def exec_sql(self, sql, *arg):
        # print sql
        result = []
        cursor = self.conn.cursor()
        rows = cursor.execute(sql, arg)
        for v in rows:
            result.append(v)
        cursor.close()
        self.conn.commit()
        return result


class DNSFrame:
    def __init__(self, data):
        (self.id, self.flags, self.quests, self.answers, self.author, self.addition) = \
            struct.unpack('>HHHHHH', data[0:12])
        self.query_type, self.query_name, self.query_bytes = self._get_query(data[12:])
        self.answer_bytes = None

    def _get_query(self, data):
        i = 1
        name = ''
        while True:
            d = data[i]
            if d == 0:
                break
            if d < 32:
                name = name + '.'
            else:
                name = name + chr(d)
            i = i + 1
        query_bytes = data[0:i + 1]
        (_type, classify) = struct.unpack('>HH', data[i + 1:i + 5])
        query_bytes += struct.pack('>HH', _type, classify)
        return _type, name, query_bytes

    def _get_answer_getbytes(self, ip):
        ttl = 0
        answer_bytes = struct.pack('>HHHLH', 49164, 1, 1, ttl, 4)
        s = ip.split('.')
        answer_bytes = answer_bytes + \
                       struct.pack('BBBB', int(s[0]), int(s[1]), int(s[2]), int(s[3]))
        return answer_bytes

    def get_query_domain(self):
        return self.query_name

    def setip(self, ip):
        self.answer_bytes = self._get_answer_getbytes(ip)

    def getbytes(self):
        res = struct.pack('>HHHHHH', self.id, 33152, self.quests, 1, self.author, self.addition)
        res += self.query_bytes + self.answer_bytes
        return res


class DNSUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        client_address = self.client_address[0]
        dns = DNSFrame(data)
        socket_u = self.request[1]
        a_map = DNSServer.A_map
        if dns.query_type == 1:
            domain = dns.get_query_domain()

            ip = '1.1.1.1'
            pre_data = domain.replace('.' + ROOT_DOMAIN, '')

            if pre_data in a_map:
                # 自定义的dns记录，保留着
                ip = a_map[pre_data]
            elif pre_data.count('.') == 3:
                # 10.11.11.11.test.com 即解析为 10.11.11.11
                ip = is_ip(pre_data)
            elif pre_data.count('.') == 7:
                # 114.114.114.114.10.11.11.11.test.com 循环解析，例如第一次解析结果为114.114.114.114，
                # 第二次解析结果为10.11.11.11
                tmp = pre_data.split('.')
                ip_1 = '.'.join(tmp[0:4])
                ip_2 = '.'.join(tmp[4:])
                if tmp in REBIND_CACHE:
                    ip = is_ip(ip_2)
                    REBIND_CACHE.remove(tmp)
                else:
                    REBIND_CACHE.append(tmp)
                    ip = is_ip(ip_1)

            if ROOT_DOMAIN in domain:
                # name = domain.replace('.' + ROOT_DOMAIN, '')
                sql = "INSERT INTO dns_log (name,domain,ip,\"from\",insert_time) \
                    VALUES(?, ?, ?, ?, datetime(CURRENT_TIMESTAMP,'localtime'))"

                DB.exec_sql(sql, pre_data, domain, ip, str(client_address))
            dns.setip(ip)
            print('%s: %s-->%s' % (self.client_address[0], pre_data, ip))
            socket_u.sendto(dns.getbytes(), self.client_address)
        else:
            socket_u.sendto(data, self.client_address)


class DNSServer:
    def __init__(self):
        DNSServer.A_map = {}

    def add_record(self, name, ip):
        DNSServer.A_map[name] = ip

    def start(self):
        server = socketserver.UDPServer(("0.0.0.0", 53), DNSUDPHandler)
        server.serve_forever()


HTML_TEMPLATE = open('template.html').read()


@app.route('/')
@auth.login_required
def index():
    return HTML_TEMPLATE.replace('{domain}', ROOT_DOMAIN).replace('{token}', API_TOKEN), 200


@app.route('/dns')
@auth.login_required
def dns_list():
    result = []
    args = request.values
    offset = int(args.get('offset', 0))
    limit = int(args.get('limit', 10))

    if args.get('search'):
        search = args.get('search')
    else:
        search = ""
    search = "%" + search + "%"

    sql = "SELECT domain,ip,\"from\",insert_time FROM dns_log where domain like ? order by id desc limit ?,?"
    rows = DB.exec_sql(sql, search, offset, limit)

    for v in rows:
        result.append({"domain": v[0], "ip": v[1], "from": v[2], "insert_time": v[3]})
    sql = "SELECT COUNT(*) FROM dns_log"
    rows = DB.exec_sql(sql)
    total = rows[0][0]
    return jsonify({'total': int(total), 'rows': result})


@app.route('/httplog/<path:path>', methods=['GET', 'POST', 'PUT'])
def http_log(path):
    post_data = request.data
    if post_data == '':
        for k, v in request.form.items():
            post_data += k + '=' + v + '&'
        post_data = post_data[:-1]
    args = [
        request.url,
        json.dumps(dict(request.headers)), post_data, request.remote_addr
    ]
    print(request.url, post_data, request.remote_addr, dict(request.headers))
    sql = "INSERT INTO http_log (url,headers,data,ip,insert_time) " \
          "VALUES(?, ?, ?, ?, datetime(CURRENT_TIMESTAMP,'localtime'))"

    DB.exec_sql(sql, *args)
    return 'success'


@app.route('/httplog')
@auth.login_required
def http_log_list():
    result = []
    total = 0
    args = request.values
    offset = int(args.get('offset', 0))
    limit = int(args.get('limit', 10))
    sql = "SELECT url,headers,data,ip,insert_time FROM http_log order by id desc limit {skip},{limit}".format(
        skip=offset, limit=limit)
    rows = DB.exec_sql(sql)
    for v in rows:
        result.append({
            'url': v[0],
            'headers': v[1],
            'data': v[2].decode(),
            'ip': v[3],
            'insert_time': v[4]
        })
    sql = "SELECT COUNT(*) FROM http_log"
    rows = DB.exec_sql(sql)
    total = rows[0][0]
    return jsonify({'total': int(total), 'rows': result})


@app.route('/del/<col>')
@auth.login_required
def del_data(col):
    if col == 'http':
        table = 'http_log'
    elif col == 'dns':
        table = 'dns_log'
    else:
        return jsonify({'status': '0', 'msg': 'unkown table'})

    sql = "Delete FROM {table}".format(table=table)
    DB.exec_sql(sql)

    return jsonify({'status': 1})


@app.route('/api/<action>')
def api_check(action):
    args = request.values

    if not args.get('token') or args.get('token') != API_TOKEN:
        return jsonify({'status': '0', 'msg': 'error token'})

    offset = int(args.get('offset', 0))
    limit = int(args.get('limit', 10))
    query = args.get('q', '')
    query = "%" + query + "%"

    result = []
    if action == 'dns':
        sql = "SELECT domain,ip,insert_time FROM dns_log where domain like ? order by id desc limit ?,?"
        rows = DB.exec_sql(sql, query, offset, limit)

        for v in rows:
            result.append({"domain": v[0], "ip": v[1], "insert_time": v[2]})

    elif action == 'http':
        sql = "SELECT url,headers,data,ip,insert_time FROM http_log where url like ? order by id desc limit ?,?"
        rows = DB.exec_sql(sql, query, offset, limit)

        for v in rows:
            result.append({'url': v[0], 'headers': v[1],
                           'data': v[2], 'ip': v[3], 'insert_time': v[4]})
    else:
        return jsonify({'status': '0', 'msg': 'error action, plz http or dns'})

    if not result:
        return jsonify({'status': '0', 'msg': 'no result'})
    else:
        return jsonify({'status': '1', 'rows': result})


def dns():
    d = DNSServer()
    d.add_record('httplog', LOCAL_IP)
    d.add_record('x', LOCAL_IP)
    d.start()


if __name__ == "__main__":
    msg = '''
Usage: python vtest.py -d yourdomain.com [-h 123.123.123.123] [-p password]
    '''
    if len(sys.argv) < 2:
        print(msg)
        exit()
    options, args = getopt.getopt(sys.argv[1:], "d:h:p:")
    for opt, arg in options:
        if opt == '-d':
            ROOT_DOMAIN = arg
        elif opt == '-h':
            LOCAL_IP = arg
        elif opt == '-p':
            PASSWORD = arg
            API_TOKEN = md5("ded08972cead38d6ed8f485e5b65b4b6" + PASSWORD)

    if LOCAL_IP == '':
        sock = socket.create_connection(('ns1.dnspod.net', 6666), 20)
        ip = sock.recv(16)
        sock.close()
        LOCAL_IP = ip
    DB = Sqlite()
    threading.Thread(target=dns).start()
    app.run('0.0.0.0', 80, threaded=True)
