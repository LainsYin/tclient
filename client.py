#!/usr/bin/env python2.7
# -*-coding:utf-8 -*-

import socket
import signal
import os
import struct
import logging
import ConfigParser
from struct import pack, unpack
from tornado.iostream import StreamClosedError
import tornado.iostream
import tornado.ioloop
from socket import htonl
import hashlib
import time
from random import Random
import threading
from socket import ntohl
import fcntl

STOP = False
THREADS = []
ROOT = os.path.dirname(os.path.abspath(__file__))
BUSINESS_HEADER_LENGTH = 56
BOX_ID = 2
APP_ID = 1

def init_log():
    logging.basicConfig(
        level=logging.DEBUG,
        format='[%(asctime)s - %(process)-6d - %(threadName)-10s - %(levelname)-8s]\t%(message)s',
        datefmt='%a, %d %b %Y %H:%M:%S',
        filename='client.log',
        filemode='w')

    sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    formatter = logging.Formatter('%(levelname)-8s %(message)s')
    sh.setFormatter(formatter)
    logging.getLogger('').addHandler(sh)


def register_options():
    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("-i", "--host", dest="host",
                      default="192.168.1.199", help="specify host, default is 192.168.1.199")
    parser.add_option("-p", "--port", dest="port", type="int",
                      default=58849, help="specify port, default is 58849")
    parser.add_option("-f", "--function", dest="fun", type="int",
                      default=88888, help="specify port, default is 88888")

    parser.add_option("-n", "--num", dest="num", type="int",
                      default=10, help="specify threads num, default is 10")
    parser.add_option("-l", "--length", dest="length", type="int",
                      default=10, help="specify body length, default is 10 bytes")
    parser.add_option("-t", "--time", dest="time",
                      default=1, help="specify threads num, default is 1")

    parser.add_option("-d", "--daemon", dest="daemon",
                      action='store_true',
                      default=True, help="set daemon process, default is true")

    (options, args) = parser.parse_args()
    return options


def get_ip():

    ip = ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1])
    return ip.pop()


def get_md5(body):

    verify = hashlib.md5()
    verify.update(str(time.time()) + body)
    md5 = verify.hexdigest()

    return md5


def random_str(random_length):
    if random_length <= 0:
        return ''

    tmp = ''
    chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789'
    length = len(chars) - 1
    random = Random()
    for i in range(random_length):
        tmp += chars[random.randint(0, length)]
    return tmp


def stop_threads():
    for th in THREADS:
        th.stop()
    global STOP
    STOP = True


def sig_handler(sig, frame):
    stop_threads()


def verify_data(data):
    pass
    if len(data) < 24:
        logging.error('received data length less than 24')

    parts = struct.unpack("6I", data[0:24])
    parts = [str(socket.ntohl(x)) for x in parts]
    header = ', '.join(parts)

    logging.info('received data :  header:%s ' % header)
    logging.info('received data :  body:%s' % data[24:])


class Client(threading.Thread):
    clients = set()

    def __init__(self, ip, port, local_ip, _time):
        Client.clients.add(self)
        threading.Thread.__init__(self)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._address = (ip, port)
        self._add_str = ip + ":" + str(port)
        self.thread_stop = False
        self._md5s = dict()  #每次发送的md5和对应的时间
        self._stream = ""
        self._stop = False
        self._time = _time
        self._ip = local_ip

        logging.info('new connection %d to %s:%d' % (len(Client.clients), self._address[0], self._address[1]))

    def run(self):
        try:
            self._sock.connect(self._address)
        except socket.error, arg:
            (errno, err_msg) = arg
            logging.error('connect server failed: %s, errno=%d' % (err_msg, errno))
            return

        self._stream = tornado.iostream.IOStream(self._sock)
        self._stream.set_close_callback(self.on_close)
        self._stream.read_bytes(24, self.read_header)
        self.send()

    def stop(self):
        self._stop = True
        tornado.ioloop.IOLoop.current().stop()

    def read_header(self, header):
        parts = unpack("6I", header)
        parts = [ntohl(x) for x in parts]

        author, version, request, verify, length, device_id = parts
        logging.debug("read header : (%d, %d, %d, %d, %d, %d) " %
                     (author, version, request, verify, length, device_id))

        self._stream.read_bytes(length, self.read_body)

    """
        md5在body的前32位字节，
        取出md5 在发送时存在self._md5s的查找同一个md5对应的时间
        用但前时间减去self._md5s查找出的时间打印
        收到数据后删除self._md5s的值
    """
    def read_body(self, body):
        md5 = body[:32]
        if self._md5s.get(md5) is not None:
            start_time = self._md5s.pop(md5)
            logging.info("process time: %s " % (time.time() - start_time))
            logging.info("%s , %s " % (start_time, time.time()))
            # logging.debug("read body : %s " % body[32:])

        self._stream.read_bytes(24, self.read_header)

    """
    send 循环发送数据，sleep时间命令参数给定，默认时1s
    在给定发送数据长度会根据random_str()生成一个随机指定长度的字符串
    body ＝ md5(32位) + length(随机字符长度)
    发送结束纪录md5和当前时间
    """
    def send(self):

        while 1:
            header = [17, 100, opts.fun, 65536, 0, 888]
            body_str = random_str(opts.length)
            md5 = get_md5(body_str)
            body = md5 + body_str
            header[4] = len(body)

            elem = [socket.htonl(x) for x in header]
            header_net = pack('6I', *elem)
            msg = header_net + body

            try:
                self._stream.write(msg)
            except StreamClosedError, arg:
                (errno, err_msg) = arg
                logging.error('send msg to server failed: %s, errno=%d' % (err_msg, errno))
                self.stop()
                tornado.ioloop.IOLoop.current().start()
                stop_threads()
                return

            header_str = ', '.join([str(x) for x in header])
            logging.debug('send header: (%d : %s) to %s:%d' % (len(header), header_str,
                                                               self._address[0], self._address[1]))

            self._md5s[md5] = time.time()
            time.sleep(float(self._time))

    def on_close(self):
        logging.debug("disconnect from %s " % self._add_str)
        self._stream.close()


if __name__ == '__main__':

    init_log()
    opts = register_options()
    local_ip = get_ip()
    logging.info('start %d threads to server %s:%d ...' % (opts.num, opts.host, opts.port))
    logging.info('client ip %s ' % local_ip)

    THREADS = []
    for i in xrange(opts.num):
        client = Client(opts.host, opts.port, local_ip, opts.time)
        THREADS.append(client)

    for i in THREADS:
        i.setDaemon(opts.daemon)
        i.start()

    """ register control+c kill thread
    """
    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)
    # master thread to catch signal
    #     while not STOP:
    #         time.sleep(0.01)

    # tornado.ioloop.IOLoop.current().start()

    """主线程等待子线程退出
    """
    for t in THREADS:
        t.join()

    logging.info('stop ...')
