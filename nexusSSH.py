#!/usr/bin/env python
import argparse
import threading
import socket
import sys
import os
import traceback
import logging
import json
import logging
import paramiko
from datetime import datetime
from binascii import hexlify
from paramiko.py3compat import b, u, decodebytes
import io

HOST_KEY_DATA = b'''
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAsbMRxAENs+mmCIBf9Dey75ELC5U7HJRm1VIHd/2TuzHpg5h3GNoJ
6AOqclLH2d0qEP13rpYMbl73FwpGYR7bCwuYYxKO5zNrZV0+RvUVpXhvLDcVW4LLukXzJ6
9iqKK+bYRuPoNbfD4imSGwaID+9VzUY03DP6zM3IwRKPWcH5l5X94oH9aVXVPjV+Jo3K6K
KXVTO19HHLh0f4ip2kid6nB3CQpOaMYzMhA7fJRLpBtU1NisJcRyxSglTPdAcyQDWsOx0v
XwksNguUFNjU8ohSlRcLxfp1PIRyuSCPX1tPlnqryB22NiiLPCtUm30B3paA1mU3t7uw2A
iWl9BsXHTQAAA8iH2ULYh9lC2AAAAAdzc2gtcnNhAAABAQCxsxHEAQ2z6aYIgF/0N7LvkQ
sLlTsclGbVUgd3/ZO7MemDmHcY2gnoA6pyUsfZ3SoQ/XeulgxuXvcXCkZhHtsLC5hjEo7n
M2tlXT5G9RWleG8sNxVbgsu6RfMnr2Koor5thG4+g1t8PiKZIbBogP71XNRjTcM/rMzcjB
Eo9ZwfmXlf3igf1pVdU+NX4mjcroopdVM7X0ccuHR/iKnaSJ3qcHcJCk5oxjMyEDt8lEuk
G1TU2KwlxHLFKCVM90BzJANaw7HS9fCSw2C5QU2NTyiFKVFwvF+nU8hHK5II9fW0+WeqvI
HbY2KIs8K1SbfQHeloDWZTe3u7DYCJaX0GxcdNAAAAAwEAAQAAAQAcBq5TX8gpuzzOw/J+
ScecrZ9UlxeA2S4D0IFxjQqfAE8ATIxiHMdpsqRQDhrLk2xmTBezbyJsSOmHFn2FpVBuRE
inPX7Q26UBUmy3U8GzfJRqIJDrgyw/B3fDZ0+z4aEPlE6v6NdFt+YMiUnxnYC4sYik1deo
xAf2c9fkAiK6v95h8r+f4igtNj2Lh/d+fhGt3sTxoATYzzsmFtVIzVzCQ/VIV1PaNYzvTa
XHFA8IsyMEL/TEV7AdhSrtaqCDf6an7JNH15QVNNkL9s6K9YFGCgvZD77hawBO1SOlj8lH
U8EHODV1G4i0WNCtvYmsemLjQOmLBGC6Uc8IxN2dU7TJAAAAgQCwkTUK2t8iuPPWXWQ8iM
1YEF9Jmjyq1OBQ1fJfy1YZeJMjB1gXn2rgNxvlEHhHnwJlVAXoiBPuIH3llPy9x6Owkd2/
R777Cdlzf32QvEsQgCBMhBquxNgeyrtvHfZZPl8p58kwmuAupbGRlQq0he+GpRale9uf8B
hzOu1eujJQBAAAAIEA2Fq46tjHsEXIpfVxijlyFJN8Q2EBMxmlc2Up7fvH/BjWtkMlH8S0
lskIIZ9Q5M0Nl1Cg1RMWX3HVcHQz/kZdz+6cD7hjMn7SFz985pr8EKF2z8jZtiQXJZHDMC
rBHCUlA29Y1R4wnm7oiHtW23gpCiM6zXoxFnut/9SCazjkGKUAAACBANJDB339sms6aw38
WzwihPrJDOLwtvGPEzpuX+nXBOZb266fpuZ35h2/jDHlMV5QUNw52V3kXDiOzPorBPrhH/
poEZXYmMzIVg75VyqNJj2HPuu0z8KRGm0trbf1wv+8195kA5rGZke/YXVeeytNEEyINoTp
tpW/zW+EK1/Kl4uJAAAADHJvb3RAcXMyODIyMQECAwQFBg==
-----END OPENSSH PRIVATE KEY-----
'''


HOST_KEY = paramiko.RSAKey(filename='/home/samt/SSH-Honeypot/private.key')
SSH_BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"

UP_KEY = '\x1b[A'.encode()
DOWN_KEY = '\x1b[B'.encode()
RIGHT_KEY = '\x1b[C'.encode()
LEFT_KEY = '\x1b[D'.encode()
BACK_KEY = '\x7f'.encode()

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    filename='ssh_honeypot.log')


def handle_cmd(cmd, chan, ip):

    response = ""
    if cmd.startswith("ls"):
        response = "users.txt"
    elif cmd.startswith("pwd"):
        response = "/home/root"

    if response != '':
        logging.info('Response from honeypot ({}): '.format(ip, response))
        response = response + "\r\n"
    chan.send(response)


class BasicSshHoneypot(paramiko.ServerInterface):

    client_ip = None

    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        logging.info('client called check_channel_request ({}): {}'.format(
                    self.client_ip, kind))
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        logging.info('client called get_allowed_auths ({}) with username {}'.format(
                    self.client_ip, username))
        return "publickey,password"

    def check_auth_publickey(self, username, key):
        fingerprint = u(hexlify(key.get_fingerprint()))
        logging.info('client public key ({}): username: {}, key name: {}, md5 fingerprint: {}, base64: {}, bits: {}'.format(
                    self.client_ip, username, key.get_name(), fingerprint, key.get_base64(), key.get_bits()))
        return paramiko.AUTH_PARTIALLY_SUCCESSFUL        

    def check_auth_password(self, username, password):
        # Accept all passwords as valid by default
        logging.info('new client credentials ({}): username: {}, password: {}'.format(
                    self.client_ip, username, password))
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

def check_channel_exec_request(self, channel, command):
    try:
        # Extracting the username from the environment variables
        username = channel.get_name().decode("utf-8").split("@")[0]
        logging.info('client sent command via check_channel_exec_request ({}): {}'.format(
                    self.client_ip, username, command))
    except Exception as e:
        logging.error('Error extracting username from environment variables: {}'.format(str(e)))

    return True



def handle_connection(client, addr):

    client_ip = addr[0]
    logging.info('New connection from: {}'.format(client_ip))
    print('New connection is here from: {}'.format(client_ip))

    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(HOST_KEY)
        transport.local_version = SSH_BANNER # Change banner to appear more convincing
        server = BasicSshHoneypot(client_ip)
        try:
            transport.start_server(server=server)

        except paramiko.SSHException:
            print('*** SSH negotiation failed.')
            raise Exception("SSH negotiation failed")

        # wait for auth
        chan = transport.accept(10)
        if chan is None:
            print('*** No channel (from '+client_ip+').')
            raise Exception("No channel")
        
        chan.settimeout(10)

        if transport.remote_mac != '':
            logging.info('Client mac ({}): {}'.format(client_ip, transport.remote_mac))

        if transport.remote_compression != '':
            logging.info('Client compression ({}): {}'.format(client_ip, transport.remote_compression))

        if transport.remote_version != '':
            logging.info('Client SSH version ({}): {}'.format(client_ip, transport.remote_version))
            
        if transport.remote_cipher != '':
            logging.info('Client SSH cipher ({}): {}'.format(client_ip, transport.remote_cipher))

        server.event.wait(10)
        if not server.event.is_set():
            logging.info('** Client ({}): never asked for a shell'.format(client_ip))
            raise Exception("No shell request")
     
        try:
            chan.send("Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-128-generic x86_64)\r\n\r\n")
            run = True
            while run:
                chan.send("$ ")
                command = ""
                while not command.endswith("\r"):
                    transport = chan.recv(1024)
                    print(client_ip+"- received:",transport)
                    # Echo input to psuedo-simulate a basic terminal
                    if(
                        transport != UP_KEY
                        and transport != DOWN_KEY
                        and transport != LEFT_KEY
                        and transport != RIGHT_KEY
                        and transport != BACK_KEY
                    ):
                        chan.send(transport)
                        command += transport.decode("utf-8")
                
                chan.send("\r\n")
                command = command.rstrip()
                logging.info('Command receied ({}): {}'.format(client_ip, command))

                if command == "exit":
                    settings.addLogEntry("Connection closed (via exit command): " + client_ip + "\n")
                    run = False

                else:
                    handle_cmd(command, chan, client_ip)

        except Exception as err:
            print('!!! Exception: {}: {}'.format(err.__class__, err))
            try:
                transport.close()
            except Exception:
                pass

        chan.close()

    except Exception as err:
        print('!!! Exception: {}: {}'.format(err.__class__, err))
        try:
            transport.close()
        except Exception:
            pass


def start_server(port, bind):
    """Init and run the ssh server"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind, port))
    except Exception as err:
        print('*** Bind failed: {}'.format(err))
        traceback.print_exc()
        sys.exit(1)

    threads = []
    while True:
        try:
            sock.listen(100)
            print('Listening for connection on port {} ...'.format(port))
            client, addr = sock.accept()
        except Exception as err:
            print('*** Listen/accept failed: {}'.format(err))
            traceback.print_exc()
        new_thread = threading.Thread(target=handle_connection, args=(client, addr))
        new_thread.start()
        threads.append(new_thread)

    for thread in threads:
        thread.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run an SSH honeypot server')
    parser.add_argument("--port", "-p", help="The port to bind the ssh server to (default 22)", default=2222, type=int, action="store")
    parser.add_argument("--bind", "-b", help="The address to bind the ssh server to", default="", type=str, action="store")
    args = parser.parse_args()
    start_server(args.port, args.bind)

