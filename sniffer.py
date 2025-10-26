from scapy.all import sniff, IP, TCP, UDP, ICMP
import datetime
import iptc
import tkinter as tk
from tkinter import scrolledtext

logs = "logs/firewall_logs.txt"

def log_pack(action,packet):
	with open(logs, "a") as f:
		timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
		f.write(f"[{timestamp}] {action.upper()}:{packet.summary()}\n")

rules = [
	{'action': 'block', 'src_ip':'192.168.1.10', 'dst_port':80, 	'protocol': 'tcp'},
	{'action':'allow', 'protocol': 'icmp'}
	
]
def rule_match(packet):
	if IP in packet:
		src_ip = packet[IP].src
		dst_ip = packet[IP].dst
		proto = None
		src_port = None
		dst_port = None
		
		if TCP in packet:
			proto:'tcp'
			src_port = packet[TCP].sport
			dst_port = packet[TCP].dport
		
		elif UDP in packet:
			proto:'udp'
			src_port = packet[UDP].sport
			dst_port = packet[UDP].dport
		
		elif ICMP in packet:
			proto:'icmp'
		
		for rule in rules:
			if rule.get('protocol') and rule['protocol']!=proto:
				continue
			
			if rule.get('src_ip') and rule['src_ip'] != src_ip:
				continue
			
			if rule.get('dst_ip') and rule['dst_ip'] != dst_ip:
				continue
			
			if rule.get('src_port') and rule['src_port'] != src_port:
				continue
			
			if rule.get('dst_port') and rule['dst_port'] != dst_port:
				continue
				
			return rule['action']
	return 'allow'

def block_ip(IP):
	table = iptc.Table(iptc.Table.FILTER)
	chain = iptc.chain(table, "INPUT")
	rule.src = ip
	target = iptc.Target(rule, "DROP")
	rule.target = Target
	chain.insert_rule(rule)
	print(f"[+] Added iptables rule to block {ip}")
	
def process_packet(packet):
	action =  rule_match(packet)
	update_gui_log(f"{datetime.datetime.now()} - {action.upper()}: {packet.summary()}")

	if action == 'block':
		print(f"Blocked : {packet.summary()}" )
		log_pack('blocked',packet)
	else:
		print(f"Allowd : {packet.summary()}")
		log_pack('allowed',packet)
	
	
		
if __name__ == '__main__':
	sniff(iface = 'eth0', prn = process_packet)

win = tk.Tk()
win.title("Personal Firewall")

log_view = scrolledtext.ScrolledText(win, width = 80, height = 20)
log_view.pack()
			
def update_gui_log(msg):
	log_view.insert(tk.END, msg + "\n")
	log_view.see(tk.END)	
	
win.mainloop()
