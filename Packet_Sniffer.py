import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP, TCP, UDP, Raw
import platform
import threading

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        
        # Create and configure the GUI components
        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=20, width=80)
        self.text_area.pack(padx=10, pady=10)

        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        self.sniff_thread = None
        self.sniffing = False

    def packet_callback(self, packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto

            message = f"Source IP: {ip_src}\nDestination IP: {ip_dst}\nProtocol: {protocol}\n"

            if TCP in packet:
                message += f"TCP Source Port: {packet[TCP].sport}\nTCP Destination Port: {packet[TCP].dport}\n"
            elif UDP in packet:
                message += f"UDP Source Port: {packet[UDP].sport}\nUDP Destination Port: {packet[UDP].dport}\n"

            if Raw in packet:
                message += f"Payload: {packet[Raw].load}\n"

            message += "\n"
            self.text_area.insert(tk.END, message)
            self.text_area.yview(tk.END)

    def sniff_packets(self):
        while self.sniffing:
            sniff(prn=self.packet_callback, filter="ip", store=0, timeout=1)

    def start_sniffing(self):
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.sniff_thread = threading.Thread(target=self.sniff_packets)
        self.sniff_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        if self.sniff_thread:
            self.sniff_thread.join()

def main():
    root = tk.Tk()
    app = PacketSnifferApp(root)
    
    current_platform = platform.system()
    if current_platform == 'Windows':
        print("On Windows, ensure you have Npcap installed and running.")
    elif current_platform == 'Linux':
        print("On Linux, you might need to run this script as root.")
    elif current_platform == 'Darwin':
        print("On macOS, you might need to provide additional permissions.")
    else:
        print(f"Running on an unsupported platform: {current_platform}")

    root.mainloop()

if __name__ == "__main__":
    main()
