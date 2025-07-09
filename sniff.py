from scapy.all import sniff

def packet_callback(pkt):
    print(pkt.summary())  # Print packet summary for each captured packet

WIFI_INTERFACE = r"\Device\NPF_{54EC6C67-06C7-4574-A83C-CBB8E167ED15}"
print(f"🔍 Listening on {WIFI_INTERFACE}...")

sniff(iface=WIFI_INTERFACE, count=10, prn=packet_callback)  # Capture 10 packets
