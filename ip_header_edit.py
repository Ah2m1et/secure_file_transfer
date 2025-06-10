# ip_header_edit.py
from scapy.all import IP, ICMP, send

def send_custom_ping(target_ip, ttl_value=64, custom_flag=False):
    """
    IP başlığı ayarlanmış özel bir ICMP paketi gönderir.
    """
    ip_layer = IP(dst=target_ip, ttl=ttl_value)
    
    if custom_flag:
        ip_layer.flags = "MF"  # More Fragments bayrağını setle

    icmp_layer = ICMP()
    
    packet = ip_layer / icmp_layer
    send(packet)
    print(f"[*] {target_ip} adresine özel ICMP paketi gönderildi.")

if __name__ == "__main__":
    target = input("Hedef IP adresi: ")
    ttl = int(input("TTL değeri (ör: 64): "))
    send_custom_ping(target_ip=target, ttl_value=ttl)
