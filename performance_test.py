# performance_test.py
import os
import subprocess

def measure_latency(target_ip):
    """
    Ping kullanarak hedef IP'ye gecikme (RTT) ölçümü yapar.
    """
    response = os.popen(f"ping -c 4 {target_ip}").read()
    print(response)

def measure_bandwidth(server_ip):
    """
    iPerf3 kullanarak bant genişliği ölçümü yapar.
    """
    print("[*] Bant genişliği ölçümü başlatılıyor...")
    subprocess.call(["iperf3", "-c", server_ip])

if __name__ == "__main__":
    print("1. Gecikme Ölçümü\n2. Bant Genişliği Ölçümü")
    choice = input("Seçiminiz: ")

    target = input("Hedef IP adresi: ")

    if choice == "1":
        measure_latency(target)
    elif choice == "2":
        measure_bandwidth(target)
    else:
        print("Geçersiz seçim.")
