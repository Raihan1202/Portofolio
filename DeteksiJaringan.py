from scapy.all import ARP, Ether, srp

# Fungsi untuk mendeteksi perangkat terhubung
def scan_devices(target_ip):
    # Buat permintaan ARP untuk mendapatkan daftar perangkat yang terhubung
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Kirim permintaan ARP dan terima respons
    result = srp(packet, timeout=3, verbose=0)[0]

    # Daftar perangkat terhubung
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

if __name__ == "__main__":
    # Ganti dengan alamat IP subnet Anda atau jaringan yang ingin Anda pindai
    target_ip = "192.168.6.110/24"

    # Panggil fungsi untuk mendeteksi perangkat
    devices = scan_devices(target_ip)

    # Tampilkan perangkat yang terhubung
    print("Perangkat yang terhubung ke jaringan:")
    print("IP Address\t\tMAC Address")
    for device in devices:
        print(f"{device['ip']}\t{device['mac']}")
