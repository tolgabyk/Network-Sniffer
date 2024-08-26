import tkinter as tk
from scapy.all import sniff
from collections import Counter
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.animation import FuncAnimation

# Paket türlerine göre sayaç
packet_count = Counter()

# Protokol isimlerini daha okunabilir hale getirmek için bir harita
protocols = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}

# Paket yakalama işlemi için callback fonksiyonu
def packet_sniffer(packet):
    try:
        if packet.haslayer('IP'):
            protocol = packet['IP'].proto
            protocol_name = protocols.get(protocol, str(protocol))

            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst

            # Paket türlerine göre sayaç güncelle
            packet_count[protocol_name] += 1

            print(f"Protocol: {protocol_name}")
            print(f"Source IP: {src_ip}")
            print(f"Destination IP: {dst_ip}")
            print(packet.summary())  # Paketin özetini gösterir
            print("-" * 50)

    except AttributeError:
        pass  # Paket beklenen katmana sahip değilse, hatayı yoksay

# Grafik güncelleme fonksiyonu
def update_graph(i):
    ax.clear()
    ax.bar(packet_count.keys(), packet_count.values(), color='blue')
    ax.set_xlabel('Protokoller')
    ax.set_ylabel('Paket Sayısı')
    ax.set_title('Yakalanan Paketlerin Protokollere Göre Dağılımı')

# Tkinter arayüzünü oluşturma
def create_gui():
    global ax

    root = tk.Tk()
    root.title("Network Packet Sniffer")

    # Matplotlib grafiğini Tkinter arayüzüne entegre et
    fig, ax = plt.subplots()
    canvas = FigureCanvasTkAgg(fig, master=root)
    canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

    # Grafik güncelleme zamanlayıcısı
    ani = FuncAnimation(fig, update_graph, interval=1000)

    # Paket yakalama işlemini arka planda başlat
    import threading
    sniff_thread = threading.Thread(target=lambda: sniff(prn=packet_sniffer), daemon=True)
    sniff_thread.start()

    # Tkinter ana döngüsünü başlat
    root.mainloop()

if __name__ == "__main__":
    create_gui()
