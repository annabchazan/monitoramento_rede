import threading
import time
import csv
import psutil
from scapy.all import sniff
import tkinter as tk
from tkinter import ttk, messagebox

# Arquivos CSV
BANDWIDTH_CSV = "bandwidth_data.csv"
PACKET_CSV = "packet_data.csv"

# Limites para detectar anormalidades na largura de banda (em KB/s)
UPLOAD_LIMIT = 1000  # Limite fictício de upload
DOWNLOAD_LIMIT = 2000  # Limite fictício de download

# Palavras-chave para identificar pacotes suspeitos
SUSPICIOUS_KEYWORDS = ["malware", "attack", "exploit"]

# Variável para controlar a parada das threads
stop_threads = threading.Event()

# Interface de rede a ser utilizada (altere conforme necessário)
NETWORK_INTERFACE = "Wi-Fi"

# Função para monitorar largura de banda
def monitor_bandwidth(log_box):
    old_value = psutil.net_io_counters()
    log_box.insert(tk.END, "Monitorando largura de banda...\n")
    log_box.see(tk.END)

    while not stop_threads.is_set():
        try:
            time.sleep(1)
            new_value = psutil.net_io_counters()
            upload_speed = round((new_value.bytes_sent - old_value.bytes_sent) / 1024, 2)  # KB/s
            download_speed = round((new_value.bytes_recv - old_value.bytes_recv) / 1024, 2)  # KB/s
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

            upload_anomaly = upload_speed > UPLOAD_LIMIT
            download_anomaly = download_speed > DOWNLOAD_LIMIT

            with open(BANDWIDTH_CSV, mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([
                    timestamp, 
                    f"{upload_speed:.2f}", 
                    f"{download_speed:.2f}", 
                    "Sim" if upload_anomaly or download_anomaly else "Nao"
                ])

            log_message = f"[REDE] {timestamp} | Upload: {upload_speed:.2f} KB/s | Download: {download_speed:.2f} KB/s | Anormalidade: {'Sim' if upload_anomaly or download_anomaly else 'Nao'}\n"
            log_box.insert(tk.END, log_message)
            log_box.see(tk.END)

            old_value = new_value
        except Exception as e:
            log_box.insert(tk.END, f"Erro no monitoramento de largura de banda: {e}\n")
            log_box.see(tk.END)
            break

# Função para capturar pacotes
def capture_packets(log_box):
    def process_packet(packet):
        summary = packet.summary()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        is_suspicious = any(keyword in summary.lower() for keyword in SUSPICIOUS_KEYWORDS)

        with open(PACKET_CSV, mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([timestamp, summary, "Sim" if is_suspicious else "Nao"])

        log_message = f"[PACOTE] {summary} | Anormalidade: {'Sim' if is_suspicious else 'Nao'}\n"
        log_box.insert(tk.END, log_message)
        log_box.see(tk.END)

    try:
        sniff(iface=NETWORK_INTERFACE, prn=process_packet, stop_filter=lambda x: stop_threads.is_set())
    except Exception as e:
        log_box.insert(tk.END, f"Erro na captura de pacotes: {e}\n")
        log_box.see(tk.END)

# Função para iniciar as threads
def start_monitoring(option, log_box):
    stop_threads.clear()

    if option == "1":
        threading.Thread(target=monitor_bandwidth, args=(log_box,), daemon=True).start()
    elif option == "2":
        threading.Thread(target=capture_packets, args=(log_box,), daemon=True).start()
    elif option == "3":
        threading.Thread(target=monitor_bandwidth, args=(log_box,), daemon=True).start()
        threading.Thread(target=capture_packets, args=(log_box,), daemon=True).start()

# Função para parar as threads
def stop_monitoring(log_box):
    stop_threads.set()
    log_box.insert(tk.END, "Monitoramento parado.\n")
    log_box.see(tk.END)

# Interface gráfica
def create_gui():
    root = tk.Tk()
    root.title("Sistema de Monitoramento de Rede")

    main_frame = ttk.Frame(root, padding="10")
    main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

    ttk.Label(main_frame, text="Escolha uma opção:").grid(row=0, column=0, sticky=tk.W)
    options = {"1": "Monitorar Largura de Banda", "2": "Capturar Pacotes", "3": "Ambos"}
    option_var = tk.StringVar(value="1")
    for key, value in options.items():
        ttk.Radiobutton(main_frame, text=value, variable=option_var, value=key).grid(sticky=tk.W)

    log_box = tk.Text(main_frame, wrap="word", height=20, width=80)
    log_box.grid(row=3, column=0, pady=10)

    ttk.Button(main_frame, text="Iniciar", command=lambda: start_monitoring(option_var.get(), log_box)).grid(row=4, column=0, pady=5)
    ttk.Button(main_frame, text="Parar", command=lambda: stop_monitoring(log_box)).grid(row=5, column=0, pady=5)
    ttk.Button(main_frame, text="Sair", command=root.quit).grid(row=6, column=0, pady=5)

    root.mainloop()

if __name__ == "__main__":
    with open(BANDWIDTH_CSV, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "Upload Speed (KB/s)", "Download Speed (KB/s)", "Anormalidade"])

    with open(PACKET_CSV, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "Packet Summary", "Anormalidade"])

    create_gui()
