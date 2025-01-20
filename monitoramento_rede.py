import threading
import time
import csv
import psutil
from scapy.all import sniff
import tkinter as tk
from tkinter import ttk, messagebox
import os
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import deque
import matplotlib
matplotlib.use('TkAgg')

# Arquivos CSV
BANDWIDTH_CSV = "bandwidth_data.csv"
PACKET_CSV = "packet_data.csv"

# Limites para detectar anormalidades
UPLOAD_LIMIT = 1000
DOWNLOAD_LIMIT = 2000
SUSPICIOUS_KEYWORDS = ["malware", "attack", "exploit"]

# Variáveis para armazenar dados dos gráficos
MAX_POINTS = 60  # Mostrar último minuto de dados
timestamps = deque(maxlen=MAX_POINTS)
upload_speeds = deque(maxlen=MAX_POINTS)
download_speeds = deque(maxlen=MAX_POINTS)
packet_counts = deque(maxlen=MAX_POINTS)

stop_threads = threading.Event()
NETWORK_INTERFACE = "Wi-Fi 2"

def initialize_csv(file_path, header):
    if not os.path.exists(file_path):
        with open(file_path, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(header)

# [Todas as importações e variáveis globais permanecem iguais até a classe NetworkMonitor]

class NetworkMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Sistema de Monitoramento de Rede")
        
        # Configurar geometria da janela
        window_width = 800
        window_height = 600
        
        # Centralizar a janela na tela
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        center_x = int(screen_width/2 - window_width/2)
        center_y = int(screen_height/2 - window_height/2)
        self.root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')
        
        # Frame principal
        self.main_frame = ttk.Frame(root, padding="5")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configurar redimensionamento
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        self.main_frame.columnconfigure(0, weight=1)
        
        # Configuração dos gráficos
        self.setup_graphs()
        
        # Interface de controle
        self.setup_controls()
        
        # Inicializar dados
        for _ in range(MAX_POINTS):
            timestamps.append("")
            upload_speeds.append(0)
            download_speeds.append(0)
            packet_counts.append(0)
        
        # Flag para controle de atualização
        self.is_monitoring = False
    
    def setup_graphs(self):
        # Criar figura com tamanho menor
        self.fig = Figure(figsize=(8, 4), dpi=100)
        self.ax1 = self.fig.add_subplot(211)
        self.ax2 = self.fig.add_subplot(212)
        
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.main_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().grid(row=3, column=0, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
    
    # [Todas as importações e variáveis globais permanecem iguais até o método setup_controls]

    def setup_controls(self):
        # Frame para controles
        control_frame = ttk.Frame(self.main_frame)
        control_frame.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        ttk.Label(control_frame, text="Escolha uma opção:").pack(side=tk.LEFT, padx=5)
        self.option_var = tk.StringVar(value="1")
        
        # Organizar radiobuttons horizontalmente
        for i, option in enumerate([("1", "Monitorar Largura de Banda"), ("2", "Capturar Pacotes")]):
            ttk.Radiobutton(control_frame, text=option[1], variable=self.option_var, 
                           value=option[0]).pack(side=tk.LEFT, padx=5)
        
        # Frame para botões
        button_frame = ttk.Frame(self.main_frame)
        button_frame.grid(row=1, column=0, pady=5, sticky=(tk.W, tk.E))
        
        ttk.Button(button_frame, text="Iniciar", command=self.start_monitoring).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Parar", command=self.stop_monitoring).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Sair", command=self.root.quit).pack(side=tk.LEFT, padx=5)
        
        # Frame para o log box e scrollbar
        log_frame = ttk.Frame(self.main_frame)
        log_frame.grid(row=4, column=0, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        log_frame.columnconfigure(0, weight=1)  # Fazer o log box expandir horizontalmente
        
        # Log box com tamanho aumentado
        self.log_box = tk.Text(log_frame, wrap="word", height=15, width=90)  # Aumentei height e width
        self.log_box.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Scrollbar vertical para o log box
        scrollbar_v = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_box.yview)
        scrollbar_v.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Scrollbar horizontal para o log box
        scrollbar_h = ttk.Scrollbar(log_frame, orient="horizontal", command=self.log_box.xview)
        scrollbar_h.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Configurar scrollbars
        self.log_box.configure(yscrollcommand=scrollbar_v.set, xscrollcommand=scrollbar_h.set, wrap="none")
        
        # Ajustar o tamanho da janela principal
        window_width = 1000  # Aumentei a largura
        window_height = 800  # Aumentei a altura
        
        # Centralizar a janela na tela
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        center_x = int(screen_width/2 - window_width/2)
        center_y = int(screen_height/2 - window_height/2)
        self.root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')


    
    def update_graphs(self):
        if not self.is_monitoring:
            return
        
        self.ax1.clear()
        self.ax2.clear()
        
        # Atualizar gráfico de largura de banda
        self.ax1.plot(list(timestamps), list(upload_speeds), label='Upload', color='blue')
        self.ax1.plot(list(timestamps), list(download_speeds), label='Download', color='green')
        self.ax1.set_title('Largura de Banda em Tempo Real', pad=2)
        self.ax1.set_ylabel('KB/s', labelpad=2)
        self.ax1.legend(loc='upper right', fontsize='small')
        self.ax1.grid(True)
        
        # Atualizar gráfico de pacotes
        self.ax2.bar(list(timestamps), list(packet_counts), color='red', alpha=0.6)
        self.ax2.set_title('Contagem de Pacotes por Segundo', pad=2)
        self.ax2.set_ylabel('Pacotes', labelpad=2)
        self.ax2.grid(True)
        
        # Rotacionar e ajustar labels
        for ax in [self.ax1, self.ax2]:
            ax.tick_params(axis='x', rotation=45, labelsize=8)
            ax.tick_params(axis='y', labelsize=8)
        
        self.fig.tight_layout()
        self.canvas.draw()
        
        if self.is_monitoring:
            self.root.after(1000, self.update_graphs)

    
    def monitor_bandwidth(self):
        old_value = psutil.net_io_counters()
        self.log_box.insert(tk.END, "Monitorando largura de banda...\n")
        self.log_box.see(tk.END)
        
        while self.is_monitoring:
            try:
                time.sleep(1)
                new_value = psutil.net_io_counters()
                upload_speed = round((new_value.bytes_sent - old_value.bytes_sent) / 1024, 2)
                download_speed = round((new_value.bytes_recv - old_value.bytes_recv) / 1024, 2)
                timestamp = time.strftime("%H:%M:%S")
                
                timestamps.append(timestamp)
                upload_speeds.append(upload_speed)
                download_speeds.append(download_speed)
                
                if not packet_counts:  # Se ainda não houver contagem de pacotes
                    packet_counts.append(0)
                
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
                self.log_box.insert(tk.END, log_message)
                self.log_box.see(tk.END)
                
                old_value = new_value
            except Exception as e:
                self.log_box.insert(tk.END, f"Erro no monitoramento de largura de banda: {e}\n")
                self.log_box.see(tk.END)
                break
    
    def capture_packets(self):
        packet_count = 0
        last_second = time.time()
        
        def process_packet(packet):
            nonlocal packet_count, last_second
            current_time = time.time()
            
            if current_time - last_second >= 1:
                timestamps.append(time.strftime("%H:%M:%S"))
                packet_counts.append(packet_count)
                packet_count = 0
                last_second = current_time
            
            packet_count += 1
            
            summary = packet.summary()
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            is_suspicious = any(keyword in summary.lower() for keyword in SUSPICIOUS_KEYWORDS)
            
            with open(PACKET_CSV, mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([timestamp, summary, "Sim" if is_suspicious else "Nao"])
            
            log_message = f"[PACOTE] {summary} | Anormalidade: {'Sim' if is_suspicious else 'Nao'}\n"
            self.log_box.insert(tk.END, log_message)
            self.log_box.see(tk.END)
        
        try:
            sniff(iface=NETWORK_INTERFACE, prn=process_packet, 
                  stop_filter=lambda x: not self.is_monitoring)
        except Exception as e:
            self.log_box.insert(tk.END, f"Erro na captura de pacotes: {e}\n")
            self.log_box.see(tk.END)
    
    def start_monitoring(self):
        self.is_monitoring = True
        option = self.option_var.get()
        
        if option == "1":
            threading.Thread(target=self.monitor_bandwidth, daemon=True).start()
        elif option == "2":
            threading.Thread(target=self.capture_packets, daemon=True).start()
        
        self.update_graphs()
    
    def stop_monitoring(self):
        self.is_monitoring = False
        self.log_box.insert(tk.END, "Monitoramento parado.\n")
        self.log_box.see(tk.END)

def main():
    root = tk.Tk()
    app = NetworkMonitor(root)
    root.mainloop()

if __name__ == "__main__":
    initialize_csv(BANDWIDTH_CSV, ["Timestamp", "Upload Speed (KB/s)", "Download Speed (KB/s)", "Anormalidade"])
    initialize_csv(PACKET_CSV, ["Timestamp", "Packet Summary", "Anormalidade"])
    main()
