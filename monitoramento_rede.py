import threading
import time
import csv
from scapy.all import sniff
import psutil

# Arquivos CSV
BANDWIDTH_CSV = "bandwidth_data.csv"
PACKET_CSV = "packet_data.csv"

# Limites para detectar anormalidades na largura de banda (em KB/s)
UPLOAD_LIMIT = 1000  # Limite fictício de upload
DOWNLOAD_LIMIT = 2000  # Limite fictício de download

# Palavras-chave para identificar pacotes suspeitos
SUSPICIOUS_KEYWORDS = ["malware", "attack", "exploit"]

# Inicializa arquivos CSV
with open(BANDWIDTH_CSV, mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["Timestamp", "Upload Speed (KB/s)", "Download Speed (KB/s)", "Anormalidade"])

with open(PACKET_CSV, mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["Timestamp", "Packet Summary", "Anormalidade"])

# Função para monitoramento de largura de banda
def monitor_bandwidth():
    old_value = psutil.net_io_counters()
    print("Monitorando largura de banda... Pressione Ctrl+C para sair.")
    
    while True:
        try:
            time.sleep(1)
            new_value = psutil.net_io_counters()
            upload_speed = round((new_value.bytes_sent - old_value.bytes_sent) / 1024, 2)  # KB/s
            download_speed = round((new_value.bytes_recv - old_value.bytes_recv) / 1024, 2)  # KB/s
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            
            # Verificar anormalidades
            upload_anomaly = upload_speed > UPLOAD_LIMIT
            download_anomaly = download_speed > DOWNLOAD_LIMIT

            # Gravar os dados de largura de banda no CSV
            with open(BANDWIDTH_CSV, mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([
                    timestamp, 
                    f"{upload_speed:.2f}", 
                    f"{download_speed:.2f}", 
                    "Sim" if upload_anomaly or download_anomaly else "Nao"
                ])
            
            print(f"[REDE] {timestamp} | Upload: {upload_speed:.2f} KB/s | Download: {download_speed:.2f} KB/s | Anormalidade: {'Sim' if upload_anomaly or download_anomaly else 'Nao'}")
            old_value = new_value
        except KeyboardInterrupt:
            print("\nMonitoramento encerrado.")
            break

# Função para captura e análise de pacotes
def capture_packets():
    def process_packet(packet):
        summary = packet.summary()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        is_suspicious = any(keyword in summary.lower() for keyword in SUSPICIOUS_KEYWORDS)

        # Gravar detalhes do pacote no CSV
        with open(PACKET_CSV, mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([timestamp, summary, "Sim" if is_suspicious else "Nao"])

        print(f"[PACOTE] {summary} | Anormalidade: {'Sim' if is_suspicious else 'Nao'}")
    
    print("Iniciando captura de pacotes...")
    sniff(iface="Wi-Fi 2", prn=process_packet, count=10)  # Substitua "Wi-Fi 2" pela interface correta

# Função principal para rodar as duas funcionalidades em paralelo
def main():
    print("=== Sistema de Monitoramento de Rede ===")
    print("1. Captura de Pacotes")
    print("2. Monitoramento de Largura de Banda")
    print("3. Ambos\n")

    # Escolha do usuário
    choice = input("Escolha uma opção (1/2/3): ").strip()

    if choice == "1":
        capture_packets()
    elif choice == "2":
        monitor_bandwidth()
    elif choice == "3":
        # Executar as duas funcionalidades simultaneamente
        thread1 = threading.Thread(target=capture_packets)
        thread2 = threading.Thread(target=monitor_bandwidth)

        thread1.start()
        thread2.start()

        thread1.join()
        thread2.join()
    else:
        print("Opção inválida. Encerrando o programa.")

if __name__ == "__main__":
    main()
