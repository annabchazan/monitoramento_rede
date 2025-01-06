import threading
import time
from scapy.all import sniff
import psutil

# Função para captura e análise de pacotes
def capture_packets():
    def process_packet(packet):
        print(f"[PACOTE] {packet.summary()}")
    
    print("Iniciando captura de pacotes...")
    sniff(iface="Wi-Fi", prn=process_packet, count=10)  # Substitua "eth0" pela sua interface de rede

# Função para monitoramento de largura de banda
def monitor_bandwidth():
    old_value = psutil.net_io_counters()
    print("Monitorando largura de banda... Pressione Ctrl+C para sair.")
    
    while True:
        try:
            time.sleep(1)
            new_value = psutil.net_io_counters()
            upload_speed = (new_value.bytes_sent - old_value.bytes_sent) / 1024  # KB/s
            download_speed = (new_value.bytes_recv - old_value.bytes_recv) / 1024  # KB/s
            print(f"[REDE] Upload: {upload_speed:.2f} KB/s | Download: {download_speed:.2f} KB/s")
            old_value = new_value
        except KeyboardInterrupt:
            print("\nMonitoramento encerrado.")
            break

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
