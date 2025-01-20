# Sistema de Monitoramento de Rede

Este projeto é uma aplicação para monitoramento de rede que captura informações de largura de banda e pacotes de rede, detectando possíveis anomalias. Ele foi desenvolvido com Python e possui uma interface gráfica interativa construída com tkinter.

## Funcionalidades

- **Monitoramento de Largura de Banda**:
  - Mede a velocidade de upload e download.
  - Detecta anomalias com base em limites configurados (em KB/s).
  - Registra os dados em um arquivo CSV (`bandwidth_data.csv`).

- **Captura de Pacotes**:
  - Inspeciona pacotes na interface de rede especificada.
  - Identifica pacotes suspeitos com base em palavras-chave configuradas.
  - Registra os dados em um arquivo CSV (`packet_data.csv`).

- **Interface Gráfica**:
  - Escolha entre monitorar largura de banda, capturar pacotes ou ambos.
  - Exibe logs em tempo real na interface.

## Requisitos

- Python 3.8 ou superior
- Bibliotecas Python:
  - `psutil`
  - `scapy`
  - `tkinter` (nativa do Python)
- Permissões de administrador (para captura de pacotes com `scapy`)

## Instalação

1. Clone este repositório:
   ```bash
   git clone https://github.com/seuusuario/sistema-monitoramento-rede.git
   cd sistema-monitoramento-rede

2. Instale as dependências:
    pip install -r requirements.txt

3. Execute o programa:
    python main.py

## Configuração

Interface de Rede: Altere a variável NETWORK_INTERFACE no código para corresponder à interface de rede que deseja monitorar (por exemplo, Wi-Fi, eth0).

Limites de Largura de Banda: Configure os valores de UPLOAD_LIMIT e DOWNLOAD_LIMIT em KB/s no código para ajustar os parâmetros de anomalia.

Palavras-chave para Pacotes Suspeitos: Adicione ou edite palavras-chave na lista SUSPICIOUS_KEYWORDS para identificar pacotes potencialmente perigosos.

## Uso

Escolha uma das opções na interface gráfica:

Monitorar largura de banda

Capturar pacotes

Executar ambas as funcionalidades

Visualize os logs em tempo real na interface.

Os dados são salvos automaticamente em arquivos CSV:

bandwidth_data.csv: Contém informações de largura de banda.

packet_data.csv: Contém detalhes sobre pacotes capturados.

Para interromper o monitoramento, clique no botão Parar.

### Desenvolvido por Anna Beatriz Chazan, Cauê Agusto e Rafael Vilares
