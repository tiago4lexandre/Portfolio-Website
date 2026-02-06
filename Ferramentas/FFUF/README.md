<!-- ===================================== -->
<!--        FFUF — Web Fuzzing Tool        -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Category-Web%20Fuzzing-black?style=for-the-badge">
  <img src="https://img.shields.io/badge/Use-Reconnaissance%20%26%20Discovery-blue?style=for-the-badge">
  <img src="https://img.shields.io/badge/Speed-High%20Performance-green?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Scope-Web%20Pentest-orange?style=flat-square">
  <img src="https://img.shields.io/badge/Attack%20Surface-Directories%20%7C%20Params%20%7C%20VHosts-informational?style=flat-square">
  <img src="https://img.shields.io/badge/Offense-Red%20Team-black?style=flat-square">
  <img src="https://img.shields.io/badge/Defense-Attack%20Surface%20Reduction-lightgrey?style=flat-square">
</p>

---

# ⚡ FFUF — Fuzz Faster U Fool  
## Fuzzing e Enumeração Ativa de Superfície de Ataque em Aplicações Web

> Este documento apresenta um **guia técnico completo sobre o uso do FFUF (Fuzz Faster U Fool)**, uma das ferramentas mais rápidas e flexíveis para **fuzzing web e enumeração ativa** durante testes de penetração e atividades de Red Team.
>
> O FFUF é amplamente utilizado para **descoberta de diretórios, arquivos sensíveis, subdomínios, parâmetros HTTP, endpoints de APIs e vetores de autenticação**, sendo um componente essencial da fase de **Reconnaissance & Discovery** em metodologias modernas de pentest.
>
> O material combina **fundamentos teóricos**, **uso prático em laboratório**, **exemplos realistas**, técnicas de **evasão de WAF/IDS**, controle de **rate limiting** e **integração com outras ferramentas** do ecossistema ofensivo.

---

## 🎯 Objetivos do Documento

- Compreender o **papel do fuzzing na metodologia de Web Pentest**
- Dominar o uso do **FFUF em diferentes superfícies de ataque**
- Realizar **enumeração eficiente e precisa** de conteúdo web
- Aplicar **filtros e matchers avançados** para redução de ruído
- Explorar **parâmetros, headers, cookies e APIs REST**
- Integrar FFUF a pipelines ofensivos com outras ferramentas
- Desenvolver **comandos reprodutíveis e otimizados**

---

## 📌 Metadados Técnicos

- **Ferramenta:** FFUF (Fuzz Faster U Fool)
- **Categoria:** Web Fuzzing · Enumeration · Reconnaissance
- **Linguagem:** Go
- **Protocolos:** HTTP / HTTPS
- **Superfícies:** Diretórios · Arquivos · Subdomínios · Parâmetros · APIs
- **Ambiente:** Linux · Windows · macOS
- **Metodologia:** Recon → Enumeração → Validação → Exploração

---

## 🏷️ Tags

`#FFUF` `#WebFuzzing` `#WebPentest` `#Reconnaissance`  
`#Enumeration` `#BugBounty` `#RedTeam` `#OffensiveSecurity`  
`#APISecurity` `#ContentDiscovery`

---

## ⚠️ Aviso Legal

> Este material é destinado **exclusivamente para fins educacionais**, laboratórios controlados e **ambientes com autorização explícita**.  
> O uso do FFUF contra sistemas sem permissão é **ilegal** e pode resultar em sanções legais.

---

# FFUF (Fuzz Faster U Fool)

## Introdução

**FFUF** é um ferramenta de fuzzing web escrita em Go, projetada para ser rápida e flexível. Permite realizar diversos tipos de testes de segurança, incluindo:

- Enumeração de diretórios e arquivos
- Descoberta de subdomínios
- Fuzzing de parâmetros (GET/POST)
- Brute force de autenticação
- Testes de injeção
- E muito mais

**Principais características:**

- Alta performance (multithreaded)
- Suporte a múltiplos métodos HTTP
- Sistema modular de filtros e matchers
- Suporte a proxies e recursão
- Output formatável (JSON, CSV, etc.)

![FFUF](https://raw.githubusercontent.com/ffuf/ffuf/master/_img/ffuf_run_logo_600.png)

---
## Instalação e Configuração

![Terminal FFUF](https://lh4.googleusercontent.com/PDaKQz2AE6HNT51PRWDQAjb0sj-Br4Rq55SBMHxks3IXhzHxry_a0z_nks4agErn3g23m3s1RTdtOnbdyER0DSTPlfGExoHrwRC2x6ekPXUwzP44KbMLwzix1jcETsF_AZVhMqwtWduNAsNGkftkIlHV0f7AfBI_gYP4Xt_Zeyz1TszEkNuTOFk2ZF8N8Q)

### 1. Instalação no Linux

```bash
# Via apt (Kali Linux)
sudo apt install ffuf

# Via go install
go install github.com/ffuf/ffuf@latest

# Compilar da fonte
git clone https://github.com/ffuf/ffuf
cd ffuf
go get
go build
sudo mv ffuf /usr/local/bin/
```

## 2. Instalação no Windows

```bash
# Via Chocolatey
choco install ffuf

# Download binário
# Baixar de https://github.com/ffuf/ffuf/releases
```

### 3. Verificação da Instalação

```bash
ffuf -h
ffuf -V
```

---
## Conceitos Fundamentais

### 1. Flags Essenciais

|Flag|Descrição|Exemplo|
|---|---|---|
|`-u`|URL alvo|`-u http://target.com/FUZZ`|
|`-w`|Wordlist|`-w /usr/share/wordlists/dirb/common.txt`|
|`-H`|Header customizado|`-H "User-Agent: Mozilla"`|
|`-X`|Método HTTP|`-X POST`|
|`-d`|Data para POST|`-d "user=FUZZ&pass=test"`|
|`-b`|Cookies|`-b "session=abc123"`|
|`-t`|Threads|`-t 100`|
|`-p`|Delay entre requests|`-p 0.1`|
|`-o`|Output file|`-o results.json`|
|`-of`|Output format|`-of json`|

### 2. Placeholders

- `FUZZ`: Substituído por cada palavra da wordlist    
- `BASEWORD`: Mantém a palavra original
- `§`: Alternativa para `FUZZ`

---
## Fuzzing Básico

### 1. Estrutura Básica de Comando

```bash
ffuf -u http://target.com/FUZZ -w wordlist.txt
```

### 2. Exemplo Prático

```bash
# Fuzzing básico com 50 threads
ffuf -u http://10.10.10.10/FUZZ \
	-w /usr/share/wordlists/dirb/common.txt \
	-t 50
	
# Output colorid com filtro de tamanho
ffuf -u http://10.10.10.10/FUZZ \
	-w common.txt
	-fc 404 \
	-c
```

### 3. Flags de Output

```bash
# Output colorido
-c

# Output em JSON
-of json -o results.json

# Output em CSV
-of csv -o results.csv

# Output em HTML
-of html -o results.html
```

---
## Enumeração de Diretórios

### 1. Enumeração Básica

```bash
ffuf -u http://target.com/FUZZ \
     -w /usr/share/wordlists/dirb/common.txt \
     -recursion \
     -recursion-depth 2 \
     -e .php,.html,.bak,.txt \
     -t 100
```

### 2. Enumeração Recursiva Avançada

```bash
ffuf -u http://target.com/FUZZ \
     -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
     -recursion \
     -recursion-depth 3 \
     -e .php,.asp,.aspx,.jsp,.html \
     -mc 200,301,302,403 \
     -fs 0 \
     -t 150 \
     -p 0.2
```

### 3. Filtros por Status Code

```bash
# Incluir apenas códigos específicos
-mc 200,301,302

# Excluir códigos específicos
-fc 404,403,500

# Exemplo combinado
ffuf -u http://target.com/FUZZ \
     -w wordlist.txt \
     -mc 200,301,302 \
     -fc 404,403
```

### 4. Filtros por Tamanho (Size Filtering)

```bash
# Filtrar por tamanho de resposta
fs 1234         # Excluir respostas de 1234 bytes
-fs 1234,5678   # Excluir múltiplos tamanhos

# Filtrar por palavras
fw 10           # Excluir respostas com 10 palavras
fl 100          # Excluir respostas com 100 linhas

# Exemplo prático
ffuf -u http://target.com/FUZZ \
     -w common.txt \
     -fs 100,200,300 \
     -fw 5
```

### 5. Enumeração com Extensões

```bash
# Extensões comuns
-e .php,.html,.txt,.js,.css,.xml,.json

# Extensões de backup
-e .bak,.old,.orig,.save,.swp,.tmp

# Todas as extensões de um arquivo
ffuf -u http://target.com/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt \
     -t 100
```

---
## Enumeração de Subdomínios

### 1. Enumeração Básica

```bash
ffuf -u http://FUZZ.target.com \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
     -H "Host: FUZZ.target.com" \
     -fs 0 \
     -t 200
```

### 2. Enumeração com DNS Wildcard Detection

```bash
# Primeiro detectar wildcard
ffuf -u http://RANDOM123.target.com \
     -w /dev/null \
     -H "Host: RANDOM123.target.com" \
     -fw 0

# Se houver wildcard, usar filtros
ffuf -u http://FUZZ.target.com \
     -w subdomains.txt \
     -H "Host: FUZZ.target.com" \
     -fs 12345  # Tamanho da resposta wildcard
```

### 3.  Enumeração com SSL/TLS

```bash
# Forçar HTTPS
ffuf -u https://FUZZ.target.com \
     -w subdomains.txt \
     -H "Host: FUZZ.target.com" \
     -t 150 \
     -timeout 10
```

### 4. Enumeração com Rate Limiting

```bash
ffuf -u http://FUZZ.target.com \
     -w massive_wordlist.txt \
     -H "Host: FUZZ.target.com" \
     -t 50 \
     -p 0.3 \
     -rate 100 \
     -maxtime 300
```

### 5. Salvando Resultados para VHosts

```bash
ffuf -u http://target.com \
     -w vhosts.txt \
     -H "Host: FUZZ.target.com" \
     -fs 0 \
     -o vhosts.json \
     -of json
```

---
## Fuzzing de Parâmetros GET/POST

### 1. Fuzzing de Parâmetros GET

```bash
# Fuzzing básico de parâmetro
ffuf -u "http://target.com/search.php?q=FUZZ" \
     -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -fs 0 \
     -t 100

# Múltiplos parâmetros
ffuf -u "http://target.com/api.php?param1=FUZZ&param2=test" \
     -w parameters.txt \
     -t 80

# Fuzzing em posições específicas
ffuf -u "http://target.com/FUZZ/page.php" \
     -w params.txt \
     -t 100
```

### 2. Fuzzing de Parâmetros POST

```bash
# POST básico
ffuf -u http://target.com/login.php \
     -X POST \
     -d "username=admin&password=FUZZ" \
     -w passwords.txt \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -fs 0 \
     -mc 302

# POST com JSON
ffuf -u http://target.com/api/login \
     -X POST \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"FUZZ"}' \
     -w rockyou.txt \
     -fs 0
```

### 3. Fuzzing de Headers

```bash
# Fuzzing de header customizado
ffuf -u http://target.com/admin \
     -H "X-API-Key: FUZZ" \
     -w api_keys.txt \
     -t 100 \
     -mc 200

# Múltiplos headers
ffuf -u http://target.com/ \
     -H "User-Agent: FUZZ" \
     -H "Referer: http://FUZZ.com" \
     -w user-agents.txt \
     -t 50
```

### 4. Fuzzing de Cookies

```bash
# Fuzzing de cookie
ffuf -u http://target.com/dashboard \
     -b "session=FUZZ" \
     -w session_tokens.txt \
     -t 80 \
     -mc 200

# Múltiplos cookies
ffuf -u http://target.com/admin \
     -b "session=abc123; auth=FUZZ" \
     -w auth_tokens.txt \
     -t 100
```

---
## Brute Force de Autenticação

### 1. Brute Force de Login Básico

```bash
# Login POST básico
ffuf -u http://target.com/login.php \
     -X POST \
     -d "username=FUZZ&password=FUZ2Z" \
     -w usernames.txt:USER \
     -w passwords.txt:PASS \
     -mode pitchfork \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -fs 0 \
     -mc 302,200
```

### 2. Modos de Fuzzing

```bash
# Clusterbomb (combinatório completo)
-mode clusterbomb

# Pitchfork (paralelo)
-mode pitchfork

# Sniper (um placeholder por vez)
-mode sniper
```

### 3. Brute Force com CSRF Token

```bash
# Primeiro obter token
curl -s http://target.com/login | grep csrf_token

# Depois usar no fuzzing
ffuf -u http://target.com/login \
     -X POST \
     -d "username=FUZZ&password=FUZ2Z&csrf_token=abc123def456" \
     -w usernames.txt:USER \
     -w passwords.txt:PASS \
     -mode pitchfork \
     -H "Cookie: session=xyz789"
```

### 4. Brute Force de API

```bash
# API REST básica
ffuf -u http://target.com/api/v1/login \
     -X POST \
     -H "Content-Type: application/json" \
     -H "X-API-Version: 1.0" \
     -d '{"email":"FUZZ@domain.com","password":"FUZ2Z"}' \
     -w emails.txt:EMAIL \
     -w passwords.txt:PASS \
     -mode pitchfork \
     -fs 0 \
     -mc 200
```

----
## Manipulação de Headers

### 1. Headers Comuns

```bash
# Headers básicos
-H "User-Agent: Mozilla/5.0 (X11; Linux x86_64)" \
-H "Accept: text/html,application/xhtml+xml" \
-H "Accept-Language: en-US,en;q=0.9" \
-H "Connection: keep-alive" \
-H "Upgrade-Insecure-Requests: 1"

# Headers de segurança
-H "X-Forwarded-For: 127.0.0.1" \
-H "X-Real-IP: 127.0.0.1" \
-H "X-Client-IP: 127.0.0.1"
```

### 2. Fuzzing de Headers Personalizados

```bash
# Fuzzing de header de autorização
ffuf -u http://target.com/api/admin \
     -H "Authorization: Bearer FUZZ" \
     -w tokens.txt \
     -t 100 \
     -mc 200

# Fuzzing de Content-Type
ffuf -u http://target.com/upload \
     -X POST \
     -H "Content-Type: FUZZ" \
     -d "test=data" \
     -w content_types.txt \
     -t 50
```

### 3. Headers para Bypass de WAF

```bash
# Bypass básico de WAF
-H "X-Originating-IP: 127.0.0.1" \
-H "X-Forwarded-For: 127.0.0.1" \
-H "X-Forwarded-Host: 127.0.0.1" \
-H "X-Remote-IP: 127.0.0.1" \
-H "X-Remote-Addr: 127.0.0.1" \
-H "X-Client-IP: 127.0.0.1" \
-H "X-Host: 127.0.0.1" \
-H "X-Forwared-Host: 127.0.0.1"

# Headers para CloudFlare bypass
-H "CF-Connecting-IP: 127.0.0.1" \
-H "True-Client-IP: 127.0.0.1"
```

---
## Filtros e Matchers Avançados

### 1. Matchers (Inclusão)

```bash
# Por status code
-mc 200,301,302

# Por palavras no conteúdo
-mw "success\|welcome\|logged"

# Por expressões regulares
-mr "admin.*panel"

# Por linhas
-ml 100

# Por tamanho
-ms 1234

# Por tempo de resposta
-mt 0.5  # 500ms
```

### 2. Filtros (Exclusão)

```bash
# Por status code
-fc 404,403,500

# Por palavras no conteúdo
-fw "error\|not found\|forbidden"

# Por expressões regulares
-fr "error.*page"

# Por linhas
-fl 10

# Por tamanho
-fs 0,100,200

# Por tempo de resposta
-ft 5  # 5 segundos
```

### 3. Exemplos Combinados

```bash
# Filtro complexo
ffuf -u http://target.com/FUZZ \
     -w wordlist.txt \
     -mc 200,301,302 \
     -fc 404,403 \
     -fw "error" \
     -fs 0,100 \
     -t 100
```

### 4. Auto-calibration

```bash
# Auto-calibrate com respostas de erro
-ac

# Auto-calibrate com filtros personalizados
-calibration-strategy advanced

# Exemplo
ffuf -u http://target.com/FUZZ \
     -w wordlist.txt \
     -ac \
     -t 100
```

---
## Técnicas de Rate Limiting

### 1. Controle de Threads e Delay

```bash
# Threads controlados
-t 50          # 50 threads
-t 1           # 1 thread (lento mas discreto)

# Delay entre requests
-p 0.5         # 0.5 segundos entre requests
-p 1.2         # 1.2 segundos

# Delay randomizado
-p "0.1-0.5"   # Delay entre 0.1 e 0.5 segundos
```

### 2. Rate Limiting Avançado

```bash
# Limite de requests por segundo
-rate 10       # Máximo 10 requests/segundo

# Timeout por request
-timeout 10    # 10 segundos de timeout

# Tempo máximo de execução
-maxtime 600   # Para após 10 minutos

# Exemplo completo
ffuf -u http://target.com/FUZZ \
     -w wordlist.txt \
     -t 30 \
     -p "0.2-0.8" \
     -rate 20 \
     -timeout 15 \
     -maxtime 1200
```

### 3. Evasão de WAF/IDS

```bash
# Headers de evasão
-H "X-Forwarded-For: 127.0.0.1" \
-H "X-Real-IP: 127.0.0.1" \
-H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Rate limiting agressivo
-t 5 \
-p "1-3" \
-rate 2 \
-timeout 30
```

---
## Integração com Outras Ferramentas

### 1. Com Grep e Cut

```bash
# Extrair apenas URLs
ffuf -u http://target.com/FUZZ -w wordlist.txt -s | grep http | cut -d' ' -f2

# Filtrar por tamanho
ffuf -u http://target.com/FUZZ -w wordlist.txt -s | awk '$2 ~ /200|301/ {print $3}'
```

### 2. Com Nmap

```bash
# Encontrar subdomínios e scanear
ffuf -u http://FUZZ.target.com -w subdomains.txt -o subs.txt
cat subs.txt | awk '{print $2}' | xargs -I {} nmap -sV -p 80,443 {}
```

### 3. Com Waybackurls

```bash
# Usar URLs do Wayback Machine
waybackurls target.com | ffuf -u http://target.com/FUZZ -w - -t 100
```

### 4. Com Aquatone

```bash
# Descobrir e visualizar
ffuf -u http://FUZZ.target.com -w subdomains.txt -o subs.json -of json
cat subs.json | jq -r '.results[].url' | aquatone
```

### 5. Com Nuclei

```bash
# Encontrar endpoints e testar vulnerabilidades
ffuf -u http://target.com/FUZZ -w wordlist.txt -o endpoints.txt
cat endpoints.txt | nuclei -t /path/to/templates
```

---
## Exemplos Práticos Completos

### 1. Scan Completo de Diretórios

```bash
#!/bin/bash
# scan_completo.sh

TARGET=$1
WORDLIST_DIR="/usr/share/seclists/Discovery/Web-Content"
WORDLIST_SUB="/usr/share/seclists/Discovery/DNS"

echo "[+] Iniciando scan completo em: $TARGET"
echo "[+] Data: $(date)"

# 1. Enumeração de diretórios
echo "[+] Enumeração de diretórios..."
ffuf -u "http://$TARGET/FUZZ" \
     -w "$WORDLIST_DIR/raft-large-directories.txt" \
     -recursion \
     -recursion-depth 3 \
     -e .php,.html,.txt,.bak,.old \
     -mc 200,301,302,403 \
     -fc 404 \
     -t 100 \
     -p 0.1 \
     -o "dirs_$TARGET.json" \
     -of json \
     -c

# 2. Enumeração de subdomínios
echo "[+] Enumeração de subdomínios..."
ffuf -u "http://FUZZ.$TARGET" \
     -w "$WORDLIST_SUB/subdomains-top1million-5000.txt" \
     -H "Host: FUZZ.$TARGET" \
     -mc 200,301,302 \
     -fc 404 \
     -t 150 \
     -p 0.2 \
     -o "subs_$TARGET.json" \
     -of json \
     -c

# 3. Fuzzing de parâmetros
echo "[+] Fuzzing de parâmetros..."
ffuf -u "http://$TARGET/page.php?FUZZ=test" \
     -w "$WORDLIST_DIR/burp-parameter-names.txt" \
     -mc 200 \
     -fs 0 \
     -t 80 \
     -o "params_$TARGET.json" \
     -of json \
     -c

echo "[+] Scan completo finalizado!"
```

**Execução:**

```bash
# Tornar o script executável
chmod +x scan_completo.sh

# Executar scan
./scan_completo.sh 192.168.1.100
./scan_completo.sh exemplo.com
```

**Arquivos Gerados:**

```bash
ls -la *testphp.vulnweb.com*
# -rw-r--r-- 1 user user  15K Jan 20 10:31 dirs_testphp.vulnweb.com.json
# -rw-r--r-- 1 user user  8K  Jan 20 10:32 subs_testphp.vulnweb.com.json
# -rw-r--r-- 1 user user  4K  Jan 20 10:33 params_testphp.vulnweb.com.json
```

### 2. Brute Force de Login com Wordlists Múltiplas

```bash
#!/bin/bash
# brute_login.sh

TARGET=$1
USERLIST="users.txt"
PASSLIST="passwords.txt"

echo "[+] Iniciando brute force em: $TARGET/login"

ffuf -u "http://$TARGET/login.php" \
     -X POST \
     -d "username=FUZZ&password=FUZ2Z" \
     -w "$USERLIST:USER" \
     -w "$PASSLIST:PASS" \
     -mode pitchfork \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
     -H "Accept: text/html,application/xhtml+xml" \
     -H "Accept-Language: en-US,en;q=0.9" \
     -H "Connection: keep-alive" \
     -H "Referer: http://$TARGET/login.php" \
     -mc 302,200 \
     -fc 500 \
     -fs 0 \
     -t 50 \
     -p 0.3 \
     -rate 30 \
     -maxtime 1800 \
     -o "login_results_$(date +%s).json" \
     -of json \
     -c
```

**Preparação:**

```bash
# Criar arquivos de exemplo
echo -e "admin\nadministrator\nroot\nuser\ntest" > users.txt
echo -e "password\n123456\nadmin\nletmein\npassword123" > passwords.txt

# Tornar executável
chmod +x brute_login.sh

# Executar brute force
./brute_login.sh 192.168.1.100
# ou
./brute_login.sh vulnsite.com
```

### 3. Scan de VHosts em Massa

```bash
#!/bin/bash
# vhost_scan.sh

DOMAIN=$1
VHOST_LIST="vhosts.txt"

echo "[+] Scanning VHosts for: $DOMAIN"

ffuf -u "http://$DOMAIN" \
     -w "$VHOST_LIST" \
     -H "Host: FUZZ.$DOMAIN" \
     -mc 200,301,302,403 \
     -fc 404 \
     -t 100 \
     -p 0.2 \
     -rate 50 \
     -timeout 10 \
     -maxtime 3600 \
     -ac \
     -o "vhosts_$DOMAIN.json" \
     -of json \
     -c \
     -s
```

**Preparação:**

```bash
# Criar wordlist de VHosts
echo -e "www\napi\nadmin\ndev\nstaging\ntest\ninternal\nsecure" > vhosts.txt
echo -e "beta\nalpha\ngamma\ndelta\nproduction\nbackend\nfrontend" >> vhosts.txt

chmod +x vhost_scan.sh

# Executar
./vhost_scan.sh examplo.com
```

**Interpretação:**

- **[www.exemplo.com](https://www.exemplo.com)**: Site principal (mesmo conteúdo do domínio base)
- **[api.exemplo.com](https://api.exemplo.com)**: API com conteúdo diferente
- **[admin.exemplo.com](https://admin.exemplo.com)**: Acesso negado (403)
- **[staging.exemplo.com](https://staging.exemplo.com)**: Ambiente de staging
- **[secure.exemplo.com](https://secure.exemplo.com)**: Redirecionamento para HTTPS

### 4. Fuzzing de API REST

```bash
#!/bin/bash
# api_fuzzer.sh

API_BASE=$1
ENDPOINTS="api_endpoints.txt"
PARAMS="api_params.txt"

echo "[+] Fuzzing API: $API_BASE"

# Fuzzing de endpoints
ffuf -u "$API_BASE/FUZZ" \
     -w "$ENDPOINTS" \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer token_here" \
     -X GET \
     -mc 200,201 \
     -fc 404,500 \
     -t 80 \
     -o "api_endpoints.json" \
     -of json

# Fuzzing de parâmetros para cada endpoint
while read endpoint; do
    echo "[+] Testing endpoint: $endpoint"
    ffuf -u "$API_BASE/$endpoint?FUZZ=test" \
         -w "$PARAMS" \
         -H "Content-Type: application/json" \
         -mc 200 \
         -fc 400 \
         -t 50 \
         -o "params_${endpoint//\//_}.json" \
         -of json
done < discovered_endpoints.txt
```

**Preparação:**

```bash
# Criar wordlists
echo -e "users\nproducts\norders\ncart\nlogin\nlogout\nprofile" > api_endpoints.txt
echo -e "id\nlimit\noffset\nsort\nfilter\nsearch\napi_key" > api_params.txt

# Arquivo com endpoints descobertos
echo -e "users\nproducts" > discovered_endpoints.txt

chmod +x api_fuzzer.sh

# Execução
./api_fuzzer.sh http://api.example.com/v1
```

**Arquivos Gerados:**

```bash
ls -la *.json
# -rw-r--r-- 1 user user  4K  Jan 20 10:40 api_endpoints.json
# -rw-r--r-- 1 user user  2K  Jan 20 10:41 params_posts.json
# -rw-r--r-- 1 user user  2K  Jan 20 10:41 params_users.json
```

### 5. Monitoramento em Tempo Real com Output

```bash
# Scan com output em tempo real
ffuf -u http://target.com/FUZZ \
     -w wordlist.txt \
     -t 100 \
     -c \
     -s \
     -o /dev/stdout \
     -of json \
     | jq -r '.results[] | "\(.status) \(.length) \(.url)"' \
     | tee -a live_results.txt
```

**Preparação:**

```bash
# Criar wordlist de exemplo
echo -e "admin\nlogin\ndashboard\napi\nconfig" > wordlist.txt

# Executar comando direto
ffuf -u http://testphp.vulnweb.com/FUZZ \
     -w wordlist.txt \
     -t 100 \
     -c \
     -s \
     -o /dev/stdout \
     -of json \
     | jq -r '.results[] | "\(.status) \(.length) \(.url)"' \
     | tee -a live_results.txt
```

**Saída:**

```text
200 8192 http://testphp.vulnweb.com/
200 32768 http://testphp.vulnweb.com/admin
200 24576 http://testphp.vulnweb.com/login
404 234 http://testphp.vulnweb.com/dashboard
200 16384 http://testphp.vulnweb.com/api
403 299 http://testphp.vulnweb.com/config
```

**Conteúdo do arquivo `live_results.txt`:**

```text
200 8192 http://testphp.vulnweb.com/
200 32768 http://testphp.vulnweb.com/admin
200 24576 http://testphp.vulnweb.com/login
404 234 http://testphp.vulnweb.com/dashboard
200 16384 http://testphp.vulnweb.com/api
403 299 http://testphp.vulnweb.com/config
```

---
## Dicas e Boas Práticas

### 1. Wordlists Recomendadas

```bash
# Diretórios
/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
/usr/share/wordlists/dirb/common.txt

# Subdomínios
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
/usr/share/seclists/Discovery/DNS/namelist.txt

# Parâmetros
/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
/usr/share/seclists/Discovery/Web-Content/api-param-names.txt

# Senhas
/usr/share/seclists/Passwords/rockyou.txt
/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt
```

### 2. Performance Tuning

```bash
# Para redes rápidas
-t 200 \
-p 0.05 \
-timeout 5

# Para redes lentas/WAF
-t 20 \
-p "0.5-1.5" \
-rate 10 \
-timeout 30
```

### 3. Evitando Detection

```bash
# Random User-Agents
-H "User-Agent: $(shuf -n 1 user_agents.txt)"

# Delay randomizado
-p "$(shuf -i 100-3000 -n 1)ms"

# IP rotation via proxy
-proxy http://127.0.0.1:8080
```

### 4. Troubleshooting

```bash
# Debug mode
-v

# Mostrar todas as requests
-s

# Ignorar erros SSL
-k

# Verbose output
-v -debug-log debug.log
```

---
## Conclusão

O FFUF é uma ferramenta extremamente poderosa e versátil para testes de segurança web. Sua velocidade, flexibilidade e variedade de funcionalidades a tornam essencial no arsenal de qualquer pentester ou bug bounty hunter.

### **Principais Takeaways:**

1. **Comece simples** e adicione complexidade gradualmente    
2. **Use filtros adequadamente** para reduzir falsos positivos
3. **Ajuste rate limiting** conforme o ambiente alvo
4. **Documente seus comandos** para reprodução
5. **Sempre respeite** os termos de serviço e leis aplicáveis

### **Recursos Adicionais:**

- [Documentação Oficial](https://github.com/ffuf/ffuf)
- [Cheat Sheet](https://github.com/ffuf/ffuf#usage)
- [Wiki de Exemplos](https://github.com/ffuf/ffuf/wiki)
- [Payloads do SecLists](https://github.com/danielmiessler/SecLists)

**Nota:** Use esta ferramenta apenas em sistemas que você possui permissão explícita para testar. Testes não autorizados são ilegais e antiéticos.
