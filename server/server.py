import socket
import secrets
import hashlib
import hmac
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
import threading
import sys
try:
    import readline
except ImportError:
    readline = None

p = int('''FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\n29024E088A67CC74020BBEA63B139B22514A08798E3404DD\nEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\nE485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF'''.replace('\n',''), 16)
g = 2

HOST = '127.0.0.1'
PORT = 65434
PRIVKEY_PATH = 'server_ecdsa.pem'
KEY_LEN = 32
HMAC_LEN = 32
IV_LEN = 16
PBKDF2_ITER = 100_000
SALT = b'saltseguro123456'
USERNAME_SERVIDOR = 'Framks'


def baixar_chave_publica(username):
    url = f"https://github.com/{username}.keys"
    r = requests.get(url)
    if r.status_code == 200:
        key_str = r.text.strip().splitlines()[0]
        print(f'Chave pública ECDSA do cliente {username} baixada com sucesso.')
        print(f'Chave: {key_str}')
        return serialization.load_ssh_public_key(key_str.encode(), backend=default_backend())
    else:
        raise Exception("Erro ao baixar chave pública")

def derivacao_chaves(S_bytes):
    key_material = PBKDF2(S_bytes, SALT, dkLen=KEY_LEN*2, count=PBKDF2_ITER, hmac_hash_module=SHA256)
    key_aes = key_material[:KEY_LEN]
    key_hmac = key_material[KEY_LEN:]
    print('Chaves derivadas com sucesso.')
    return key_aes, key_hmac

def verifica_assinatura(pubkey, sig_A, A_bytes, username_cliente):
    try:
        pubkey.verify(sig_A, A_bytes + username_cliente.encode(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        print('Assinatura ECDSA do invalida inválida!')
        return

def recv_all(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def receber_mensagens(conn, key_aes, key_hmac):
    try:
        while True:
            header = recv_all(conn, HMAC_LEN + IV_LEN + 4)
            if not header:
                sys.stdout.write('\r\033[K[Conexão encerrada pelo cliente.]\n')
                sys.stdout.flush()
                break
            # Extrai HMAC, IV e tamanho do ciphertext do header
            hmac_tag = header[:HMAC_LEN]
            iv = header[HMAC_LEN:HMAC_LEN+IV_LEN]
            tam_cipher = int.from_bytes(header[HMAC_LEN+IV_LEN:HMAC_LEN+IV_LEN+4], 'big')
            ciphertext = recv_all(conn, tam_cipher)
            if ciphertext is None:
                sys.stdout.write('\r\033[K[Conexão encerrada ao receber ciphertext.]\n')
                sys.stdout.flush()
                break
            hmac_calc = hmac.new(key_hmac, iv + ciphertext, hashlib.sha256).digest()
            if not hmac.compare_digest(hmac_tag, hmac_calc):
                sys.stdout.write('\r\033[K[HMAC inválido. Mensagem descartada.]\n')
                sys.stdout.flush()
                continue
            cipher = AES.new(key_aes, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            # Limpa a linha, imprime a mensagem recebida e reimprime o prompt e buffer  
            sys.stdout.write('\r\033[K[Cliente]: ' + plaintext.decode() + '\n')
            if readline:
                line = readline.get_line_buffer()
                sys.stdout.write('Mensagem: ' + line)
            else:
                sys.stdout.write('Mensagem: ')
            sys.stdout.flush()
    except Exception as e:
        sys.stdout.write('\r\033[K[Erro na thread de recebimento: %s]\n' % e)
        sys.stdout.flush()

def print_banner():
    print(r"""
    ██████╗ ██╗      █████╗  ██████╗██╗  ██╗██████╗  ██████╗ ██╗  ██╗
    ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██╔══██╗██╔═══██╗╚██╗██╔╝
    ██████╔╝██║     ███████║██║     █████╔╝ ██████╔╝██║   ██║ ╚███╔╝   
    ██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██╔══██╗██║   ██║ ██╔██╗   
    ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗██████╔╝╚██████╔╝██╔╝ ██╗
    ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝ 

                 ██████╗██╗  ██╗ █████╗ ████████╗
                ██╔════╝██║  ██║██╔══██╗╚══██╔══╝
                ██║     ███████║███████║   ██║   
                ██║     ██╔══██║██╔══██║   ██║   
                ╚██████╗██║  ██║██║  ██║   ██║   
                 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   
""")

def main():
    print_banner() 
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        username = input('Digite seu username do GitHub (default Framks e não maior que 32 caracteres): ') or USERNAME_SERVIDOR
        privKeyPath = input('Digite o caminho para a chave privada ECDSA do servidor (default server_ecdsa.pem): ') or PRIVKEY_PATH
        
        s.bind((HOST, PORT))
        s.listen(1)
        print(f'Servidor ouvindo em {HOST}:{PORT}... (BlackBox Chat)\n')

        conn, addr = s.accept()
        with conn:
            print('Conectado por ', addr, '\n')
            
            tam_A = 512
            tam_sig_len = 1
            tam_user = 32
            header = recv_all(conn, tam_A + tam_sig_len)
            if not header:
                print('Conexão encerrada prematuramente ao receber header do cliente.')
                return
            A_bytes = header[:tam_A]
            sig_A_len = header[tam_A]
            sig_A = recv_all(conn, sig_A_len)
            user_bytes = recv_all(conn, tam_user)
            username_cliente = user_bytes.rstrip(b'\x00').decode()
            A = int.from_bytes(A_bytes, 'big')

            print(f'Cliente {username_cliente} enviou A: (bytes: {A_bytes.hex()})\n')
            
            print('=====================================================\n')
            print('Baixando chave pública do cliente...\n')
            pubkey_cliente = baixar_chave_publica(username_cliente)
            
            verifica_assinatura(pubkey_cliente, sig_A, A_bytes, username_cliente)
            print(f'Assinatura do cliente {username_cliente} verificada.\n')
            
            print('=====================================================\n')
            print('Calculando chave pública B...\n')
            b = secrets.randbelow(p-2) + 2
            B = pow(g, b, p)
            B_bytes = B.to_bytes(512, 'big')

            print(f'B (bytes): {B_bytes.hex()}')
            print('=====================================================\n')
            print(f'Enviando B, assinatura e username para o cliente {username_cliente}...\n')
            with open(privKeyPath, 'rb') as f:
                privkey = serialization.load_pem_private_key(f.read(), password=None)
            sig_B = privkey.sign(B_bytes + username.encode(), ec.ECDSA(hashes.SHA256()))
            user_bytes = username.encode().ljust(tam_user, b'\x00')
            sig_B_len = len(sig_B)
            
            print(f'tamanho de B_bytes: {len(B_bytes)}\n')
            print(f'tamanho de sig_B: {len(sig_B)}\n')
            print(f'tamanho de user_bytes: {len(user_bytes)}\n')
            print('=====================================================\n')
            
            conn.sendall(B_bytes + sig_B_len.to_bytes(1, 'big') + sig_B + user_bytes)

            print('Pacote enviado:', (B_bytes + sig_B + user_bytes).hex() , '\n')
            print('=====================================================\n')
            # Calcula segredo compartilhado
            S = pow(A, b, p)
            S_bytes = S.to_bytes((S.bit_length()+7)//8, 'big')
            print(f'Segredo compartilhado S (bytes): {S_bytes.hex()}\n')
            # 2. Deriva chaves
            key_aes, key_hmac= derivacao_chaves(S_bytes)
            print(f'Chave AES: {key_aes.hex()}\n')
            print(f'Chave HMAC: {key_hmac.hex()}\n')
            print('Chaves derivadas com sucesso.\n')
            print('Conexão estabelecida com sucesso!\n')
            print('=====================================================\n')
            
            print('Chat seguro iniciado. Digite "/sair" para encerrar.\n')
            t = threading.Thread(target=receber_mensagens, args=(conn, key_aes, key_hmac), daemon=True)
            t.start()
            while True:
                mensagem = input('Mensagem: ')
                if mensagem.strip().lower() == '/sair':
                    print('Encerrando chat.')
                    break

                msg_bytes = mensagem.encode()
                iv = secrets.token_bytes(IV_LEN)
                cipher = AES.new(key_aes, AES.MODE_CBC, iv)
                ciphertext = cipher.encrypt(pad(msg_bytes, AES.block_size))
                hmac_tag = hmac.new(key_hmac, iv + ciphertext, hashlib.sha256).digest()
                tam_cipher = len(ciphertext).to_bytes(4, 'big')
                pacote = hmac_tag + iv + tam_cipher + ciphertext
                conn.sendall(pacote)
                print('Mensagem enviada.\n')
            conn.close()

if __name__ == '__main__':
    main()