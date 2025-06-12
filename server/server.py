import socket
import secrets
import hashlib
import hmac
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Protocol.KDF import PBKDF2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

# Parâmetros públicos DH (exemplo seguro para fins didáticos)
p = int('''FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\n29024E088A67CC74020BBEA63B139B22514A08798E3404DD\nEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\nE485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF'''.replace('\n',''), 16)
g = 2

HOST = '127.0.0.1'
PORT = 65432
PRIVKEY_PATH = 'server_ecdsa.pem'  # Caminho padrão para a chave privada ECDSA do servidor

# Tamanho das chaves
KEY_LEN = 32  # 256 bits para AES-256 e HMAC-SHA256
HMAC_LEN = 32
IV_LEN = 16
PBKDF2_ITER = 100_000

# esse salto vai ser o mesmo do cliente
SALT = b'saltseguro123456'

USERNAME_SERVIDOR = 'Framks'
# Função para baixar chave pública ECDSA do GitHub
def baixar_chave_publica(username):
    url = f"https://github.com/{username}.keys"
    r = requests.get(url)
    if r.status_code == 200:
        key_str = r.text.strip().splitlines()[0]
        return serialization.load_ssh_public_key(key_str.encode(), backend=default_backend())
    else:
        raise Exception("Erro ao baixar chave pública")

def derivacao_chaves(S_bytes):
    key_material = PBKDF2(S_bytes, SALT, dkLen=KEY_LEN*2, count=PBKDF2_ITER, hmac_hash_module=hashlib.sha256)
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

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        username = input('Digite seu username do GitHub (default Framks e não maior que 32 caracteres): ') or USERNAME_SERVIDOR
        privKeyPath = input('Digite o caminho para a chave privada ECDSA do servidor (default server_ecdsa.pem): ') or PRIVKEY_PATH
        
        s.bind((HOST, PORT))
        s.listen(1)
        print(f'Servidor ouvindo em {HOST}:{PORT}...')

        conn, addr = s.accept()
        with conn:
            print('Conectado por', addr)
            
            tam_A = 512
            tam_sig = 72  # Tamanho máximo da assinatura ECDSA 
            tam_user = 32  # Limite username

            header = recv_all(conn, tam_A + tam_sig + tam_user) # 1. Recebe A, sig_A, username_cliente 
            
            if not header:
                print('Conexão encerrada prematuramente.')
                return
            
            A_bytes = header[:tam_A]
            sig_A = header[tam_A:tam_A+tam_sig]
            username_cliente = header[tam_A+tam_sig:].rstrip(b'\x00').decode()

            A = int.from_bytes(A_bytes, 'big')

            pubkey_cliente = baixar_chave_publica(username_cliente) # Baixa chave pública do cliente
            
            verifica_assinatura(pubkey_cliente, sig_A, A_bytes, username_cliente) # Verifica assinatura
            print(f'Assinatura do cliente {username_cliente} verificada.')

            b = secrets.randbelow(p-2) + 2
            B = pow(g, b, p)
            B_bytes = B.to_bytes(512, 'big')

            with open(privKeyPath, 'rb') as f:
                privkey = serialization.load_pem_private_key(f.read(), password=None) # Carrega a chave privada ECDSA do servidor
            sig_B = privkey.sign(B_bytes + username.encode(), ec.ECDSA(hashes.SHA256())) # Assina B + username com a chave privada ECDSA
            user_bytes = username.encode().ljust(tam_user, b'\x00')

            conn.sendall(B_bytes + sig_B + user_bytes) # Envia B, sig_B, username_servidor
            # Calcula segredo compartilhado
            S = pow(A, b, p)
            S_bytes = S.to_bytes((S.bit_length()+7)//8, 'big')

            # 2. Deriva chaves
            key_aes, key_hmac= derivacao_chaves(S_bytes)
            
            # 3. Loop de recebimento de mensagens seguras
            print('Aguardando mensagens do cliente. Pressione Ctrl+C para encerrar.')
            while True:
                header = recv_all(conn, HMAC_LEN + IV_LEN)
                if not header:
                    print('Conexão encerrada pelo cliente.')
                    break
                hmac_tag = header[:HMAC_LEN]
                iv = header[HMAC_LEN:HMAC_LEN+IV_LEN]
                # Recebe o resto (mensagem cifrada)
                ciphertext = b''
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    ciphertext += chunk
                    # Para chat, cada mensagem é um pacote, então pode sair do loop após o primeiro chunk
                    break
                # Verifica HMAC
                hmac_calc = hmac.new(key_hmac, iv + ciphertext, hashlib.sha256).digest()
                if not hmac.compare_digest(hmac_tag, hmac_calc):
                    print('HMAC inválido! Mensagem rejeitada.')
                    continue
                # Descriptografa
                cipher = AES.new(key_aes, AES.MODE_CBC, iv)
                try:
                    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
                    print('Mensagem recebida (decriptada):', plaintext.decode())
                except Exception as e:
                    print('Erro ao descriptografar:', e)

if __name__ == '__main__':
    main()