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
from Crypto.Hash import SHA256

# Parâmetros públicos DH (exemplo seguro para fins didáticos)
p = int('''FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\n29024E088A67CC74020BBEA63B139B22514A08798E3404DD\nEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\nE485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF'''.replace('\n',''), 16)
g = 2

HOST = '127.0.0.1'
PORT = 65432

# Tamanho das chaves
KEY_LEN = 32  # 256 bits para AES-256 e HMAC-SHA256
HMAC_LEN = 32
IV_LEN = 16
PBKDF2_ITER = 100_000
PRIVKEY_PATH = 'server_ecdsa.pem'

# Salt fixo para PBKDF2 (poderia ser negociado)
SALT = b'saltseguro123456'

USERNAME_SERVIDOR = 'Framks'  # Altere para seu username real

# Função para baixar chave pública ECDSA do GitHub
def baixar_chave_publica_github(username):
    url = f"https://github.com/{username}.keys"
    r = requests.get(url)
    if r.status_code == 200:
        key_str = r.text.strip().splitlines()[0]
        print(f'Chave pública ECDSA do servidor {username} baixada com sucesso.')
        print(f'Chave: {key_str}')
        return serialization.load_ssh_public_key(key_str.encode(), backend=default_backend())
    else:
        raise Exception("Erro ao baixar chave pública")

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
        s.bind((HOST, PORT))
        s.listen(1)
        print(f'Servidor ouvindo em {HOST}:{PORT}...')
        conn, addr = s.accept()
        with conn:
            print('Conectado por', addr)
            # 1. Recebe A, sig_A, username_cliente
            tam_A = 512
            tam_sig_len = 1  # 1 byte para o tamanho da assinatura
            tam_user = 32
            header = recv_all(conn, tam_A + tam_sig_len)
            if not header:
                print('Conexão encerrada prematuramente.')
                return
            A_bytes = header[:tam_A]
            sig_len = header[tam_A]
            sig_A = recv_all(conn, sig_len)
            user_bytes = recv_all(conn, tam_user)
            username_cliente = user_bytes.rstrip(b'\x00').decode()
            A = int.from_bytes(A_bytes, 'big')
            # Baixa chave pública do cliente
            pubkey_cliente = baixar_chave_publica_github(username_cliente)
            # Verifica assinatura
            try:
                pubkey_cliente.verify(sig_A, A_bytes + username_cliente.encode(), ec.ECDSA(hashes.SHA256()))
            except InvalidSignature:
                print('Assinatura ECDSA do cliente inválida!')
                return
            print(f'Assinatura do cliente {username_cliente} verificada.')
            # 2. Gera par DH e assina B+username_servidor
            b = secrets.randbelow(p-2) + 2
            B = pow(g, b, p)
            B_bytes = B.to_bytes(512, 'big')
            with open(PRIVKEY_PATH, 'rb') as f:
                privkey = serialization.load_pem_private_key(f.read(), password=None) # Carrega a chave privada ECDSA do servidor
            sig_B = privkey.sign(B_bytes + USERNAME_SERVIDOR.encode(), ec.ECDSA(hashes.SHA256()))
            sig_B_len = len(sig_B)
            user_bytes = USERNAME_SERVIDOR.encode().ljust(tam_user, b'\x00')
            # Envia B, tamanho da assinatura, assinatura, username_servidor
            conn.sendall(B_bytes + sig_B_len.to_bytes(1, 'big') + sig_B + user_bytes)
            S = pow(A, b, p)
            S_bytes = S.to_bytes((S.bit_length()+7)//8, 'big')
            key_material = PBKDF2(S_bytes, SALT, dkLen=KEY_LEN*2, count=PBKDF2_ITER, hmac_hash_module=SHA256)
            key_aes = key_material[:KEY_LEN]
            key_hmac = key_material[KEY_LEN:]
            print('Chaves derivadas com sucesso.')
            
            
            header = recv_all(conn, HMAC_LEN + IV_LEN)
            if not header:
                print('Conexão encerrada prematuramente.')
                return
            hmac_tag = header[:HMAC_LEN]
            iv = header[HMAC_LEN:HMAC_LEN+IV_LEN]
            
            
            ciphertext = b''
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                ciphertext += chunk
            
            
            hmac_calc = hmac.new(key_hmac, iv + ciphertext, hashlib.sha256).digest()
            if not hmac.compare_digest(hmac_tag, hmac_calc):
                print('HMAC inválido! Mensagem rejeitada.')
                return
            
            
            cipher = AES.new(key_aes, AES.MODE_CBC, iv)
            try:
                plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
                print('Mensagem recebida (decriptada):', plaintext.decode())
            except Exception as e:
                print('Erro ao descriptografar:', e)

if __name__ == '__main__':
    main()