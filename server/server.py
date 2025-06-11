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

# Salt fixo para PBKDF2 (poderia ser negociado)
SALT = b'saltseguro123456'

USERNAME_SERVIDOR = 'seu_usuario_github'  # Altere para seu username real

# Função para baixar chave pública ECDSA do GitHub
def baixar_chave_publica_github(username):
    url = f'https://github.com/{username}.keys'
    resp = requests.get(url)
    if resp.status_code != 200:
        raise Exception(f'Não foi possível baixar chave pública de {username}')
    # Pega a primeira chave (assume ECDSA)
    for line in resp.text.splitlines():
        if line.startswith('ecdsa-sha2-nistp256'):
            return serialization.load_ssh_public_key(line.encode())
    raise Exception('Chave ECDSA não encontrada no GitHub')

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
            tam_sig = 72  # Tamanho máximo DER ECDSA
            tam_user = 32  # Limite username
            header = recv_all(conn, tam_A + tam_sig + tam_user)
            if not header:
                print('Conexão encerrada prematuramente.')
                return
            A_bytes = header[:tam_A]
            sig_A = header[tam_A:tam_A+tam_sig]
            username_cliente = header[tam_A+tam_sig:].rstrip(b'\x00').decode()
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
            # Gera chave privada ECDSA do servidor (exemplo: PEM local, ou gere temporária)
            # Aqui, para exemplo, gera temporária (não seguro para produção)
            privkey_servidor = ec.generate_private_key(ec.SECP256R1())
            sig_B = privkey_servidor.sign(B_bytes + USERNAME_SERVIDOR.encode(), ec.ECDSA(hashes.SHA256()))
            # Envia B, sig_B, username_servidor
            user_bytes = USERNAME_SERVIDOR.encode().ljust(tam_user, b'\x00')
            conn.sendall(B_bytes + sig_B + user_bytes)
            # Calcula segredo compartilhado
            S = pow(A, b, p)
            S_bytes = S.to_bytes((S.bit_length()+7)//8, 'big')

            # 2. Deriva chaves
            key_material = PBKDF2(S_bytes, SALT, dkLen=KEY_LEN*2, count=PBKDF2_ITER, hmac_hash_module=hashlib.sha256)
            key_aes = key_material[:KEY_LEN]
            key_hmac = key_material[KEY_LEN:]
            print('Chaves derivadas com sucesso.')
            
            # 3. Recebe mensagem segura
            # Estrutura: [HMAC_TAG (32)] + [IV (16)] + [CIPHERTEXT (resto)]
            header = recv_all(conn, HMAC_LEN + IV_LEN)
            if not header:
                print('Conexão encerrada prematuramente.')
                return
            hmac_tag = header[:HMAC_LEN]
            iv = header[HMAC_LEN:HMAC_LEN+IV_LEN]
            
            # Recebe o resto (mensagem cifrada)
            ciphertext = b''
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                ciphertext += chunk
            
            # Verifica HMAC
            hmac_calc = hmac.new(key_hmac, iv + ciphertext, hashlib.sha256).digest()
            if not hmac.compare_digest(hmac_tag, hmac_calc):
                print('HMAC inválido! Mensagem rejeitada.')
                return
            
            # Descriptografa
            cipher = AES.new(key_aes, AES.MODE_CBC, iv)
            try:
                plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
                print('Mensagem recebida (decriptada):', plaintext.decode())
            except Exception as e:
                print('Erro ao descriptografar:', e)

if __name__ == '__main__':
    main()