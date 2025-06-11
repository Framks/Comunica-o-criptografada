import socket
import secrets
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Protocol.KDF import PBKDF2
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

# Parâmetros públicos DH (devem ser idênticos ao do servidor)
p = int('''FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\n29024E088A67CC74020BBEA63B139B22514A08798E3404DD\nEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\nE485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF'''.replace('\n',''), 16)
g = 2

KEY_LEN = 32
HMAC_LEN = 32
IV_LEN = 16
PBKDF2_ITER = 100_000
SALT = b'saltseguro123456'

USERNAME_CLIENTE = 'Framks'  # Altere para seu username real
PRIVKEY_PATH = 'cliente_ecdsa.pem'  # Caminho para chave privada ECDSA do cliente

def baixar_chave_publica_github(username):
    url = f'https://github.com/{username}.keys'
    resp = requests.get(url)
    if resp.status_code != 200:
        raise Exception(f'Não foi possível baixar chave pública de {username}')
    for line in resp.text.splitlines():
        if line.startswith('ecdsa-sha2-nistp256'):
            return serialization.load_ssh_public_key(line.encode())
    raise Exception('Chave ECDSA não encontrada no GitHub')

def main():
    host = input('Digite o IP do servidor (default 127.0.0.1): ') or '127.0.0.1'
    port_str = input('Digite a porta do servidor (default 65432): ') or '65432'
    privKeyPath = input('Digite o caminho para a chave privada ECDSA do cliente (default cliente_ecdsa.pem): ') or PRIVKEY_PATH
    try:
        port = int(port_str)
    except ValueError:
        print('Porta inválida, usando 65432.')
        port = 65432
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        # 1. Handshake DH + ECDSA
        a = secrets.randbelow(p-2) + 2
        A = pow(g, a, p)
        A_bytes = A.to_bytes(512, 'big')
        # Carrega chave privada ECDSA do cliente
        with open(privKeyPath, 'rb') as f:
            privkey_cliente = serialization.load_pem_private_key(f.read(), password=None)
        sig_A = privkey_cliente.sign(A_bytes + USERNAME_CLIENTE.encode(), ec.ECDSA(hashes.SHA256()))
        user_bytes = USERNAME_CLIENTE.encode().ljust(32, b'\x00')
        s.sendall(A_bytes + sig_A + user_bytes)
        # Recebe B, sig_B, username_servidor
        tam_B = 512
        tam_sig = 72
        tam_user = 32
        header = s.recv(tam_B + tam_sig + tam_user)
        B_bytes = header[:tam_B]
        sig_B = header[tam_B:tam_B+tam_sig]
        username_servidor = header[tam_B+tam_sig:].rstrip(b'\x00').decode()
        B = int.from_bytes(B_bytes, 'big')
        # Baixa chave pública do servidor
        pubkey_servidor = baixar_chave_publica_github(username_servidor)
        # Verifica assinatura do servidor
        try:
            pubkey_servidor.verify(sig_B, B_bytes + username_servidor.encode(), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            print('Assinatura ECDSA do servidor inválida!')
            return
        print(f'Assinatura do servidor {username_servidor} verificada.')
        # Calcula segredo compartilhado
        S = pow(B, a, p)
        S_bytes = S.to_bytes((S.bit_length()+7)//8, 'big')
        # 2. Deriva chaves
        key_material = PBKDF2(S_bytes, SALT, dkLen=KEY_LEN*2, count=PBKDF2_ITER, hmac_hash_module=hashlib.sha256)
        key_aes = key_material[:KEY_LEN]
        key_hmac = key_material[KEY_LEN:]
        print('Chaves derivadas com sucesso.')
        # 3. Prepara mensagem
        mensagem = input('Digite a mensagem para enviar: ').encode()
        iv = secrets.token_bytes(IV_LEN)
        cipher = AES.new(key_aes, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(mensagem, AES.block_size))
        # 4. Calcula HMAC
        hmac_tag = hmac.new(key_hmac, iv + ciphertext, hashlib.sha256).digest()
        # 5. Envia pacote
        pacote = hmac_tag + iv + ciphertext
        s.sendall(pacote)
        print('Mensagem enviada com sucesso.')

if __name__ == '__main__':
    main()