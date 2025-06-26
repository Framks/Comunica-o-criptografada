import socket
import secrets
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
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
KEY_LEN = 32
HMAC_LEN = 32
IV_LEN = 16
PBKDF2_ITER = 100_000
SALT = b'saltseguro123456'
USERNAME_CLIENTE = 'Framks'
PRIVKEY_PATH = 'cliente_ecdsa.pem'

def baixar_chave_publica(username):
    url = f"https://github.com/{username}.keys"
    r = requests.get(url)
    if r.status_code == 200:
        key_str = r.text.strip().splitlines()[1]
        print(f'Chave pública ECDSA do servidor {username} baixada com sucesso.')
        print(f'Chave: {key_str}')
        return serialization.load_ssh_public_key(key_str.encode(), backend=default_backend())
    else:
        raise Exception("Erro ao baixar chave pública")
    
def verifica_assinatura(pubkey, sig_B, B_bytes, username_servidor):
    try:
        pubkey.verify(sig_B, B_bytes + username_servidor.encode(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        print('Assinatura ECDSA do servidor inválida!')
        return
    
def derivacao_chaves(S_bytes):
    key_material = PBKDF2(S_bytes, SALT, dkLen=KEY_LEN*2, count=PBKDF2_ITER, hmac_hash_module=SHA256)
    key_aes = key_material[:KEY_LEN]
    key_hmac = key_material[KEY_LEN:]
    print('Chaves derivadas com sucesso.')
    return key_aes, key_hmac

def recv_all(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def receber_mensagens(sock, key_aes, key_hmac):
    try:
        while True:
            header = recv_all(sock, HMAC_LEN + IV_LEN + 4)
            if not header:
                sys.stdout.write('\r\033[K[Conexão encerrada pelo servidor.]\n')
                sys.stdout.flush()
                break
            hmac_tag = header[:HMAC_LEN]
            iv = header[HMAC_LEN:HMAC_LEN+IV_LEN]
            tam_cipher = int.from_bytes(header[HMAC_LEN+IV_LEN:HMAC_LEN+IV_LEN+4], 'big')
            ciphertext = recv_all(sock, tam_cipher)
            if ciphertext is None:
                sys.stdout.write('\r\033[K[Conexão encerrada ao receber ciphertext.]\n')
                sys.stdout.flush()
                break
            hmac_calc = hmac.new(key_hmac, iv + ciphertext, hashlib.sha256).digest()
            if not hmac.compare_digest(hmac_tag, hmac_calc):
                sys.stdout.write('\r\033[K[HMAC inválido, ignorando mensagem]\n')
                sys.stdout.flush()
                continue
            cipher = AES.new(key_aes, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            sys.stdout.write('\r\033[K[Servidor]: ' + plaintext.decode() + '\n')
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
 ██████╗██╗  ██╗ █████╗ ████████╗███████╗██████╗ ██╗███╗   ██╗ █████╗ ██████╗ ███████╗
██╔════╝██║  ██║██╔══██╗╚══██╔══╝██╔════╝██╔══██╗██║████╗  ██║██╔══██╗██╔══██╗██╔════╝
██║     ███████║███████║   ██║   █████╗  ██████╔╝██║██╔██╗ ██║███████║██████╔╝█████╗  
██║     ██╔══██║██╔══██║   ██║   ██╔══╝  ██╔══██╗██║██║╚██╗██║██╔══██║██║  ██║██╔══╝  
╚██████╗██║  ██║██║  ██║   ██║   ███████╗██████╔╝██║██║ ╚████║██║  ██║██║  ██║███████╗
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝                                                                                     
    """)
    print("bem vindo ao chat seguro!")
    print("Para começar vc tem que ter uma chave privada ECDSA gerada com o comando:")
    print("openssl ecparam -name prime256v1 -genkey -noout -out cliente_ecdsa.pem")
    print("E a chave pública do servidor deve estar no GitHub do usuário que você deseja se conectar.")
    print("Certifique-se de que o servidor está rodando e que você tem a chave pública do servidor no GitHub.")
    print("Pressione Enter para continuar...")
    input()

def main():
    print_banner()
    host = input('Digite o IP do servidor (default 127.0.0.1): ') or '127.0.0.1'
    port = input('Digite a porta do servidor (default 65432): ') or 65434
    privKeyPath = input('Digite o caminho para a chave privada ECDSA do cliente (default cliente_ecdsa.pem): ') or PRIVKEY_PATH
    username = input('Digite seu username do GitHub (default Framks): ') or USERNAME_CLIENTE
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        
        a = secrets.randbelow(p-2) + 2
        A = pow(g, a, p)
        A_bytes = A.to_bytes(512, 'big')

        print(f'Chave pública A: (bytes: {A_bytes.hex()})\n')
        print('=====================================================\n')
        
        with open(privKeyPath, 'rb') as f:
            privkey = serialization.load_pem_private_key(f.read(), password=None)
        sig_A = privkey.sign(A_bytes + username.encode(), ec.ECDSA(hashes.SHA256()))
        print(f'Assinatura A: {sig_A.hex()} (tamanho: {len(sig_A)} bytes)\n')

        sig_A_len = len(sig_A)
        user_bytes = username.encode().ljust(32, b'\x00')

        print(f'Enviando (A_bytes + sig_A + username) para o servidor...\n')
        s.sendall(A_bytes + sig_A_len.to_bytes(1, 'big') + sig_A + user_bytes)


        tam_B = 512
        tam_sig_len = 1
        tam_user = 32
        print('Recebendo B_bytes, sig_B e username do servidor...\n')
        header = recv_all(s, tam_B + tam_sig_len)
        if not header:
            print('Conexão encerrada prematuramente ao receber header do servidor.\n')
            return
        B_bytes = header[:tam_B]
        sig_B_len = header[tam_B]
        sig_B = recv_all(s, sig_B_len)
        user_bytes = recv_all(s, tam_user)
        username_servidor = user_bytes.rstrip(b'\x00').decode()
        B = int.from_bytes(B_bytes, 'big')
        print(f'Servidor {username_servidor} enviou B: (bytes: {B_bytes.hex()})\n')
        print(f'Signature length: {sig_B_len}, Signature: {sig_B.hex()}\n')
        print('=====================================================\n')
        print(f'Verificando assinatura do servidor {username_servidor}...\n')

        pubkey_servidor = baixar_chave_publica(username_servidor)     
        verifica_assinatura(pubkey_servidor, sig_B, B_bytes, username_servidor)
        print(f'Assinatura do servidor {username_servidor} verificada.\n') 
        print('=====================================================\n')
        print('Calculando segredo compartilhado S...\n')

        B = int.from_bytes(B_bytes, 'big')
        S = pow(B, a, p)
        S_bytes = S.to_bytes((S.bit_length()+7)//8, 'big')

        key_aes, key_hmac = derivacao_chaves(S_bytes)

        print(f'Secreto compartilhado S: (bytes: {S_bytes.hex()})\n')
        print(f'Chave AES: {key_aes.hex()}\n')
        print(f'Chave HMAC: {key_hmac.hex()}\n')
        print('Chaves derivadas com sucesso.')
        print('Conexão estabelecida com sucesso!')
        print('=====================================================\n')

        print('Digite "/sair" para encerrar o chat.')
        # Inicia thread de recebimento
        t = threading.Thread(target=receber_mensagens, args=(s, key_aes, key_hmac), daemon=True)
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
            s.sendall(pacote)
            print('Mensagem enviada.')
        s.close()
if __name__ == '__main__':
    main()