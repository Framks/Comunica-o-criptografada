# BlackBox Chat - Comunicação Criptografada Cliente/Servidor

Este projeto implementa um chat seguro entre cliente e servidor em Python, com autenticação mútua baseada em ECDSA (chaves do GitHub), troca de chaves Diffie-Hellman, derivação de chaves com PBKDF2, criptografia AES-CBC e autenticação de mensagens com HMAC-SHA256. O chat é bidirecional e permite que ambos os lados enviem e recebam mensagens simultaneamente, como em um chat real.

# 📌 Observação Importante

Este projeto foi desenvolvido **exclusivamente para fins didáticos e acadêmicos**.

👉 **Finalidade:**  
O código, a estrutura e as implementações aqui presentes têm o único propósito de **apoiar o estudo e o aprendizado de conceitos relacionados a segurança da informação, criptografia, redes de computadores, etc**.

👉 **Não recomendado para produção:**  
Este repositório **não foi testado, validado ou auditado para uso em ambientes de produção**. O uso fora do contexto educacional é de responsabilidade exclusiva do usuário.

👉 **Sem garantias:**  
Não há garantias de **segurança**, **desempenho** ou **conformidade com padrões de mercado**.

## Conceitos necessários para entender o projeto

### Sistemas Operacionais
- **Sockets:** Interface de comunicação entre processos, usada para troca de dados entre cliente e servidor via rede.
- **Threads:** Execução concorrente para permitir envio e recebimento de mensagens simultaneamente.
- **Entrada/Saída (I/O):** Manipulação de entrada do usuário e saída no terminal, incluindo manipulação de linhas para melhor experiência de chat.

### Redes
- **Modelo Cliente-Servidor:** Arquitetura onde um lado (servidor) aguarda conexões e o outro (cliente) inicia a comunicação.
- **TCP/IP:** Protocolo de transporte confiável usado para garantir entrega e ordem das mensagens.
- **Endereçamento (IP/Porta):** Identificação dos participantes na rede.
- **Protocolo de aplicação:** Definição de como as mensagens são formatadas, enviadas e recebidas.

### Criptografia
- **ECDSA (Elliptic Curve Digital Signature Algorithm):** Algoritmo de assinatura digital usado para autenticação mútua, com chaves públicas publicadas no GitHub.
- **Diffie-Hellman:** Protocolo de troca de chaves para gerar um segredo compartilhado entre cliente e servidor, mesmo em canal inseguro.
- **PBKDF2 (Password-Based Key Derivation Function 2):** Derivação de chaves seguras a partir do segredo compartilhado, usando salt e múltiplas iterações.
- **AES-CBC (Advanced Encryption Standard - Cipher Block Chaining):** Algoritmo de criptografia simétrica para proteger o conteúdo das mensagens.
- **HMAC-SHA256:** Código de autenticação de mensagem para garantir integridade e autenticidade das mensagens trocadas.
- **IV (Initialization Vector):** Valor aleatório usado em cada mensagem para garantir segurança na criptografia em modo CBC.

Esses conceitos são fundamentais para compreender como o chat garante confidencialidade, integridade, autenticidade e comunicação segura entre cliente e servidor.

---

## Funcionalidades
- Autenticação mútua usando ECDSA (chaves públicas do GitHub)
- Troca de chaves Diffie-Hellman
- Derivação de chaves com PBKDF2 (SHA256)
- Criptografia de mensagens com AES-CBC
- Integridade e autenticidade com HMAC-SHA256
- Protocolo robusto para mensagens de tamanho arbitrário
- Chat bidirecional em tempo real (ambos podem digitar e receber ao mesmo tempo)

## Pré-requisitos
- Python 3.8+
- Instale as dependências:

```bash
pip install -r requirements.txt
```

## Geração das chaves ECDSA
Cada lado precisa de uma chave privada ECDSA (prime256v1) e a chave pública correspondente deve estar publicada no GitHub do usuário. 
( Devera fazer esse processo para o cliente e o servidor )

### Gerar chave privada (exemplo para cliente):
```bash
openssl ecparam -name prime256v1 -genkey -noout -out cliente_ecdsa.pem
```

### Extrair chave pública (para publicar no GitHub):
```bash
ssh-keygen -y -f cliente_ecdsa.pem > cliente_ecdsa.pub
```

Faça o mesmo para o servidor, usando nomes apropriados.

## Como rodar o servidor
1. Edite o arquivo `server/server.py` para garantir que o caminho da chave privada e o username do GitHub estejam corretos.
2. Execute:
```bash
python3 server/server.py
```
3. Informe seu username do GitHub e o caminho da chave privada quando solicitado.

## Como rodar o cliente
1. Edite o arquivo `client/client.py` para garantir que o caminho da chave privada e o username do GitHub estejam corretos.
2. Execute:
```bash
python3 client/client.py
```
3. Informe o IP, porta, username do GitHub e caminho da chave privada quando solicitado.

## Como usar o chat
- Digite mensagens normalmente e pressione Enter para enviar.
- Digite `/sair` para encerrar o chat.
- Mensagens recebidas aparecem imediatamente, sem atrapalhar sua digitação.


Dúvidas ou sugestões? Abra uma issue ou envie um pull request!

