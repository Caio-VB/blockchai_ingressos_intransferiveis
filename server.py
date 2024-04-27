from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import socket
import json
import hashlib
import datetime

# Definindo a estrutura de um bloco da blockchain
class Bloco:
    def __init__(self, index, timestamp, dados, hash_anterior):
        self.index = index
        self.timestamp = timestamp
        self.dados = dados
        self.hash_anterior = hash_anterior

    def calcular_hash(self):
        dados_codificados = str(self.index) + str(self.timestamp) + str(self.dados) + self.hash_anterior
        return hashlib.sha256(dados_codificados.encode()).hexdigest()

# Função para exibir a blockchain
def exibir_blockchain(blockchain):
    for bloco in blockchain:
        print(f"Índice: {bloco.index}")
        print(f"Timestamp: {bloco.timestamp}")
        print(f"Dados: {bloco.dados}")
        print(f"Hash Anterior: {bloco.hash_anterior}")
        print()

# Função para adicionar um bloco à blockchain
def adicionar_bloco(blockchain, dados):
    cpf_existente = False
    ingresso_existente = False

    # Verifica se o CPF ou o código de ingresso já existem na blockchain
    for bloco in blockchain:
        if 'cpf' in bloco.dados and bloco.dados['cpf'] == dados['cpf']:
            cpf_existente = True
            if 'ingresso' in bloco.dados and bloco.dados['ingresso'] == dados['ingresso']:
                ingresso_existente = True
                break
        elif 'ingresso' in bloco.dados and bloco.dados['ingresso'] == dados['ingresso']:
            ingresso_existente = True
            break

    # Verifica se os dados foram adicionados à blockchain com sucesso
    if cpf_existente and ingresso_existente:
        mensagem = "Esse já é um ingresso válido."
    elif cpf_existente:
        mensagem = "Erro: Já existe um cadastro com este CPF na blockchain."
    elif ingresso_existente:
        mensagem = "Erro: Já existe um cadastro com este código de ingresso na blockchain."
    else:
        mensagem = "Dados adicionados à blockchain com sucesso."
        index = len(blockchain)
        timestamp = datetime.datetime.now()
        if index == 0:
            hash_anterior = "0"  # Bloco de gênese
        else:
            hash_anterior = blockchain[-1].calcular_hash()
        novo_bloco = Bloco(index, timestamp, dados, hash_anterior)
        blockchain.append(novo_bloco)
        print("Dados adicionado à blockchain com sucesso.")

    # Criptografa a mensagem usando a chave pública do cliente
    encrypted_message = client_public_key.encrypt(
        mensagem.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Envia a mensagem cifrada para o cliente
    conn.sendall(encrypted_message)

# Gerar chaves pública e privada
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Converter chaves para o formato PEM
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Configurações do servidor
HOST = 'localhost'  # Endereço IP local
PORT = 1234        # Porta para ouvir conexões
HASH_SENHA = '1a19e1bb4515db467c7683d7c53000393dfda285efdb04cd6f97f749d1d89f6f'      # Senha para usar o sistema (Ingresso1234)

# Inicializando a blockchain com um bloco de gênese
blockchain = [Bloco(0, datetime.datetime.now(), "Gênese", "0")]

# Cria um socket TCP/IP
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    # Vincula o socket à porta
    server_socket.bind((HOST, PORT))
    # Fica ouvindo por conexões
    server_socket.listen()

    print(f"Servidor aguardando conexões em {HOST}:{PORT}")

    while True:
        # Aceita a conexão quando um cliente se conecta
        conn, addr = server_socket.accept()
        with conn:
            print(f"Conexão aceita de {addr}")

            # Envia a chave pública para o cliente
            conn.sendall(public_key_pem)

            # Recebe a chave pública do cliente
            client_public_key_pem = conn.recv(4096)
            client_public_key = serialization.load_pem_public_key(
                client_public_key_pem,
                backend=default_backend()
            )

            # Recebe os dados criptografados do cliente
            encrypted_data = conn.recv(4096)

            # Decifra os dados usando a chave pública do cliente
            decrypted_data = private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Converte os dados de volta para JSON
            dados_json = decrypted_data.decode()

            # Converte o JSON de volta para um dicionário
            dados_cliente = json.loads(dados_json)

            # Verifica se o hash da senha fornecido pelo cliente corresponde ao esperado
            if dados_cliente.get('hash_senha') != HASH_SENHA:
                print("Erro: O hash da senha fornecido pelo cliente não corresponde ao esperado.")
                mensagem = "Erro: Senha incorreta."

                # Criptografa a mensagem usando a chave pública do cliente
                encrypted_message = client_public_key.encrypt(
                    mensagem.encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                # Envia a mensagem cifrada para o cliente
                conn.sendall(encrypted_message)
            else:
                print("Hash da senha verificado com sucesso.")
                # Remove o has_senha do dicionário
                del dados_cliente['hash_senha']
                # Antes de adicionar a mensagem à blockchain, vamos converter a mensagem recebida de volta para string.
                mensagem_decifrada = decrypted_data.decode()
                # Adiciona os dados do cliente a um bloco na blockchain
                adicionar_bloco(blockchain, dados_cliente)

            # Imprime a blockchain atualizada
            print("\nBlockchain atualizada:")
            exibir_blockchain(blockchain)
