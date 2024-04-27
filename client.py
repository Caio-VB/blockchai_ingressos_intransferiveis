from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend  # Importe default_backend
import socket
import json

def obter_dados_compra():
    senha = input("Digite a senha do sistema: ")      # Senha para usar o sistema (Ingresso1234)
    nome = input("Digite o nome do comprador: ")
    cpf = input("Digite o CPF do comprador: ")
    ingresso = input("Digite o código do ingresso: ")
    return senha, nome, cpf, ingresso

# Gerar chaves pública e privada
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()  # Use default_backend()
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

# Configurações do cliente
HOST = 'localhost'  # Endereço IP do servidor
PORT = 1234        # Porta utilizada pelo servidor

while True:
    # Cria um socket TCP/IP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        # Conecta ao servidor
        client_socket.connect((HOST, PORT))

        # Recebe a chave pública do servidor
        server_public_key_pem = client_socket.recv(2048)
        server_public_key = serialization.load_pem_public_key(
            server_public_key_pem,
            backend=default_backend()
        )

        # Envia a chave pública para o servidor
        client_socket.sendall(public_key_pem)

        # Dados da compra
        senha, nome, cpf, ingresso = obter_dados_compra()

        # Gera um hash com a senha inputada
        hash_senha = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hash_senha.update(senha.encode())
        hash_senha = hash_senha.finalize()

        # Antes de adicionar o hash_senha ao dicionário dados_compra, vamos convertê-lo para uma representação serializável.
        hash_senha_hex = hash_senha.hex()

        # Agora podemos adicionar o hash_senha convertido ao dicionário dados_compra.
        dados_compra = {
            'nome': nome,
            'cpf': cpf,
            'ingresso': ingresso,
            'hash_senha': hash_senha_hex  # Usando a representação em hexadecimal do hash_senha
        }

        # Converte o dicionário para uma string JSON
        dados_json = json.dumps(dados_compra)

        # Criptografa os dados com a chave pública do servidor
        encrypted_data = server_public_key.encrypt(
            dados_json.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Envia os dados criptografados para o servidor
        client_socket.sendall(encrypted_data)

        # Recebe a mensagem cifrada do servidor
        encrypted_message = client_socket.recv(4096)

        # Decifra a mensagem usando a chave privada do cliente
        decrypted_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Exibe a mensagem decifrada
        print("Resposta do servidor:", decrypted_message.decode())

    continuar = input("\nDeseja adicionar ou validar outro ingresso? (s/n): ")
    if continuar.lower() != 's':
        break
