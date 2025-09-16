# app.py

# Importa a biblioteca Streamlit, que é usada para criar a interface web da aplicação.
import streamlit as st
# Importa a biblioteca `string` para obter constantes de string, como o alfabeto em maiúsculas.
import string
# Importa componentes específicos da biblioteca `cryptography` para a implementação do RSA.
from cryptography.hazmat.backends import default_backend # Define o backend criptográfico a ser usado.
from cryptography.hazmat.primitives.asymmetric import rsa, padding # Para geração de chaves RSA e preenchimento (padding).
from cryptography.hazmat.primitives import hashes # Para usar algoritmos de hash (ex: SHA256).
from cryptography.hazmat.primitives import serialization # Para converter chaves em formatos de texto (PEM).

# ==============================================================================
# SEÇÃO 1: CIFRA DE CÉSAR
# ==============================================================================

def caesar_cipher(text, shift, mode):
    """
    Criptografa ou decifra um texto usando a Cifra de César.

    Args:
        text (str): A mensagem a ser processada.
        shift (int): O número de posições para deslocar no alfabeto.
        mode (str): 'encode' para criptografar, 'decode' para decifrar.

    Returns:
        str: A mensagem criptografada ou decifrada.
    """
    # Inicializa uma string vazia para armazenar o resultado.
    result = ""
    # Itera sobre cada caractere no texto de entrada.
    for char in text:
        # Verifica se o caractere é uma letra minúscula.
        if 'a' <= char <= 'z':
            # Define o ponto de partida como o código ASCII da letra 'a'.
            start = ord('a')
        # Verifica se o caractere é uma letra maiúscula.
        elif 'A' <= char <= 'Z':
            # Define o ponto de partida como o código ASCII da letra 'A'.
            start = ord('A')
        # Se não for uma letra (número, símbolo, espaço).
        else:
            # Adiciona o caractere ao resultado sem modificá-lo.
            result += char
            # Pula para a próxima iteração do loop.
            continue

        # Verifica se o modo é 'encode' (criptografar).
        if mode == 'encode':
            # Calcula o novo caractere deslocando-o para a frente e aplicando o módulo 26 para ciclar no alfabeto.
            shifted_char = chr(start + (ord(char) - start + shift) % 26)
        # Verifica se o modo é 'decode' (decifrar).
        elif mode == 'decode':
            # Calcula o novo caractere deslocando-o para trás e aplicando o módulo 26.
            shifted_char = chr(start + (ord(char) - start - shift) % 26)
        # Se o modo for inválido.
        else:
            # Retorna uma mensagem de erro.
            return "Modo inválido"
        
        # Adiciona o caractere processado (criptografado/decifrado) ao resultado.
        result += shifted_char
    
    # Retorna a string de resultado completa.
    return result

# ==============================================================================
# SEÇÃO 2: CIFRA DE VIGENÈRE
# ==============================================================================

def vigenere_cipher(text, key, mode):
    """
    Criptografa ou decifra um texto usando a Cifra de Vigenère.

    Args:
        text (str): A mensagem a ser processada.
        key (str): A palavra-chave para a cifra.
        mode (str): 'encrypt' para criptografar, 'decrypt' para decifrar.

    Returns:
        str: A mensagem criptografada ou decifrada.
    """
    # Inicializa uma string vazia para armazenar o resultado.
    result = ""
    # Remove espaços da chave e a converte para maiúsculas para consistência.
    key = key.replace(" ", "").upper()
    # Armazena o comprimento da chave.
    key_length = len(key)
    # Inicializa um índice para percorrer a chave.
    key_index = 0

    # Itera sobre cada caractere no texto de entrada.
    for char in text:
        # Verifica se o caractere é uma letra do alfabeto.
        if char.isalpha():
            # Obtém o deslocamento numérico da letra atual da chave (A=0, B=1, ...).
            shift = ord(key[key_index % key_length]) - ord('A')
            
            # Verifica se o modo é 'encrypt' (criptografar).
            if mode == 'encrypt':
                # Aplica a Cifra de César com o deslocamento da chave.
                result += caesar_cipher(char, shift, 'encode')
            # Verifica se o modo é 'decrypt' (decifrar).
            elif mode == 'decrypt':
                # Aplica a Cifra de César reversa com o deslocamento da chave.
                result += caesar_cipher(char, shift, 'decode')
            
            # Avança o índice da chave para a próxima letra.
            key_index += 1
        # Se o caractere não for uma letra.
        else:
            # Adiciona o caractere ao resultado sem modificação.
            result += char
            
    # Retorna a string de resultado completa.
    return result

# ==============================================================================
# SEÇÃO 3: CRIPTOGRAFIA RSA
# ==============================================================================

# Usa o cache do Streamlit para evitar gerar novas chaves a cada interação na UI.
@st.cache_data
def generate_rsa_keys():
    """Gera um par de chaves RSA (privada e pública)."""
    # Gera a chave privada com um expoente público padrão e um tamanho de 2048 bits.
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Deriva a chave pública a partir da chave privada.
    public_key = private_key.public_key()
    # Retorna ambas as chaves.
    return private_key, public_key

def encrypt_rsa_message(public_key, message):
    """Criptografa uma mensagem usando a chave pública RSA."""
    # Criptografa a mensagem (convertida para bytes) usando a chave pública.
    encrypted_message = public_key.encrypt(
        message.encode('utf-8'), # A mensagem precisa ser codificada em bytes.
        padding.OAEP( # OAEP é um esquema de preenchimento que adiciona aleatoriedade e segurança.
            mgf=padding.MGF1(algorithm=hashes.SHA256()), # Função de geração de máscara.
            algorithm=hashes.SHA256(), # Algoritmo de hash usado.
            label=None
        )
    )
    # Retorna a mensagem criptografada (em bytes).
    return encrypted_message

def decrypt_rsa_message(private_key, encrypted_message):
    """Decifra uma mensagem usando a chave privada RSA."""
    # Decifra a mensagem criptografada usando a chave privada.
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP( # O mesmo esquema de preenchimento da criptografia deve ser usado.
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Retorna a mensagem decifrada, decodificada de bytes para string.
    return decrypted_message.decode('utf-8')

def serialize_keys(private_key, public_key):
    """Converte as chaves RSA para o formato PEM para exibição."""
    # Serializa a chave privada para o formato PEM.
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Serializa a chave pública para o formato PEM.
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Retorna as chaves serializadas como strings (decodificadas de bytes).
    return pem_private_key.decode('utf-8'), pem_public_key.decode('utf-8')

# ==============================================================================
# SEÇÃO 4: MÁQUINA ENIGMA
# ==============================================================================

# Função para criar o plugboard (painel de conectores) da Enigma.
def create_plugboard(pairs_str):
    """Cria um dicionário de mapeamento para o plugboard a partir de uma string."""
    # Inicializa o plugboard onde cada letra aponta para si mesma.
    plugboard = {c: c for c in string.ascii_uppercase}
    # Remove espaços da string de pares e a converte para maiúsculas.
    pairs_str = pairs_str.replace(" ", "").upper()
    
    # Verifica se a string tem um número par de caracteres (formando pares).
    if len(pairs_str) % 2 != 0:
        # Se for ímpar, retorna o plugboard padrão e um erro.
        return None, "A string do plugboard deve conter pares de letras (ex: 'AB CD')."

    # Itera sobre a string de dois em dois caracteres para formar os pares.
    for i in range(0, len(pairs_str), 2):
        # Pega o par de letras.
        a, b = pairs_str[i], pairs_str[i+1]
        # Mapeia a primeira letra para a segunda.
        plugboard[a] = b
        # Mapeia a segunda letra para a primeira (conexão recíproca).
        plugboard[b] = a
        
    # Retorna o plugboard configurado e nenhuma mensagem de erro.
    return plugboard, None

# Função de substituição de um caractere pelo rotor.
def substitute(rotor, char, reverse=False):
    """Realiza a substituição de um caractere através de um rotor."""
    # Define o alfabeto como referência.
    alphabet = string.ascii_uppercase
    # Se for o caminho reverso (do refletor para a entrada).
    if reverse:
        # Encontra o índice do caractere no rotor e retorna a letra correspondente no alfabeto.
        return alphabet[rotor.index(char)]
    # Se for o caminho normal (da entrada para o refletor).
    else:
        # Encontra o índice do caractere no alfabeto e retorna a letra correspondente no rotor.
        return rotor[alphabet.index(char)]

# Função principal para simular a criptografia Enigma.
def enigma_machine(message, plugboard, rotors_config, reflector):
    """Simula a criptografia de uma mensagem pela máquina Enigma."""
    # Inicializa uma lista para armazenar o resultado.
    encrypted_message = []
    # Cria uma cópia da configuração dos rotores para poder modificá-la durante a execução.
    rotors = list(rotors_config) 

    # Para cada caractere na mensagem de entrada.
    for char in message.upper():
        # Se o caractere não for uma letra maiúscula.
        if char not in string.ascii_uppercase:
            # Adiciona o caractere ao resultado sem modificá-lo.
            encrypted_message.append(char)
            # Pula para a próxima iteração.
            continue

        # --- Simulação da Enigma ---
        
        # Rotação dos rotores (antes da substituição)
        # O rotor da direita (rotors[0]) gira a cada letra.
        rotors[0] = rotors[0][1:] + rotors[0][0] 
        # Verifica se o primeiro rotor completou uma volta (condição de "entalhe").
        # Esta é uma simplificação; a Enigma real era mais complexa.
        if len(encrypted_message) > 0 and len(encrypted_message) % 26 == 0:
            # Se sim, o segundo rotor (rotors[1]) gira.
            rotors[1] = rotors[1][1:] + rotors[1][0]
        
        # Passo 1: Passagem pelo Plugboard na entrada.
        char_after_plugboard = plugboard[char]

        # Passo 2: Passagem pelos rotores (da direita para a esquerda).
        char_through_rotors = char_after_plugboard
        # Itera pelos rotores na ordem configurada.
        for rotor in rotors:
            # Realiza a substituição de acordo com o rotor atual.
            char_through_rotors = substitute(rotor, char_through_rotors)

        # Passo 3: Passagem pelo Refletor.
        char_reflected = substitute(reflector, char_through_rotors)
        
        # Passo 4: Passagem reversa pelos rotores (da esquerda para a direita).
        char_return_through_rotors = char_reflected
        # Itera pelos rotores na ordem inversa.
        for rotor in reversed(rotors):
            # Realiza a substituição reversa.
            char_return_through_rotors = substitute(rotor, char_return_through_rotors, reverse=True)

        # Passo 5: Passagem final pelo Plugboard na saída.
        final_char = plugboard[char_return_through_rotors]
        
        # Adiciona o caractere final criptografado à lista de resultado.
        encrypted_message.append(final_char)

    # Junta todos os caracteres da lista em uma única string e a retorna.
    return "".join(encrypted_message)

# ==============================================================================
# SEÇÃO 5: INTERFACE DO USUÁRIO COM STREAMLIT
# ==============================================================================

# Define o título principal da aplicação.
st.title("🛠️ Ferramenta de Criptografia")
# Define um subtítulo ou descrição.
st.write("Uma aplicação para demonstrar diferentes algoritmos de criptografia.")

# Cria um menu de seleção na barra lateral.
st.sidebar.title("Menu de Criptografia")
# Define as opções do menu.
cipher_choice = st.sidebar.selectbox(
    "Escolha o método de criptografia:",
    ("Cifra de César", "Cifra de Vigenère", "RSA", "Máquina Enigma")
)

# --- Lógica para exibir a interface da Cifra de César ---
if cipher_choice == "Cifra de César":
    # Exibe o cabeçalho para a cifra selecionada.
    st.header("Cifra de César")
    # Cria uma área de texto para o usuário inserir a mensagem.
    text_to_process = st.text_area("Digite o texto aqui:")
    # Cria um campo numérico para o deslocamento (chave).
    shift_key = st.number_input("Digite o deslocamento (chave)", min_value=1, max_value=25, value=3)
    # Cria botões de rádio para escolher entre codificar e decodificar.
    mode = st.radio("Escolha a operação:", ('Codificar', 'Decodificar'))

    # Cria um botão para iniciar o processamento.
    if st.button("Processar César"):
        # Mapeia a escolha do rádio para o argumento esperado pela função.
        mode_arg = 'encode' if mode == 'Codificar' else 'decode'
        # Chama a função da Cifra de César com os dados do usuário.
        result = caesar_cipher(text_to_process, shift_key, mode_arg)
        # Exibe um subtítulo para o resultado.
        st.subheader("Resultado:")
        # Exibe o resultado em uma caixa de sucesso.
        st.success(result)

# --- Lógica para exibir a interface da Cifra de Vigenère ---
elif cipher_choice == "Cifra de Vigenère":
    # Exibe o cabeçalho para a cifra selecionada.
    st.header("Cifra de Vigenère")
    # Cria uma área de texto para a mensagem.
    text_to_process = st.text_area("Digite o texto aqui:")
    # Cria um campo de texto para a palavra-chave.
    vigenere_key = st.text_input("Digite a palavra-chave:")
    # Cria botões de rádio para escolher a operação.
    mode = st.radio("Escolha a operação:", ('Criptografar', 'Decriptografar'))

    # Cria um botão para iniciar o processamento.
    if st.button("Processar Vigenère"):
        # Verifica se a chave foi inserida.
        if vigenere_key:
            # Mapeia a escolha do rádio para o argumento da função.
            mode_arg = 'encrypt' if mode == 'Criptografar' else 'decrypt'
            # Chama a função da Cifra de Vigenère.
            result = vigenere_cipher(text_to_process, vigenere_key, mode_arg)
            # Exibe o subtítulo do resultado.
            st.subheader("Resultado:")
            # Exibe o resultado em uma caixa de sucesso.
            st.success(result)
        # Se a chave estiver vazia.
        else:
            # Exibe um aviso para o usuário.
            st.warning("Por favor, insira uma palavra-chave.")

# --- Lógica para exibir a interface do RSA ---
elif cipher_choice == "RSA":
    # Exibe o cabeçalho para a cifra selecionada.
    st.header("Criptografia RSA")
    # Cria uma área de texto para a mensagem a ser criptografada.
    text_to_encrypt = st.text_area("Digite a mensagem para criptografar:")
    
    # Cria um botão para iniciar todo o processo RSA.
    if st.button("Gerar Chaves, Criptografar e Decriptografar"):
        # Verifica se o usuário digitou alguma mensagem.
        if text_to_encrypt:
            # Exibe uma mensagem de status enquanto as chaves são geradas.
            with st.spinner("Gerando par de chaves RSA (pública e privada)..."):
                # Chama a função para gerar as chaves.
                private_key, public_key = generate_rsa_keys()
                # Converte as chaves para formato de texto para exibição.
                pem_private, pem_public = serialize_keys(private_key, public_key)
            
            # Exibe uma mensagem de sucesso.
            st.success("Chaves geradas com sucesso!")
            
            # Exibe a chave pública.
            st.subheader("Chave Pública (para criptografar)")
            st.code(pem_public, language='pem')

            # Exibe a chave privada.
            st.subheader("Chave Privada (para decifrar)")
            st.code(pem_private, language='pem')
            
            # Criptografa a mensagem usando a chave pública.
            encrypted = encrypt_rsa_message(public_key, text_to_encrypt)
            # Exibe a mensagem criptografada (em formato hexadecimal para facilitar a leitura).
            st.subheader("Mensagem Criptografada")
            st.code(encrypted.hex())

            # Decifra a mensagem usando a chave privada.
            decrypted = decrypt_rsa_message(private_key, encrypted)
            # Exibe a mensagem original decifrada.
            st.subheader("Mensagem Decifrada")
            st.success(decrypted)
        # Se nenhuma mensagem foi inserida.
        else:
            # Exibe um aviso.
            st.warning("Por favor, digite uma mensagem para criptografar.")

# --- Lógica para exibir a interface da Máquina Enigma ---
elif cipher_choice == "Máquina Enigma":
    # Exibe o cabeçalho.
    st.header("Máquina Enigma")
    # Explica como a Enigma funciona (reciprocidade).
    st.info("A Enigma é recíproca: criptografar o texto cifrado com as mesmas configurações retorna o texto original.")
    
    # Configurações fixas da Enigma para esta simulação.
    ROTOR_I = "EKMFLGDQVZNTOWYHXUSPAIBRCJ"
    ROTOR_II = "AJDKSIRUXBLHWTMCQGZNPYFVOE"
    ROTOR_III = "BDFHJLCPRTXVZNYEIWGAKMUSQO"
    REFLECTOR_B = "YRUHQSLDPXNGOKMIEBFZCWVJAT"
    
    # Cria uma área de texto para a mensagem.
    text_to_process = st.text_area("Digite o texto (apenas letras serão processadas):")
    # Cria um campo de texto para o usuário configurar o plugboard.
    plugboard_str = st.text_input("Configuração do Plugboard (ex: AB CD EF)", "AV BS CG DL FU HZ IN KM OW RX")
    
    # Cria um botão para processar a mensagem.
    if st.button("Processar Enigma"):
        # Chama a função para criar o plugboard a partir da string do usuário.
        plugboard, error = create_plugboard(plugboard_str)
        # Se houver um erro na configuração do plugboard.
        if error:
            # Exibe o erro.
            st.error(error)
        # Se a configuração for válida.
        else:
            # Chama a função da máquina Enigma para criptografar a mensagem.
            result = enigma_machine(text_to_process, plugboard, [ROTOR_I, ROTOR_II, ROTOR_III], REFLECTOR_B)
            # Exibe o resultado.
            st.subheader("Resultado:")
            st.success(result)