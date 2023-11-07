import os

chave_random = os.urandom(32)
msg_aleatorio = os.urandom(8)

S_BOX = [
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
]

sbox = lambda bin: S_BOX[(bin >> 4) & 0xF][bin & 0xF]

r_con = [None] * 10
r_con[0] = 1

for x in range(1, 10):
    r_con[x] = (r_con[x - 1] << 1) ^ (0x11B if r_con[x - 1] >= 0x80 else 0)
    r_con[x] &= 0xFF 

def gera_matriz(data):
    matrix = [[0] * 4 for _ in range(4)]
    for col in range(3, -1, -1):
        for row in range(3, -1, -1):
            matrix[row][col] = data & 0xFF
            data >>= 8
    return matrix

def hex_append(a, b):
    if b == 0:
        return a
    
    sizeof_b_hex = ((b.bit_length() - 1) // 4 + 1) * 4
    return (a << sizeof_b_hex) | b

def add_round_key(key, matrix):
    key_matrix = gera_matriz(key)
    matrix = [[matrix[r][c] ^ key_matrix[r][c] for c in range(4)] for r in range(4)]

def byte_substitution(matrix):
    return [[sbox(byte) for byte in row] for row in matrix]


def rotacionar_esq_linha(matrix, rowNum, shiftCount):
    matrix[rowNum] = matrix[rowNum][shiftCount:] + matrix[rowNum][:shiftCount]
    return matrix

def shift_rows(matrix):
    matrix = rotacionar_esq_linha(matrix, 1, 1)
    matrix = rotacionar_esq_linha(matrix, 2, 2)
    matrix = rotacionar_esq_linha(matrix, 3, 3)

def mmult(matb):
    c = [0] * 4

    for i in range(4):
        a = matb[i]
        b = matb[(i + 1) % 4]
        c[i] = a ^ ((b << 1) ^ ((b >> 7) * 0x1B)) ^ ((a << 1) ^ ((a >> 7) * 0x1B) ^ ((a >> 6) * 0x36))

    return c

def mix_columns(matrix):
    for c in range(4):
        col = [matrix[r][c] for r in range(4)]
        matrix[:][c] = mmult(col) # Teve que fazer usando uma copia shallow pq tava quebrando sem

    return matrix

def g_func(wIn, rc):
    wIn = (lambda wIN: (((wIN << 8) & 0xFFFFFF00)  | ((wIN >> 24) & 0xFF)))(wIn)

    w0, w1, w2, w3 = (wIn >> 24) & 0xFF, (wIn >> 16) & 0xFF, (wIn >> 8) & 0xFF, wIn & 0xFF
    w0, w1, w2, w3 = sbox(w0) ^ rc, sbox(w1), sbox(w2), sbox(w3)
    
    ret = (w0 << 24) | (w1 << 16) | (w2 << 8) | w3
    return ret

def h_func(wIn):
    ret = ((sbox(wIn >> 24 & 0xFF) << 24) |
           (sbox(wIn >> 16 & 0xFF) << 16) |
           (sbox(wIn >> 8 & 0xFF) << 8) |
           sbox(wIn & 0xFF))
    return ret

def separar_chave(inkey):
    words = [ (inkey >> shift) & 0xFFFFFFFF for shift in range(224, -1, -32)]
    words.extend([None] * (60 - len(words)))
    return words

def expansao_chave(inkey):
    words = separar_chave(inkey)
    rconIdx = 0

    for x in range(8, 60):
        if x % 8 == 0:
            rc = r_con[rconIdx]
            rconIdx += 1
            words[x] = g_func(words[x - 1], rc) ^ words[x - 8]
        elif x % 4 == 0:
            words[x] = h_func(words[x - 1]) ^ words[x - 8]
        else:
            words[x] = words[x - 1] ^ words[x - 8]

    keys = []
    for x in range(4, 45, 4):
        key = (words[x - 4] << 96) | (words[x - 3] << 64) | (words[x - 2] << 32) | words[x - 1]
        keys.append(key)

    return keys
    
def aes_encrypt(data, chave):
    round_keys = expansao_chave(chave)
    matrix = gera_matriz(data)
    add_round_key(round_keys[0], matrix)

    for round_num, round_key in enumerate(round_keys[1:], start=1):
        add_round_key(round_key, matrix)
        if round_num < 9:
            mix_columns(matrix)
        shift_rows(matrix)
        matrix = byte_substitution(matrix)
    
    cipher = sum((matrix[r][c] << (24 - 8 * c)) for c in range(4) for r in range(4))
    return cipher

def aes_decrypt(data, chave):
    round_keys = expansao_chave(chave)
    matrix = gera_matriz(data)
    add_round_key(round_keys[0], matrix)

    for round_num, round_key in enumerate(round_keys[1:], start=1):
        if round_num < 9:
            mix_columns(matrix)
        add_round_key(round_key, matrix)
        matrix = byte_substitution(matrix)
        shift_rows(matrix)
    
    cipher = sum((matrix[r][c] << (24 - 8 * c)) for c in range(4) for r in range(4))
    return cipher


def cypher(chave):
    texto = input("Escreva a mensagem a ser decodificada: ")
    info = [texto[i:i+16] for i in range(0, len(texto), 16)][:16]
    texto = texto.encode()
    texto = int.from_bytes(texto, "big")
    cont = 0
    for i, _ in enumerate(info):
        for _ in range(16 - i):
            cont += 1
            i_hex = hex(i)[2:].zfill(2)
            i_byte = bytes.fromhex(i_hex) 
            k = i_byte +  b'\x00'
        j = int.from_bytes(k, "big")
        data_random = msg_aleatorio + i.to_bytes(8,byteorder='big')
        data = int.from_bytes(data_random, "big")
        resp = aes_encrypt(data, chave)
        cifer = resp ^ j
        if i == 0:
            cifrado = cifer
        else:
            cifrado = hex_append(cifrado,cifer)

    return cifrado , cont    

def decipher(texto, chave, msg_aleatorio):
    texto_bytes = texto.to_bytes((texto.bit_length() + 7) // 8, 'big')
    mensagem_bytes = []
    for i in range(0, len(texto_bytes), 16):
        bloco = texto_bytes[i:i + 16]
        mensagem_bytes.append(int.from_bytes(bloco, 'big'))

    decifrado = 0
    for i, bloco in enumerate(mensagem_bytes):
        contador_bytes = (i * 8).to_bytes(8, byteorder='big')
        data_random_bytes = msg_aleatorio + contador_bytes
        data = int.from_bytes(data_random_bytes, 'big')
        resp = aes_decrypt(data, chave)
        cifer = resp ^ bloco
        decifrado = hex_append(decifrado, cifer)

    hex_decifrado = hex(decifrado)[2:]
    if len(hex_decifrado) % 2 != 0:
        hex_decifrado = '0' + hex_decifrado  
    return hex_decifrado

def main():
    chave = int.from_bytes(chave_random, "big")
    cifrado, cont = cypher(chave)
    print(cifrado, cont)
    #decifrado = decipher(cifrado, chave, msg_aleatorio)
    #print(decifrado)

if __name__ == "__main__":
    main()