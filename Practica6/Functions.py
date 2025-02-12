from math import log
from math import floor

# 1 = Si, 0 = No.
debugMode = 0


def debug(text):
    if debugMode == 1:
        print(text)


# Funcion encargada de obtener un texto de un fichero.
def readTextFromFile(path):
    file = open(path, 'r', encoding='utf8')
    text = file.read()
    file.close()
    return text


# Inverso modular.
def modularInverse(a, mod):
    return pow(a, -1, mod)


# Algoritmo de potenciacion modular.
def powerModInt(a, k, n):
    # Obtenido de https://elbauldelprogramador.com/criptografia-101-fundamentos-matematicos-ii/
    b = 1
    if k == 0:
        return b
    A = a
    # If the least significant bit is 1, $a^1 = a$
    if 1 & k:
        b = a
    k = k >> 1
    while k:
        A = (A ** 2) % n
        if 1 & k:
            b = (b * A) % n
        k = k >> 1
    return b


# Convertir conjunto de enteros a conjunto de bloques de longitud k.
def integerToBlocks(integer, k, mod):
    blocks = []
    for i in range(k):
        # Se insertan los restos de la division entre el entero y el modulo.
        blocks.insert(0, integer % mod)
        integer = integer // mod
        if integer <= mod:
            # Cuando el entero ya es menor se inserta el mismo y se rellena con 0's si aun no es de longitud k.
            blocks.insert(0, integer)
            while len(blocks) < k:
                blocks.insert(0, 0)
            break
    return blocks


# Convertir conjunto de bloques a enteros.
def blocksToIntegers(blocks, mod):
    integers = []
    for element in blocks:
        # Se invierte el array para hacer el ultimo * modulo a la 0, penultimo * modulo a la 1 ...
        element.reverse()
        integer = 0
        for i in range(len(element)):
            integer += element[i] * (mod ** i)
        integers.append(integer)
    return integers


def RSADecrypter(encryptedData, receiver, alphabet):
    # Se calcula la longitud del alfabeto (Modulo para operaciones).
    mod = len(alphabet)

    # Se convierte el dato como String a lista de enteros (Posicion de cada string en el alfabeto.
    encryptedDataList = [alphabet.index(element) for element in encryptedData]
    debug('Mensaje cifrado como posiciones del alfabeto: ' + str(encryptedDataList) + '.')

    # Se calcula la longitud del bloque a cifrar.
    k = floor(log(receiver.n, mod))  # k es el entero tal que N^k <= n < N^(k+1).
    debug('k = ' + str(k))

    # Se separa el dato en cadenas de longitud k+1.
    splitData = [encryptedDataList[i:i + (k + 1)] for i in range(0, len(encryptedDataList), (k + 1))]
    debug('Mensaje cifrado en bloques de longitud k+1: ' + str(splitData) + '.')

    # Se convierte el bloque a entero con una funcion auxiliar
    debug('Se convierten cada bloque a entero (Para cada elemento del bloque es ultimo * mod^0 hasta 1º * mod^k).')
    integersCyphered = blocksToIntegers(splitData, mod)
    debug('C (Enteros cifrados): ' + str(integersCyphered) + '.')

    # Si no esta ya calculada se calcula la clave privada del usuario.
    debug('Si no esta calculada se calcula la clave privada de ' + receiver.name)
    if receiver.d == -1:
        receiver.calculatePrivateKey()

    # Se aplica RSA simple para descifrar para entero.
    debug('Se descifran los enteros usando rsa (C^d mod n).')
    integers = []
    for element in integersCyphered:
        integers.append(powerModInt(element, receiver.d, receiver.n))
    debug('M (Enteros descifrados): ' + str(integers) + '.')

    debug('Se convierten los enteros M a bloques de longitud k.')
    splitMessage = []
    for element in integers:
        splitMessage.append(integerToBlocks(element, k, mod))
    debug('Bloques descifrados: ' + str(splitMessage) + '.')

    debug('Se convierten los bloques de lista de posiciones a caracteres del alfabeto.\n')
    message = ''
    for element in splitMessage:
        for number in element:
            message += alphabet[int(number)]

    # Se devuelve el mensaje cambiando dos espacios por un salto de linea.
    return message.replace('  ', '\n')
