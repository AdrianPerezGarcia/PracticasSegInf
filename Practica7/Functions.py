from math import log
from math import floor

# 1 = Si, 0 = No.
debugMode = 1


def debug(text):
    if debugMode == 1:
        print(text)


def readTextFromFile(path):
    # Funcion encargada de obtener un texto de un fichero.
    file = open(path, 'r', encoding='utf8')
    text = file.read()
    file.close()
    return text


def modularInverse(a, mod):
    # Inverso modular.
    return pow(a, -1, mod)


def powerModInt(a, k, n):
    # Algoritmo de potenciacion modular.
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


def integerToBlocks(integer, k, mod):
    # Convertir conjunto de enteros a conjunto de bloques de longitud k.
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


def blocksToIntegers(blocks, mod):
    # Convertir conjunto de bloques a enteros.
    integers = []
    for element in blocks:
        # Se invierte el array para hacer el ultimo * modulo a la 0, penultimo * modulo a la 1 ...
        element.reverse()
        integer = 0
        for i in range(len(element)):
            integer += element[i] * (mod ** i)
        integers.append(integer)
    return integers


def primeFactors(n):
    i = 2
    factors = []
    while i * i <= n:
        if n % i:
            i += 1
        else:
            n //= i
            factors.append(i)
    if n > 1:
        factors.append(n)
    return factors


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

    debug('Se convierten los bloques de lista de posiciones a caracteres del alfabeto.')
    message = ''
    for element in splitMessage:
        for number in element:
            message += alphabet[int(number)]

    # Se devuelve el mensaje cambiando dos espacios por un salto de linea.
    return message.replace('  ', '\n')


def extendKey(key, extendedLength, alphabet):
    debug('Clave sin extender: \'' + str(key) + '\'')

    mod = len(alphabet)
    extendedKey = ''
    equationCoefficients = []
    extendedKeyNumeric = []
    # Se marcan los coeficientes de la ecuacion y se añade la clave original a la extendida.
    for element in key:
        equationCoefficients.append(alphabet.index(element))
        extendedKeyNumeric.append(alphabet.index(element))

    # Se van calculando iterativamente todas las nuevas posiciones de la clave extendida usando la ecuacion.
    for i in range(extendedLength - len(key)):
        baseCalculator = extendedKeyNumeric[i: i + len(key)]
        newKey = 0
        for j in range(len(equationCoefficients)):
            newKey += (baseCalculator[j] * extendedKeyNumeric[j])
        extendedKeyNumeric.append(newKey % mod)

    extendedKey = ''
    for element in extendedKeyNumeric:
        extendedKey += alphabet[element]

    debug('Clave extendida numerica: \'' + str(extendedKeyNumeric) + '\'')
    debug('Clave extendida: \'' + str(extendedKey) + '\'')
    return extendedKeyNumeric


def vigenereDecrypter(encryptedData, key, alphabet):
    debug('Se descifra el mensaje utilizando el sistema de Vigenère.')

    # Se extiende la clave de Vigenère con la ecuacion de recurrencia lineal.
    extendedKey = extendKey(key, len(encryptedData), alphabet)

    # Cada posicion descifrada sera la cifrada menos la clave en el modulo del alfabeto.
    message = ''
    mod = len(alphabet)
    for i in range(len(encryptedData)):
        message += alphabet[(alphabet.index(encryptedData[i]) - extendedKey[i]) % mod]

    return message


def mixedDecrypter(encryptedPair, receiver, alphabet):
    # Primero se descifra la clave de Vigenère (K) usando el descifrado de RSA por bloques usado en la practica 6.
    debug('\nDescifrando la clave de Vigenère mediante RSA por bloques: ' + encryptedPair[0])
    vigenereKey = RSADecrypter(encryptedPair[0], receiver, alphabet)
    debug('Clave descifrada: ' + vigenereKey)

    # Una vez se tiene la clave se usa una funcion auxiliar para hacer el descifrado por la variante de Vigenère
    return vigenereDecrypter(encryptedPair[1], vigenereKey, alphabet)


def RSAEncryptor(data, receiver, alphabet):
    # Se calcula la longitud del alfabeto (Modulo para operaciones).
    mod = len(alphabet)

    # Se convierte el dato como String a lista de enteros (Posicion de cada string en el alfabeto.
    encryptedDataList = [alphabet.index(element) for element in data]
    debug('Mensaje como posiciones del alfabeto: ' + str(encryptedDataList) + '.')

    # Se calcula la longitud del bloque a cifrar.
    k = floor(log(receiver.n, mod))  # k es el entero tal que N^k <= n < N^(k+1).
    debug('k = ' + str(k))

    # Se separa el dato en cadenas de longitud k.
    splitData = [encryptedDataList[i:i + k] for i in range(0, len(encryptedDataList), k)]
    debug('Mensaje cifrado en bloques de longitud k+1: ' + str(splitData) + '.')

    # Se convierte el bloque a entero con una funcion auxiliar
    debug('Se convierten cada bloque a entero (Para cada elemento del bloque es ultimo * mod^0 hasta 1º * mod^k).')
    integers = blocksToIntegers(splitData, mod)
    debug('M (Enteros sin cifrar): ' + str(integers) + '.')

    # Se cifra cada entero con RSA simple (c = m ^ e mod n).
    integersCyphered = []
    for element in integers:
        integersCyphered.append(powerModInt(element, receiver.e, receiver.n))
    debug('C (Enteros cifrados): ' + str(integersCyphered) + '.')

    # Se convierte cada entero cifrado a bloque de longitud k+1.
    blocks = [integerToBlocks(element, (k + 1), mod) for element in integersCyphered]
    debug('Bloques cifrados: ' + str(blocks) + '.')

    # El mensaje sera, para cada posicion de cada bloque, la posicion a la que corresponda en el alfabeto.
    messageCyphered = ''
    for block in blocks:
        for number in block:
            messageCyphered += alphabet[number]

    return messageCyphered


def vigenereEncryptor(data, key, alphabet):
    debug('Se cifra el mensaje utilizando el sistema de Vigenère.')

    # Se extiende la clave de Vigenère con la ecuacion de recurrencia lineal.
    extendedKey = extendKey(key, len(data), alphabet)

    # Cada posicion cifrada sera la suma numerica del mensaje y la clave en el modulo del alfabeto.
    encryptedMessage = ''
    mod = len(alphabet)
    for i in range(len(data)):
        encryptedMessage += alphabet[(alphabet.index(data[i]) + extendedKey[i]) % mod]

    return encryptedMessage


def mixedEncryptor(data, key, receiver, alphabet):
    debug('\nSe obtiene C (Dato cifrado con el sistema de Vigènere).')
    encryptedMessage = vigenereEncryptor(data, key, alphabet)
    debug('Mensaje cifrado con Vigenère: \'' + encryptedMessage + '\'')

    debug('Se obtiene K* (Clave cifrada usando RSA por bloques).')
    encryptedKey = RSAEncryptor(key, receiver, alphabet)
    debug('Clave cifrada con RSA: \'' + encryptedKey + '\'\n')

    return [encryptedKey, encryptedMessage]
