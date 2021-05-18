import Functions
from User import User

print('Practica 7 Seguridad Informatica apereg24\n')

# Se obtiene el alfabeto de un fichero.
alphabet = Functions.readTextFromFile('data/alphabet.txt')
mod = len(alphabet)
print('Alfabeto -> ' + alphabet)
print('Modulo para operaciones: ' + str(mod))
print()

# Se mapean los usuarios con su clave publica RSA.
alicia = User()
alicia.name = 'Alicia'
alicia.n = 21962054407
alicia.e = 80263681

benito = User()
benito.name = 'Benito'
benito.n = 9641865053
benito.e = 70241161

print(alicia.tostring())
print(benito.tostring())

# Ejercicio 1: Descifrar el par del fichero data.txt recibido por Alicia.
print('\nEjercicio 1: ')
dataEx1 = Functions.readTextFromFile('data/data.txt').split(',')
print('Mensaje a descifrar recibido por Alicia:', dataEx1)
# Se delega el descifrado en una funcion auxiliar.
print('Mensaje descifrado: \'' + Functions.mixedDecrypter(dataEx1, alicia, alphabet) + '\'.')

# Ejercicio 2: Cifrar el mensaje del fichero data2.txt usando como clave de Vigenère la cadena del fichero key2.txt
print('\nEjercicio 2: ')
dataEx2 = Functions.readTextFromFile('data/data2.txt')
keyEx2 = Functions.readTextFromFile('data/key2.txt')
print('Mensaje a cifrar para enviar a Benito: \'' + dataEx2 + '\' (Clave de Vigenère: \'' + keyEx2 + '\').')
print('Par cifrado:', Functions.mixedEncryptor(dataEx2, keyEx2, benito, alphabet))

angel = User()
angel.name = "Angel"
angel.n = 532891
angel.e = 11111

bea = User()
bea.name = 'Bea'
bea.n = 2641
bea.e = 497

print('\n-------------------------------------------------------------------------------------------------------\n')
print('Parte extra 18/05/2021\n')
alphabetExtra = Functions.readTextFromFile('data/alphabet2.txt')
print('Nuevo alfabeto', alphabet)
print()

print(angel.tostring())
print(bea.tostring())

# Ejercicio extra preparacion
print('\nEjercicio extra 18/05/2021')
dataExtra = ['CCT', 'WAVODS']
print('Mensaje a descifrar recibido por Bea:', dataExtra)
print('Mensaje descifrado: \'' + Functions.mixedDecrypter(dataExtra, bea, alphabetExtra) + '\'.')

# Ejercicio extra preparacion 2
print('\nEjercicio extra 2 18/05/2021: ')
dataExtra2 = 'SANSEBASTIAN'
keyExtra2 = 'CAMINODE'
print('Mensaje a cifrar para enviar a Angel: \'' + dataEx2 + '\' (Clave de Vigenère: \'' + keyEx2 + '\').')
print('Par cifrado:', Functions.mixedEncryptor(dataExtra2, keyExtra2, angel, alphabetExtra))

