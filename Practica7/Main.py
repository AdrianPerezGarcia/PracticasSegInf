import Functions
from User import User


# Funcion encargada de obtener un texto de un fichero.
def getText(path):
    file = open(path, 'r', encoding='utf8')
    text = file.read()
    file.close()
    return text


print('Practica 7 Seguridad Informatica apereg24\n')

# Se obtiene el alfabeto de un fichero.
alphabet = getText('data/alphabet.txt')
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
dataEx1 = getText('data/data.txt').split(',')
print('Mensaje a descifrar:', dataEx1)
# Se delega el descifrado en una funcion auxiliar.
print('Mensaje descifrado: \'' + Functions.mixedDecrypter(dataEx1, alicia, alphabet) + '\'.')

# Ejercicio 2: Cifrar el mensaje del fichero data2.txt usando como clave de Vigenère la cadena del fichero key2.txt
print('\nEjercicio 2: ')
dataEx2 = getText('data/data2.txt')
keyEx2 = getText('data/key2.txt')
print('Mensaje a cifrar: \'' + dataEx2 + '\' (Clave de Vigenère: \'' + keyEx2 + '\').')
print('Par cifrado:', Functions.mixedEncryptor(dataEx2, keyEx2, benito, alphabet))
