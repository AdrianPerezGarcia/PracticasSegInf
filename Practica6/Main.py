from Functions import readTextFromFile
from Functions import RSADecrypter
from User import User

print('Practica 6 Seguridad Informatica apereg24.\n')
print('-------------------------------------------------------------------------------------------------\n')

# Se obtiene el alfabeto de un fichero.
alphabet = readTextFromFile('data/alphabet.txt')
mod = len(alphabet)
print('Alfabeto -> \'' + alphabet + '\'.')
print('Modulo para operaciones: ' + str(mod) + '.')
print()

# Se mapean los usuarios con su clave publica RSA.
pepa = User()
pepa.name = 'Pepa'
pepa.n = 62439738695706104201747
pepa.e = 356812573
pepa.p = 249879448303
pepa.q = 249879448349

benito = User()
benito.name = 'Benito'
benito.n = 743330222539755158153
benito.e = 80263681
benito.p = 27264083009
benito.q = 27264083017

maria = User()
maria.name = 'Maria'
maria.n = 8849169404252643679
maria.e = 196413997
maria.p = 2974755337
maria.q = 2974755367

juan = User()
juan.name = 'Juan'
juan.n = 5244938048376303456108649
juan.e = 114340249
juan.p = 2290182972661
juan.q = 2290182972709

print(pepa.tostring())
print(benito.tostring())
print(maria.tostring())
print(juan.tostring())
print()

print('-------------------------------------------------------------------------------------------------\n')

# Ejercicio 1: Obtener el mensaje en claro del fichero model1.txt sabiendo que Pepa se lo envio a Benito.
print('Modelo 1: Pepa envia un mensaje a Benito.\n')
data1 = readTextFromFile('data/model1.txt')[1:-1]  # Substring para quitar las comillas.
print('Mensaje cifrado: \'' + data1 + '\'.\n')
print('Mensaje descifrado: \'' + RSADecrypter(data1, benito, alphabet) + '\'\n')

print('-------------------------------------------------------------------------------------------------\n')

# Ejercicio 2: Obtener el mensaje en claro del fichero model2.txt sabiendo que Benito se lo envio a Pepa.
print('Modelo 2: Benito envia un mensaje a Pepa.\n')
data2 = readTextFromFile('data/model2.txt')[1:-1]
print('Mensaje cifrado: \'' + data2 + '\'.\n')
print('Mensaje descifrado: \'' + RSADecrypter(data2, pepa, alphabet) + '\'\n')

print('-------------------------------------------------------------------------------------------------\n')

# Ejercicio 3: Obtener el mensaje en claro del fichero model3.txt sabiendo que Maria se lo envio a Juan.
print('Modelo 3: Maria envia un mensaje a Juan.\n')
data3 = readTextFromFile('data/model3.txt')[1:-1]
print('Mensaje cifrado: \'' + data3 + '\'.\n')
print('Mensaje descifrado: \'' + RSADecrypter(data3, juan, alphabet) + '\'\n')

print('-------------------------------------------------------------------------------------------------\n')

# Ejercicio 2: Obtener el mensaje en claro del fichero model4.txt sabiendo que Juan se lo envio a Maria.
print('Modelo 4: Juan envia un mensaje a Maria.\n')
data4 = readTextFromFile('data/model4.txt')[1:-1]
print('Mensaje cifrado: \'' + data4 + '\'.\n')
print('Mensaje descifrado: \'' + RSADecrypter(data4, maria, alphabet) + '\'\n')

print('-------------------------------------------------------------------------------------------------')
