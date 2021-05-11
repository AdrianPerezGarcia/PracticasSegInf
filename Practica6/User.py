from Functions import modularInverse
from Functions import debug


class User:

    n = -1
    e = -1
    p = -1
    q = -1
    d = -1
    name = ''

    def calculatePrivateKey(self):
        # En la practica p y q son datos (No hay que calcularlos).
        phy = (self.p - 1) * (self.q - 1)
        self.d = modularInverse(self.e, phy)
        debug('-------------------')
        debug('Calculando la clave privada.')
        debug('Factorizaciones de n: p = ' + str(self.p) + ', q = ' + str(self.q) + '.')
        debug('Phy = (p - 1) * (q - 1) = ' + str(phy) + '.')
        debug('Clave privada (d) = Inverso de e en modulo Phy = ' + str(self.d) + '.')
        debug('-------------------')

    def tostring(self):
        return 'Clave publica para RSA de ' + self.name + ': n = ' + str(self.n) + ', e = ' + str(self.e) + '.'
