from Functions import modularInverse
from Functions import debug
from Functions import primeFactors


class User:
    n = -1
    e = -1
    p = -1
    q = -1
    d = -1
    name = ''

    def calculatePrivateKey(self):
        # Si no se conocen p y q se calculan.
        if (self.p == -1) | (self.q == -1):
            self.calculatePAndQ()

        phy = (self.p - 1) * (self.q - 1)
        self.d = modularInverse(self.e, phy)
        debug('-------------------')
        debug('Calculando la clave privada.')
        debug('Factorizaciones de n: p = ' + str(self.p) + ', q = ' + str(self.q) + '.')
        debug('Phy = (p - 1) * (q - 1) = ' + str(phy) + '.')
        debug('Clave privada (d) = Inverso de e en modulo Phy = ' + str(self.d) + '.')
        debug('-------------------')

    def calculatePAndQ(self):
        # Se delega el calculo en una funcion auxiliar.
        factors = primeFactors(self.n)
        self.p = factors[0]
        self.q = factors[1]

    def tostring(self):
        return 'Clave publica para RSA de ' + self.name + ': n = ' + str(self.n) + ', e = ' + str(self.e) + '.'
