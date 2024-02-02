import random,hashlib,math
from base64 import b64encode,b85decode

class Rsa:
    def __init__(self,bits:int) -> None:
        self.p = None #prime number
        self.q = None #prime number
        self.n = None #modulus
        self.phi = None #Euler's totient
        self.e = 65537 #
        self.d = None
        self.bits = bits
        self._generateKey()

    def history(self)->None:
        h = 'RSA is a public-key cryptosystem that is widely used in the world today to provide a secure transmission system to millions of communications, is one of the oldest such systems in existence. The acronym RSA comes from the surnames of Ron Rivest, Adi Shamir, and Leonard Adleman, who publicly described the algorithm in 1977. An equivalent system was developed secretly, in 1973 at GCHQ (the British signals intelligence agency), by the English mathematician Clifford Cocks. That system was declassified in 1997.'
        print(f'\n\n{h}\n')

    def _gcd(a:int, b:int)->int:
        '''
        Euclid's algorithm
        '''
        while b != 0:
            a, b = b, a % b
        return a

    def _millerRabin(self,n:int,k:int)->bool:
        '''
        Miller Rabin Primality test
        '''
        d = n - 1
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x in [1, -1]:
                continue
            return False
        return True

    def _randomPrime(self,bits:int)->int:
        while True:
            x = random.randrange(2 ** (bits - 1) + 1, 2 ** bits - 1, 2)
            if pow(2, x - 1, x) == 1:
                if self._millerRabin(x, 40):
                    return x
    
    def _egcd(self,e:int, n:int)->tuple:
        '''
        Extended Euler's algorithm
        '''
        if e == 0:
            return (n, 0, 1)
        
        g, y, x = self._egcd(n % e, e)
        return (g, x - (n // e) * y, y)

    def _modinv(self, a:int, m:int)->int:
        g, x, y = self._egcd(a, m)
        if g != 1:
            raise Exception('modular inverse does not exist')
        
        return x % m

    def _generateKey(self)->None:
        self.p = self._randomPrime(self.bits)
        while (prime := self._randomPrime(self.bits)) == self.p:
            pass
        self.q = prime
        self.n = self.p*self.q #Euler's totient
        self.phi = (self.p - 1) * (self.q - 1)
        self.d = self._modinv(self.e, self.phi) #
        if self.d < 0:
            self.d += self.phi

    def getPublicKey(self)->tuple:
        return (self.e,self.n)

    def encrypt(self,message:str,publicKey:tuple)->tuple:
        array = []
        for char in message:
            encryptedText = pow(ord(char),publicKey[0],publicKey[1])
            array.append(encryptedText)
        return tuple(array)

    def decrypt(self,array)->str:
        decryptedText = ''
        for integer in array:
            decrypted = pow(integer,self.d,self.n)
            decryptedText += chr(decrypted)
        return decryptedText
    
    def signature(self,msg:bytes)->int:
        h = int.from_bytes(hashlib.sha256(msg).digest(),byteorder='big')
        sig = pow(h,self.d,self.n)
        return sig
    
    def verify(self,signature,msg)->None:
        h = int.from_bytes(hashlib.sha256(msg).digest(),byteorder='big')
        hashSig = pow(signature,self.e,self.n)

class Exploits:
    def __init__(self,bits) -> None:
        self.p = None #prime number
        self.q = None #prime number
        self.n = None #modulus
        self.phi = None #Euler's totient
        self.e = None #
        self.d = None # Decrypt Key
        
        self.bits = bits
        self.estimated = (2**bits)/1.154e+7

    def encrypt(self,message:str)->tuple:
        array = []
        for char in message:
            encryptedText = pow(ord(char),self.e,self.n)
            array.append(encryptedText)
        return tuple(array)
    
    def decrypt(self,array)->str:
        decryptedText = ''
        for integer in array:
            decrypted = pow(integer,self.d,self.n)
            decryptedText += chr(decrypted)
        return decryptedText
    
    def bruteForce(self,e:int,n:int):
        self.e = e
        self.n = n
        self.p = self._factor()
        self.q = n//self.p
        self.phi = (self.p - 1) * (self.q - 1)
        self.d = self._modinv(self.e, self.phi)

    def _egcd(self,e:int, n:int)->tuple:
        '''
        Extended Euler's algorithm
        '''
        if e == 0:
            return (n, 0, 1)
        
        g, y, x = self._egcd(n % e, e)
        return (g, x - (n // e) * y, y)
        
    def _modinv(self, a, m):
        g, x, y = self._egcd(a, m)
        if g != 1:
            raise Exception('modular inverse does not exist')
        return x % m        

    def _factor(self):
        for i in range(3,self.n):
            if self.n%i == 0:
                return i

bob = Rsa(1024)
msg = b'Hello, World!i2jkl;djsafipfo[dasjflk;]'
h = int.from_bytes(hashlib.sha256(msg).digest(),byteorder='big')
intMsg = int.from_bytes(msg)

print('Message byte length:',len(msg))
print('Decimal:',intMsg)
print('Hex:',msg.hex())

encrypted = pow(intMsg,bob.e,bob.n)
print('encrypted:',encrypted,'\n')
sig = pow(encrypted,bob.d,bob.n)
print('signature',sig,'\n')

i = pow(encrypted,bob.d,bob.n)
print('decrypted:',i.to_bytes(max(1, math.ceil(i.bit_length() / 8)),'big'))

print(pow(sig,bob.e,bob.n))
