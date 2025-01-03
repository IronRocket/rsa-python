# What is it?
This is a simple implimentation of [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) algorithm in python.
It also exposes a few rsa vulnerabilities.
# Math
### Generate Public and Private key
* Choose two large prime numbers p and q.  
    * p shouldn't equal q
    * p and q should be a secret

* n = p*q
    * n is the [modulus](https://en.wikipedia.org/wiki/Modulus) for both public key and private key

* using [Euler's totient](https://en.wikipedia.org/wiki/Euler%27s_totient_function) function phi = (p-1)(q-1)

* choose an interger e such that 2 < e < [λ](https://en.wikipedia.org/wiki/Carmichael_function)(n) and [gcd](https://en.wikipedia.org/wiki/Greatest_common_divisor)(e, λ(n)) = 1; that is, e and λ(n) are coprime
    * Generally e is 65537
* Compute d =  e (mod λ(n)) using [Eucelidean extended algorithm](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm) d can be computed efficiently
    * d should be a secret

Public key = (e,n)  
Private key = (d,n)

let m be the message  
### Encryption

ciphertext = $m^e*mod(n)$

### Decryption

decrypted = $c^d*mod(n)$


# Code
Given the performance of this implementation,  bit length shouldn't exceed 1024
```python
from pureRsa import Rsa

bits = 1024
bob = Rsa(bits)
alice = Rsa(bits)

#Bob encrypted message with alice's public key
cipherText = bob.encrypt('Euler is in your closet',alice.getPublicKey())

#Alice decrypts with her private key
decrypted = alice.decrypt(cipherText)

print(decrypted)

```

## Vulnerabilities
In order for the brute force to work in a reasonable amount of time, 
bit length shouldn't exceed 30
```python
from pureRsa import Rsa,Exploits
import time

bits = 27
bob = Rsa(bits)
alice = Rsa(bits)

cipherText = bob.encrypt('Hello, World!',alice.getPublicKey())

e,n = alice.getPublicKey()

x = Exploits(bits)
print('brute forcing...')
s = time.perf_counter()
x.bruteForce(e,n)
e = time.perf_counter()
print('Successfully found private key')


print(f'Brute Forced decryption = {x.decrypt(cipherText)} Elasped Time: {e-s} seconds')

```