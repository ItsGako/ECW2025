# Write-up : challenge **rsa_rsa_rsa** 😊

**Niveau :** pour un lycéen de 15 ans — tout expliqué simplement 🧑‍🏫

---

## Contexte (en deux phrases)

On a un fichier PNG dans lequel quelqu'un a caché des données RSA. On nous donne un grand nombre `N` dans l'énoncé, mais la vraie astuce est que certaines valeurs premières sont directement dans le PNG. En utilisant ces premiers, on peut déchiffrer le message 😎

---

## Idée générale (version courte)

1. Ouvrir le PNG et regarder **après** le chunk `IEND` — c'est un endroit courant pour cacher des données. 🕵️‍♂️
2. On trouve dans cette zone une série de nombres (des `p_i`) et un grand nombre `C` (le ciphertext).
3. Les `p_i` sont des nombres premiers qui servent à construire un premier modulus (produit des `p_i`). Avec ces `p_i` on peut faire un décryptage multi-prime (méthode CRT). 🔧
4. Le résultat révèle une seconde paire `(C, N)` ; là, le `N` trouvé est **premier**. Si `N` est premier, `phi(N) = N-1`, donc on peut calculer `d = e^{-1} mod (N-1)` et déchiffrer. 🎉

---

## Ce qu'il faut comprendre (petite théorie) 🤓

* **RSA classique** : on a `N = p*q` (produit de deux premiers). `phi(N) = (p-1)(q-1)`. Si tu connais `phi(N)` ou les facteurs, tu peux trouver la clef privée `d` et déchiffrer.
* **Si N est premier** : ce n'est pas un RSA normal, mais mathématiquement `phi(N) = N-1`. Donc si tu trouves `N` et `C`, et que `e` est connu (souvent `65537`), tu peux faire `d = e^{-1} mod (N-1)` et `m = C^d mod N`.
* **Multi-prime RSA / CRT** : si un message a été chiffré modulo `N_multi = p1*p2*...*pk`, tu peux déchiffrer modulo chaque `p_i` puis reconstituer le message modulo `N_multi` avec le *Chinese Remainder Theorem (CRT)*.

---

## Étapes détaillées (pas à pas) 🛠️

### 1) Regarder après `IEND` dans le PNG

* Un PNG contient plusieurs chunks (entêtes). Le chunk final s'appelle `IEND`.
* Beaucoup de CTFs cachent des données après ce chunk : ouvre le fichier en binaire et cherche `IEND`.

### 2) Extraire les nombres

* Après `IEND` j'ai trouvé une suite de grands nombres.
* En général on extrait toutes les suites de chiffres dans cette zone. Les premiers 20 nombres peuvent être les `p_i` puis un grand nombre `C` (ciphertext).

### 3) Déchiffrage par résidus (pour chaque p_i)

Pour chaque prime `p_i` :

* Calculer `d_i = e^{-1} mod (p_i - 1)` (car si on chiffre avec `e` modulo `p_i`, l'inverse s'obtient modulo `p_i-1`).
* Calculer `m_i = C^{d_i} mod p_i`. Ceci donne `m mod p_i`.

### 4) Reconstituer `m mod N_multi` avec CRT

* On a, pour chaque `i`, `m ≡ m_i (mod p_i)`.
* Utilise CRT pour obtenir `m (mod N_multi)` où `N_multi = p1*p2*...*p20`.
* `m` est typiquement un entier qui, une fois converti en bytes, donne un texte. Dans ce challenge, ce texte contenait une autre paire `C2` et `N2`.

### 5) Deuxième décryptage (N2 est premier)

* Comme `N2` est premier, `phi(N2) = N2 - 1`.
* Calcule `d2 = e^{-1} mod (N2 - 1)` et `m_final = C2^{d2} mod N2`.
* Convertis `m_final` en bytes — c'est le flag.

---

## Script Python (exécutable) 🐍

Tu peux copier-coller ce script et le lancer. Il reprend les étapes ci-dessus.

```python
# solve_rsa_rsa_rsa.py
import sys, re

try:
    sys.set_int_max_str_digits(2000000)
except:
    pass

def read_tail_after_iend(png_path):
    data = open(png_path, "rb").read()
    iend = data.find(b'IEND')
    if iend == -1:
        raise ValueError("No IEND found")
    start = iend + 8
    tail = data[start:]
    return tail

def parse_tail(tail):
    s = tail.decode(errors='ignore')
    digits = re.findall(r'\d+', s)
    primes = [int(x) for x in digits[:20]]
    C = int(digits[20])
    return primes, C

# CRT reconstruction
def crt_from_residues(residues):
    x = residues[0][1]
    M = residues[0][0]
    for p, r in residues[1:]:
        invM = pow(M % p, -1, p)
        t = (r - x) * invM % p
        x = x + t * M
        M = M * p
    return x, M


def main(png_path):
    tail = read_tail_after_iend(png_path)
    primes, bigC = parse_tail(tail)

    e = 65537
    residues = []
    for p in primes:
        di = pow(e, -1, p-1)
        ri = pow(bigC % p, di, p)
        residues.append((p, ri))

    m_int, N_multi = crt_from_residues(residues)

    m_bytes = int.to_bytes(m_int, (m_int.bit_length()+7)//8, 'big')
    m_text = m_bytes.decode(errors='ignore')
    print("Intermediate plaintext:\n", m_text)

    nums = re.findall(r'\d+', m_text)
    C2 = int(nums[0])
    N2 = int(nums[1])

    phi2 = N2 - 1
    d2 = pow(e, -1, phi2)
    m2 = pow(C2, d2, N2)
    m2_bytes = int.to_bytes(m2, (m2.bit_length()+7)//8, 'big')
    print("Final message:\n", m2_bytes.decode())

if __name__ == "__main__":
    main("esna_FileEncryption.png")
```

> ⚠️ Remarque : le script suppose que les 20 premiers nombres trouvés sont les `p_i`. Si le format diffère, il faudra ajuster la façon de parser la queue du PNG.

---

## Résultat final (petit mot) 🎯

En appliquant ces étapes on obtient un flag (une chaîne de texte). Le principe à retenir : **quand on te donne un modulo étrange, vérifie toujours l'environnement (fichier, métadonnées, queue) — parfois les facteurs sont cachés**.

Si tu veux, je peux :

* fournir les 20 nombres premiers extraits 👀
* expliquer en détail le CRT (avec des petits dessins) ✍️
* transformer ce markdown en fichier `.md` téléchargeable pour toi 🙂

---

Bon challenge et dis-moi si tu veux que je t'explique une étape en particulier ! 🎉
