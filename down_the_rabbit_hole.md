# Down the rabbit hole — Write‑up (débutant, très détaillé)

> **Énoncé** : *Find the key that opens Wonderland; you’ll face some challenges along the way!*

**Binaire analysé** : `down_the_rabbit_hole.elf`  
**SHA‑256** : `b09c743fc255b73192ec7f857ce3014f9c99191a25f85602a0473c5bc961d282`  
**Date** : 2025-10-13 18:25 UTC

---

## ✅ Résultat (TL;DR)

- **Key à saisir (32 caractères)** :  
  `SPDBIQPJVKIUOKFZZFFUITJCYYEXFANT`

- **Flag renvoyé par le programme** :  
  `ECW{Y0u_r_n0th1ng_buT_4_p4cK_0f_c4rd5!}`

---

## 1) Vue d’ensemble

Le binaire ELF 64‑bit lit une *key*, applique des protections anti‑analyse (anti‑debug + anti “pas à pas”), 
puis vérifie ta *key*. Si elle est correcte, il initialise un contexte **ChaCha20** et déchiffre un message
de 0x27 octets (39 octets) qui contient le **flag**.

Pour “naviguer” dans le programme, il utilise une **table de dispatch** (7 entrées) :
chaque entrée contient un **hash** et un **pointeur de fonction** ; le programme appelle la fonction dont
le hash correspond à l’étape en cours.

Les 7 chaînes associées aux étapes sont :
```
DownTheRabbitHole, WhiteRabbit, MadHatter, CheshireCat,
QueenOfHearts, Alice, Wonderland
```

---

## 2) Anti‑analyse

### a) Anti‑debug (WhiteRabbit)
- Appel d’un `syscall` n° **0x65** (sur x86‑64 Linux : **ptrace**).
- Si le retour est **-1** (on est tracé par gdb/strace), le programme part en erreur (`wrong`).
- Solution : exécuter **sans** debugger (ou patcher, mais inutile ici).

### b) Anti “pas à pas” (MadHatter)
- `rdtsc()` au début puis `rdtscp()` plus tard ; si trop de cycles se sont écoulés (≥ 10^10), erreur.
- Solution : exécution “temps réel” (ne pas “stepper” lentement).

---

## 3) Table de dispatch (les « portes »)

La fonction de remplissage calcule un **hash 32‑bit** pour chacune des 7 chaînes à l’aide d’un **CRC32** avec
table (256 entrées) puis **XOR** final `^ 0xDEADBEEF`. Chaque *hash* est stocké avec le pointeur de fonction cible.
Le programme “saute” d’une étape à l’autre en comparant contre ces valeurs.

---

## 4) Construction de la key attendue (CheshireCat)

La *key* attendue est **générée dynamiquement** (elle n’est pas stockée en clair). Principe :

1. Pour chaque chaîne `S` parmi les 7 ci‑dessus, on calcule `U = CRC(S)` avec la même fonction que plus haut.
2. On parcourt les caractères de `S` et, pour l’indice `k` (0‑based), on calcule :
   - `mask = (U >> ((k & 3) * 8)) & 0xFF` (octet tournant parmi les 4 octets de `U`)
   - `x = ord(S[k]) ^ mask`
   - on émet `chr((x % 26) + 0x41)` → une lettre **A..Z**
3. On itère sur les 7 chaînes **en boucle** jusqu’à obtenir **32 caractères**.

En appliquant l’algorithme, on obtient précisément :
```
SPDBIQPJVKIUOKFZZFFUITJCYYEXFANT
```

Le programme compare ensuite **ton entrée** (paddée à 32 avec `#` si plus courte) avec cette chaîne.
Si ça ne correspond pas → erreur.

---

## 5) ChaCha20 : clé et nonce (QueenOfHearts)

- **Clé ChaCha20 (32 octets)** = la *key* ci‑dessus (en ASCII, 32 lettres A‑Z).
- **Nonce (12 octets)** = dérivé d’une chaîne hex en `.rodata` (par ex. `"ac1587535d...`) :
  - on prend les **24 premiers hex digits** → **12 octets** ;
  - on calcule le **CRC** (même fonction) de la **section `.text`** du binaire (oui, il lit `/proc/self/exe`) ;
  - on **XOR** chaque octet du nonce avec **l’octet de poids faible** du CRC.

Le **keystream** ChaCha20 est alors prêt (constantes `"expand 32-byte k"`, compteurs conformes, 20 rounds).
La fonction de chiffrement **XOR** le buffer de 0x27 octets avec ce keystream → message en clair.

**Conséquence importante** : si tu patches le binaire, le **CRC(.text)** change, donc le **nonce** change… 
et le déchiffrement ne donnera plus le bon résultat.

---

## 6) Déchiffrement & validation (Alice → Wonderland)

- Le programme copie 0x27 octets chiffrés depuis `.rodata`, applique le XOR ChaCha20, puis affiche le résultat.
- Il vérifie que les 4 premiers octets correspondent à une constante (ici, le **préfixe du flag**).
- Si c’est OK, il affiche un message **GG** et termine proprement.

Flag obtenu :
```
ECW{Y0u_r_n0th1ng_buT_4_p4cK_0f_c4rd5!}
```

---

## 7) Le “leurre” 0xABCD (facultatif)

Une autre fonction désobfusque un gros blob 16‑bit via `^ 0xABCD` et affiche un message “anti‑LLM/anti‑IA”.
Ce n’est **pas** nécessaire pour la résolution ; tu peux l’ignorer.

---

## 8) Reproduire l’extraction automatiquement (script)

Tu peux utiliser le script ci‑dessous (il reconstruit la *key*, dérive le nonce depuis `.text`, puis déchiffre) :
```bash
python3 solve_down_the_rabbit_hole.py /chemin/vers/down_the_rabbit_hole.elf
```

### Contenu de `solve_down_the_rabbit_hole.py`
```python
#!/usr/bin/env python3
import struct, sys, hashlib

PATH = sys.argv[1] if len(sys.argv) > 1 else "down_the_rabbit_hole.elf"

def unpack(fmt, b, off): return struct.unpack_from(fmt, b, off)

def elf64_headers(b):
    e_ident = b[:16]
    assert e_ident[:4] == b"\x7fELF" and e_ident[4] == 2 and e_ident[5] == 1
    (e_type,e_machine,e_version,e_entry,e_phoff,e_shoff,e_flags,
     e_ehsize,e_phentsize,e_phnum,e_shentsize,e_shnum,e_shstrndx) = unpack("<HHIQQQIHHHHHH", b, 16)
    phdrs = [unpack("<IIQQQQQQ", b, e_phoff+i*e_phentsize) for i in range(e_phnum)]
    shdrs = [unpack("<IIQQQQIIQQ", b, e_shoff+i*e_shentsize) for i in range(e_shnum)]
    return (e_entry, phdrs, shdrs, e_shstrndx)

def va_to_off(va, phdrs):
    for (p_type,p_flags,p_offset,p_vaddr,p_paddr,p_filesz,p_memsz,p_align) in phdrs:
        if p_type == 1 and p_vaddr <= va < p_vaddr + p_memsz:
            off = p_offset + (va - p_vaddr)
            if p_offset <= off < p_offset + p_filesz:
                return off
    return None

def read_cstr_va(va, data, phdrs):
    off = va_to_off(va, phdrs); end = data.find(b"\x00", off)
    return data[off:end].decode("latin-1")

def rotl32(x,n): return ((x << n) & 0xffffffff) | (x >> (32-n))

def chacha_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    st = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        *struct.unpack("<8I", key),
        counter, *struct.unpack("<3I", nonce)
    ]
    w = st.copy()
    for _ in range(10):
        for a,b,c,d in [(0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15)]:
            w[a]=(w[a]+w[b])&0xffffffff; w[d]^=w[a]; w[d]=rotl32(w[d],16)
            w[c]=(w[c]+w[d])&0xffffffff; w[b]^=w[c]; w[b]=rotl32(w[b],12)
            w[a]=(w[a]+w[b])&0xffffffff; w[d]^=w[a]; w[d]=rotl32(w[d],8)
            w[c]=(w[c]+w[d])&0xffffffff; w[b]^=w[c]; w[b]=rotl32(w[b],7)
        for a,b,c,d in [(0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)]:
            w[a]=(w[a]+w[b])&0xffffffff; w[d]^=w[a]; w[d]=rotl32(w[d],16)
            w[c]=(w[c]+w[d])&0xffffffff; w[b]^=w[c]; w[b]=rotl32(w[b],12)
            w[a]=(w[a]+w[b])&0xffffffff; w[d]^=w[a]; w[d]=rotl32(w[d],8)
            w[c]=(w[c]+w[d])&0xffffffff; w[b]^=w[c]; w[b]=rotl32(w[b],7)
    out = [(w[i]+st[i]) & 0xffffffff for i in range(16)]
    return struct.pack("<16I", *out)

def chacha_xor(key: bytes, nonce: bytes, buf: bytes, counter: int=0) -> bytes:
    out = bytearray()
    i = 0
    while i < len(buf):
        ks = chacha_block(key, counter, nonce); counter = (counter + 1) & 0xffffffff
        chunk = buf[i:i+64]
        out.extend( bytes([a ^ b for a,b in zip(chunk, ks[:len(chunk)])]) )
        i += 64
    return bytes(out)

# constants (from analysis)
VA_PAIRS      = 0x404DA0
VA_CRC_TABLE  = 0x403180
VA_NONCE_HEX  = 0x4035E0
VA_CIPHERTEXT = 0x4036AA

data = open(PATH, "rb").read()
e_entry, phdrs, shdrs, shstrndx = elf64_headers(data)

pairs_off = va_to_off(VA_PAIRS, phdrs)
pairs = []
for i in range(7):
    sp = struct.unpack_from("<Q", data, pairs_off + i*16)[0]
    fp = struct.unpack_from("<Q", data, pairs_off + i*16 + 8)[0]
    pairs.append((sp, fp))

def read_cstr_va(va):
    off = va_to_off(va, phdrs); end = data.find(b"\x00", off)
    return data[off:end].decode("latin-1")

strings = [read_cstr_va(sp) for sp,_ in pairs]

crc_tbl_off = va_to_off(VA_CRC_TABLE, phdrs)
crc_table = list(struct.unpack_from("<256I", data, crc_tbl_off))

def crc32_deadbeef(buf: bytes) -> int:
    c = 0xffffffff
    for b in buf:
        c = crc_table[(b ^ (c & 0xff))] ^ (c >> 8)
    return c ^ 0xdeadbeef

def build_key(strings):
    crcs = [crc32_deadbeef(s.encode()) for s in strings]
    out = bytearray()
    i = j = 0
    while i < 32:
        s = strings[j].encode()
        u = crcs[j]
        for k in range(len(s)):
            if i >= 32: break
            mask = (u >> ((k & 3) * 8)) & 0xff
            out.append(((s[k] ^ mask) % 26) + 0x41)
            i += 1
        j = (j + 1) % 7
    return out.decode()

key = build_key(strings)

# .text bytes
shstr = shdrs[shstrndx]; shstr_off = shstr[4]; shstr_sz = shstr[5]
shstr_tab = data[shstr_off:shstr_off+shstr_sz]
def sname(off): return shstr_tab[off:shstr_tab.find(b"\x00", off)].decode()
text = next(sh for sh in shdrs if sname(sh[0]) == ".text")
text_bytes = data[text[4]:text[4]+text[5]]
crc_text = crc32_deadbeef(text_bytes)
lsb = crc_text & 0xff

nonce_hex_full = read_cstr_va(VA_NONCE_HEX)
nonce_hex = "".join([c for c in nonce_hex_full if c in "0123456789abcdefABCDEF"])[:24]
nonce = bytes.fromhex(nonce_hex)
nonce = bytes([b ^ lsb for b in nonce])

ct = data[va_to_off(VA_CIPHERTEXT, phdrs):va_to_off(VA_CIPHERTEXT, phdrs)+0x27]
pt = chacha_xor(key.encode(), nonce, ct, 0)

print("SHA256:", hashlib.sha256(data).hexdigest())
print("KEY   :", key)
try:
    print("FLAG  :", pt.decode())
except UnicodeDecodeError:
    print("FLAG  :", pt.decode("latin-1"))

```

---

## 9) Annexes pratiques

### Vérifications rapides
```bash
file down_the_rabbit_hole.elf
sha256sum down_the_rabbit_hole.elf
strings -tx -a down_the_rabbit_hole.elf | head -n 30
```

### Conseils “anti‑anti‑debug” (optionnels)
- Exécuter sans débogueur, ou lancer `gdb` **après** `ptrace` (plus avancé).
- Éviter le “single‑step” ; préférer l’exécution continue jusqu’aux points d’arrêt.

---

## 10) Conclusion

Le challenge démontre :
- des **protections légères** (ptrace, TSC) ;
- un **dispatcher** à base de *hash* (CRC modifié) ;
- une **key** calculée à partir de 7 chaînes thématiques ;
- un **déchiffrement ChaCha20** avec nonce couplé au **CRC(.text)**.

**Key** : `SPDBIQPJVKIUOKFZZFFUITJCYYEXFANT`  
**Flag** : `ECW{Y0u_r_n0th1ng_buT_4_p4cK_0f_c4rd5!}`

Bon CTF ! 🐇🕳️
