# Especificação do formato `.svault`

**Versão do formato:** 1.0
**Status:** rascunho (em implementação)
**Projeto:** JonCrypt

---

## 1. Visão geral

O `.svault` é o formato de arquivo do cofre do JonCrypt. Um arquivo `.svault` contém, em um único bloco binário, tudo o que é necessário para abrir o cofre — exceto a senha mestre.

O formato foi projetado com cinco objetivos:

1. **Autossuficiente** — salt, parâmetros de derivação e a chave de dados cifrada ficam no próprio arquivo. Copiar o arquivo é copiar o cofre inteiro.
2. **Opaco** — nenhuma informação sobre as credenciais (sites, usuários, senhas, quantidade) é visível sem a senha mestre.
3. **À prova de adulteração** — qualquer alteração em qualquer byte do arquivo é detectada.
4. **Evolutivo** — o formato é versionado e pode mudar sem quebrar cofres antigos.
5. **Robusto** — falhas durante a gravação não corrompem o cofre existente.

---

## 2. Convenções

- Todos os inteiros de múltiplos bytes são **big-endian**, sem sinal.
- Não há padding nem alinhamento entre campos.
- Tamanhos são expressos em bytes, salvo indicação contrária.
- `‖` indica concatenação de sequências de bytes.
- `S` indica o tamanho do salt (`salt_len`). Na configuração padrão, `S = 16`.
- Os termos **DEVE**, **NÃO DEVE** e **PODE** indicam, respectivamente, requisito obrigatório, proibição e comportamento opcional.

---

## 3. Estrutura geral do arquivo

```
┌──────────────────────────────┐
│ HEADER                       │  texto claro, autenticado
│ (header_len bytes)           │
├──────────────────────────────┤
│ PAYLOAD CIFRADO              │  credenciais em JSON, cifradas
│ (payload_len − 16 bytes)     │
├──────────────────────────────┤
│ TAG GCM (16 bytes)           │  lacre de integridade
└──────────────────────────────┘
```

O payload cifrado e a tag GCM são produzidos juntos pelo AES-GCM e tratados como um único bloco de `payload_len` bytes.

O tamanho total do arquivo DEVE ser exatamente `header_len + payload_len`.

---

## 4. Header

### 4.1 Layout (v1.0, com `S = 16`)

| Offset | Campo            | Tamanho | Tipo    | Valor padrão          |
|-------:|------------------|--------:|---------|-----------------------|
|      0 | `magic`          |       4 | bytes   | `53 56 4C 54` (`SVLT`)|
|      4 | `format_major`   |       2 | uint16  | `1`                   |
|      6 | `format_minor`   |       2 | uint16  | `0`                   |
|      8 | `flags`          |       2 | uint16  | `0`                   |
|     10 | `header_len`     |       4 | uint32  | `123`                 |
|     14 | `kdf_id`         |       1 | uint8   | `1` (Argon2id)        |
|     15 | `time_cost`      |       4 | uint32  | `3`                   |
|     19 | `memory_cost`    |       4 | uint32  | `65536` (KiB)         |
|     23 | `parallelism`    |       1 | uint8   | `4`                   |
|     24 | `hash_len`       |       1 | uint8   | `32`                  |
|     25 | `salt_len`       |       1 | uint8   | `16`                  |
|     26 | `salt`           |       S | bytes   | aleatório             |
|     42 | `cipher_id`      |       1 | uint8   | `1` (AES-256-GCM)     |
|     43 | `dek_nonce`      |      12 | bytes   | aleatório             |
|     55 | `wrapped_dek`    |      48 | bytes   | DEK cifrada + tag     |
|    103 | `payload_nonce`  |      12 | bytes   | aleatório             |
|    115 | `payload_len`    |       8 | uint64  | variável              |
|    123 | *(fim do header)*|         |         |                       |

Para um `salt_len` diferente de 16, todos os offsets a partir de `cipher_id` são deslocados em `S − 16`.

### 4.2 Representação com `struct` (Python)

O header é dividido em três partes, porque o salt tem tamanho variável:

| Parte   | Formato `struct`   | Tamanho | Campos                              |
|---------|--------------------|--------:|-------------------------------------|
| Prefixo | `>4sHHHIBIIBBB`    |      26 | `magic` até `salt_len`              |
| Salt    | —                  |       S | `salt`                              |
| Sufixo  | `>B12s48s12sQ`     |      81 | `cipher_id` até `payload_len`       |

Fórmula do tamanho do header:

```
header_len = 26 + S + 81
```

### 4.3 Descrição dos campos

**`magic`** — Assinatura fixa `SVLT`. Identifica o arquivo como um cofre JonCrypt. Ocupa sempre os bytes 0–3 em todas as versões do formato.

**`format_major` / `format_minor`** — Versão do formato binário. Ocupam sempre os bytes 4–7 em todas as versões. Ver seção 10.

**`flags`** — Reservado para recursos futuros. Nenhuma flag é definida na v1.0. Escritores v1.0 DEVEM gravar `0`. Leitores v1.0 DEVEM ignorar bits desconhecidos.

**`header_len`** — Tamanho total do header em bytes. DEVE ser igual a `26 + salt_len + 81`.

**`kdf_id`** — Algoritmo de derivação da KEK. Ver seção 5.

**`time_cost`, `memory_cost`, `parallelism`, `hash_len`** — Parâmetros do Argon2id. `memory_cost` é expresso em KiB. São a fonte da verdade para a derivação: o leitor DEVE usar estes valores, e não valores fixos no código.

**`salt_len` / `salt`** — Salt aleatório usado na derivação da KEK. Gerado com um CSPRNG (`secrets.token_bytes`).

**`cipher_id`** — Algoritmo de cifragem da DEK e do payload. Ver seção 5.

**`dek_nonce`** — Nonce de 12 bytes usado para cifrar a DEK com a KEK.

**`wrapped_dek`** — DEK (32 bytes) cifrada com AES-256-GCM, seguida da tag de 16 bytes. Total: 48 bytes.

**`payload_nonce`** — Nonce de 12 bytes usado para cifrar o payload com a DEK. DEVE ser regenerado a cada gravação.

**`payload_len`** — Tamanho do payload cifrado, incluindo a tag GCM. Igual a `len(json_utf8) + 16`.

---

## 5. Identificadores registrados

### 5.1 `kdf_id`

| Valor | Algoritmo | Status     |
|------:|-----------|------------|
|     0 | —         | inválido   |
|     1 | Argon2id  | v1.0       |

### 5.2 `cipher_id`

| Valor | Algoritmo   | Status   |
|------:|-------------|----------|
|     0 | —           | inválido |
|     1 | AES-256-GCM | v1.0     |

Um identificador NÃO DEVE ser reutilizado com outro significado. Novos algoritmos recebem novos valores.

---

## 6. Limites de validação

Leitores e escritores DEVEM rejeitar headers com valores fora destes limites.

| Campo         | Mínimo         | Máximo            | Motivo                                       |
|---------------|---------------:|------------------:|----------------------------------------------|
| `time_cost`   | 1              | 10                | Unlock em tempo aceitável                    |
| `memory_cost` | 8192 (8 MiB)   | 1048576 (1 GiB)   | Evita KDF fraco e consumo abusivo de memória |
| `parallelism` | 1              | 16                | Valor realista para CPUs comuns              |
| `hash_len`    | 32             | 32                | A KEK é uma chave AES-256                    |
| `salt_len`    | 16             | 64                | Salt com entropia suficiente                 |

Os limites DEVEM ser verificados **antes** de executar o Argon2id. Um arquivo malicioso poderia declarar parâmetros extremos para travar a máquina.

---

## 7. Hierarquia de chaves

```
senha mestre ──Argon2id(salt, parâmetros)──▶ KEK (32 bytes)
                                              │
                                              │ AES-256-GCM (dek_nonce, AAD = kdf_section)
                                              ▼
                                       wrapped_dek  ◀──▶  DEK (32 bytes, aleatória)
                                                            │
                                                            │ AES-256-GCM (payload_nonce, AAD = header)
                                                            ▼
                                                     payload cifrado
```

- **KEK** (Key Encryption Key) — derivada da senha mestre. Nunca é gravada.
- **DEK** (Data Encryption Key) — 32 bytes aleatórios gerados na criação do cofre. Gravada apenas na forma cifrada (`wrapped_dek`).
- A senha mestre nunca é gravada, nem de forma derivada.

Essa separação permite trocar a senha mestre sem alterar a DEK e salvar o cofre sem precisar da senha.

---

## 8. Dados autenticados (AAD)

### 8.1 AAD do wrap da DEK: `kdf_section`

```
kdf_section = header[0 : 26 + S]
```

Corresponde aos bytes de `magic` até o fim do `salt` (offsets 0–41 com `S = 16`).

Inclui: magic, versão, flags, `header_len`, `kdf_id`, parâmetros do Argon2id, `salt_len` e `salt`.

**Propriedade importante:** a `kdf_section` não depende de `cipher_id`, `dek_nonce`, `wrapped_dek`, `payload_nonce` nem `payload_len`. Isso permite calculá-la antes de cifrar a DEK, durante a criação do cofre.

**Proteção:** impede o rebaixamento dos parâmetros do KDF. Se um atacante reduzir `time_cost` ou `memory_cost` no arquivo, a DEK deixa de abrir.

### 8.2 AAD do payload: header completo

```
payload_aad = header[0 : header_len]
```

**Proteção:** qualquer alteração em qualquer byte do header — inclusive `payload_nonce` e `payload_len` — invalida a decifragem do payload.

---

## 9. Payload

### 9.1 Conteúdo em texto claro

O payload, antes da cifragem, é um documento JSON codificado em UTF-8.

**Schema v1:**

| Campo            | Tipo              | Descrição                                      |
|------------------|-------------------|------------------------------------------------|
| `schema_version` | inteiro           | Versão do schema dos dados. Valor: `1`.        |
| `next_id`        | inteiro           | Próximo ID a ser atribuído a uma credencial.   |
| `entries`        | lista de objetos  | Credenciais armazenadas.                       |

**Cada item de `entries`:**

| Campo        | Tipo             | Descrição                                   |
|--------------|------------------|---------------------------------------------|
| `id`         | inteiro          | Identificador único. Nunca reutilizado.     |
| `link`       | string           | Site ou serviço.                            |
| `password`   | string           | Senha da credencial.                        |
| `created_at` | inteiro          | Timestamp Unix (segundos, UTC).             |
| `updated_at` | inteiro ou `null`| Timestamp Unix da última alteração.         |

**Exemplo:**

```json
{
  "schema_version": 1,
  "next_id": 2,
  "entries": [
    {
      "id": 1,
      "link": "https://www.exemplo.com",
      "password": "SenhaSite123!",
      "created_at": 1762731000,
      "updated_at": null
    }
  ]
}
```

O texto acima nunca é gravado em disco.

### 9.2 Cifragem

```
payload_cifrado ‖ tag = AES-256-GCM(
    chave = DEK,
    nonce = payload_nonce,
    dados = json_utf8,
    aad   = header completo
)
```

O `payload_nonce` DEVE ser novo a cada gravação. Reutilizar um nonce com a mesma DEK compromete a segurança do AES-GCM.

---

## 10. Versionamento

O formato possui duas versões independentes.

### 10.1 Versão do formato (`format_major.format_minor`)

Descreve a estrutura binária do arquivo.

| Situação ao abrir                         | Comportamento                                      |
|-------------------------------------------|----------------------------------------------------|
| `format_major == 0`                       | Rejeitar (`VaultFormatError`)                      |
| `format_major` igual ao suportado         | Abrir; ignorar `format_minor` maior e flags desconhecidas |
| `format_major` menor e conhecido          | Abrir, migrar e gravar na versão atual             |
| `format_major` maior que o suportado      | Rejeitar (`UnsupportedVersionError`)               |

- **`major`** muda quando a alteração é incompatível (ordem de campos, algoritmo padrão, estrutura).
- **`minor`** muda quando a alteração é compatível (ex.: nova flag que leitores antigos podem ignorar).

Os campos `magic`, `format_major` e `format_minor` ocupam os bytes 0–7 em **todas** as versões futuras.

### 10.2 Versão do schema (`schema_version`)

Descreve a estrutura das credenciais dentro do payload. Evolui independentemente da versão do formato.

### 10.3 Migrações

- Cada migração converte a versão N para N+1.
- As migrações são aplicadas em sequência até a versão atual.
- Um backup (`.svault.bak`) DEVE ser criado antes da primeira gravação de um cofre migrado.

---

## 11. Operações

### 11.1 Criação

1. Gerar `salt` aleatório.
2. Derivar a KEK com Argon2id usando o salt e os parâmetros padrão.
3. Gerar a DEK aleatória (32 bytes).
4. Montar um header provisório com `dek_nonce`, `wrapped_dek` e `payload_nonce` preenchidos com zeros.
5. Calcular a `kdf_section` do header provisório.
6. Gerar `dek_nonce` e cifrar a DEK com a KEK usando a `kdf_section` como AAD.
7. Montar o header definitivo com `dek_nonce` e `wrapped_dek` reais.
8. Gravar o arquivo com um payload vazio (seção 11.3).

### 11.2 Abertura

1. Ler o arquivo e validar o header (seção 12).
2. Verificar se o tamanho do arquivo é igual a `header_len + payload_len`.
3. Derivar a KEK com o salt e os parâmetros **do header**.
4. Decifrar `wrapped_dek` com a KEK e a `kdf_section` como AAD.
   - Falha → `InvalidPasswordError`.
5. Decifrar o payload com a DEK e o header completo como AAD.
   - Falha → `IntegrityError`.
6. Decodificar o JSON e validar `schema_version`.

### 11.3 Gravação

1. Serializar o payload em JSON (UTF-8).
2. Gerar um novo `payload_nonce`.
3. Calcular `payload_len = len(json_utf8) + 16`.
4. Gerar um novo header com o novo `payload_nonce` e o novo `payload_len`.
5. Cifrar o payload com a DEK e o header completo como AAD.
6. Gravar `header ‖ payload cifrado` de forma atômica (seção 13).

A gravação não exige a senha mestre nem a KEK: `dek_nonce` e `wrapped_dek` são reaproveitados.

### 11.4 Troca da senha mestre

1. Gerar um novo `salt`.
2. Derivar uma nova KEK com a nova senha.
3. Gerar um novo `dek_nonce` e recifrar a **mesma** DEK com a nova KEK e a nova `kdf_section`.
4. Gravar o cofre (seção 11.3). O payload é recifrado com novo nonce porque o header mudou.

---

## 12. Validação e erros

### 12.1 Ordem de validação do header

1. Tamanho mínimo de 26 bytes.
2. `magic == "SVLT"`.
3. `format_major` válido e suportado.
4. `kdf_id` conhecido e `salt_len` dentro dos limites.
5. `header_len == 26 + salt_len + 81`.
6. Dados disponíveis ≥ `header_len`.
7. `cipher_id` conhecido.
8. Parâmetros do KDF dentro dos limites.

Cada etapa só acessa bytes cuja existência foi garantida pelas etapas anteriores.

### 12.2 Exceções

| Exceção                   | Situação                                           | Mensagem sugerida ao usuário                         |
|---------------------------|----------------------------------------------------|------------------------------------------------------|
| `VaultFormatError`        | Arquivo malformado, truncado ou fora dos limites   | "Arquivo corrompido ou não é um cofre JonCrypt."     |
| `UnsupportedVersionError` | `format_major` maior que o suportado               | "Atualize o JonCrypt para abrir este cofre."         |
| `InvalidPasswordError`    | Falha ao decifrar `wrapped_dek`                    | "Senha incorreta."                                   |
| `IntegrityError`          | Falha ao decifrar o payload                        | "Os dados do cofre foram corrompidos ou adulterados."|

Todas herdam de `VaultError`.

Se a DEK foi decifrada com sucesso, a senha está correta. Uma falha posterior no payload indica, necessariamente, corrupção ou adulteração.

---

## 13. Gravação atômica e arquivos auxiliares

| Arquivo                 | Função                                          |
|-------------------------|-------------------------------------------------|
| `joncrypt.svault`       | Cofre atual                                     |
| `joncrypt.svault.bak`   | Versão anterior, criada a cada gravação         |
| `joncrypt.svault.tmp`   | Arquivo temporário, existe apenas durante a gravação |

Procedimento:

1. Gravar o conteúdo completo em `.svault.tmp`.
2. Executar `flush()` e `os.fsync()`.
3. Copiar o `.svault` atual para `.svault.bak`, se existir.
4. Substituir o `.svault` pelo `.tmp` com `os.replace()` (operação atômica).

Se a gravação for interrompida, o `.svault` original permanece intacto.

Nenhum desses arquivos DEVE ser versionado no Git.

---

## 14. Considerações de segurança

O formato protege os dados **em repouso** (disco, backups, mídias removíveis). Ele **não** protege contra:

- **Senha mestre fraca** — o Argon2id encarece cada tentativa, mas não impede ataques a senhas óbvias.
- **Malware com o cofre aberto** — enquanto o cofre está aberto, a DEK e as credenciais estão na memória.
- **Resíduos na memória** — o Python não oferece apagamento confiável de strings.
- **Perda da senha mestre** — não existe mecanismo de recuperação, por design.

**Informações visíveis sem a senha:** que o arquivo é um cofre JonCrypt, a versão do formato, os parâmetros do Argon2id e o tamanho aproximado do conteúdo.

**Informações protegidas:** links, senhas, IDs, datas e quantidade de credenciais.

---

## 15. Referências

- [`cryptography` — AEAD (AESGCM)](https://cryptography.io/en/latest/hazmat/primitives/aead/)
- [`argon2-cffi` — API](https://argon2-cffi.readthedocs.io/en/stable/api.html)
- [Python — `struct`](https://docs.python.org/3/library/struct.html)
- [KDBX File Format Specification (KeePass)](https://keepass.info/help/kb/kdbx.html)
- [age-encryption.org/v1](https://age-encryption.org/v1)

---

## 16. Histórico do documento

| Versão do documento | Formato | Alterações                     |
|---------------------|---------|--------------------------------|
| 0.1                 | 1.0     | Versão inicial da especificação |