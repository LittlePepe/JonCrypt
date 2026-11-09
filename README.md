# JonCrypt

**Cofre local de credenciais desenvolvido em Python, com criptografia
AES-256-GCM e derivação de chaves usando Argon2id.**

O JonCrypt é um projeto de estudo com o objetivo de compreender e
aplicar conceitos de criptografia, gerenciamento de chaves,
armazenamento seguro de dados e programação orientada a objetos.

A proposta é desenvolver um cofre de senhas local, no qual as
credenciais são criptografadas antes de serem armazenadas no banco de
dados SQLite.

> **Status:** Projeto educacional em desenvolvimento. Não recomendado
> para armazenar senhas reais ou informações sensíveis em ambientes de
> produção.

------------------------------------------------------------------------

## Objetivos do projeto

-   Implementar uma hierarquia de chaves criptográficas.
-   Utilizar uma Master Password para proteger o acesso ao cofre.
-   Aplicar Argon2id para derivação de chaves.
-   Utilizar AES-256-GCM para criptografia e descriptografia.
-   Armazenar credenciais criptografadas localmente.
-   Aplicar conceitos de Programação Orientada a Objetos (POO).
-   Separar responsabilidades entre criptografia, lógica de negócio e
    persistência de dados.

## Arquitetura criptográfica

O JonCrypt utiliza uma hierarquia de chaves para evitar que a Master
Password seja utilizada diretamente na criptografia das credenciais.

### Hierarquia de chaves

``` text
             Master Password
                    |
                    v
                Argon2id
                    |
                    v
              KEK (32 bytes)
                    |
                    v
             AES-256-GCM
                    |
                    v
             DEK criptografada
                    |
                    v
              SQLite Vault
```

**Master Password**

Senha principal utilizada como entrada para o processo de derivação de
chaves. Não é armazenada diretamente no banco de dados.

**KEK (Key Encryption Key)**

Chave derivada da Master Password utilizando Argon2id. Sua função é
criptografar e descriptografar a DEK.

**DEK (Data Encryption Key)**

Chave aleatória de 256 bits utilizada para criptografar e
descriptografar as credenciais armazenadas no cofre.

### Fluxo de inicialização

1.  O usuário fornece sua Master Password.
2.  O Argon2id deriva a KEK utilizando um salt aleatório.
3.  Uma DEK aleatória de 32 bytes é gerada.
4.  A KEK protege a DEK utilizando AES-256-GCM.
5.  Os metadados criptográficos são armazenados no SQLite.

### Fluxo de desbloqueio

1.  O sistema recupera os metadados criptográficos do banco.
2.  A Master Password é utilizada novamente no Argon2id.
3.  A KEK é derivada utilizando o salt armazenado.
4.  A KEK descriptografa a DEK.
5.  A DEK recuperada fica disponível para operações com as credenciais.

### Criptografia das credenciais

Cada credencial utiliza AES-256-GCM com um nonce aleatório de 12 bytes.

O ciphertext e o nonce são armazenados no banco de dados. O nonce não é
secreto, mas é necessário para realizar a descriptografia.

------------------------------------------------------------------------

## Tecnologias utilizadas

- Python      |  Linguagem principal
- SQLite      |  Armazenamento local
- Argon2id    |  Derivação de chaves
- AES-256-GCM |  Criptografia autenticada
- Cryptography|  Implementação dos algoritmos criptográficos
- Dataclasses |  Organização de estruturas de dados
- POO         |  Organização da arquitetura


------------------------------------------------------------------------

## Instalação

### 1. Clonar o repositório

``` bash
git clone <URL_DO_REPOSITORIO>
cd JonCrypt
```

### 2. Criar ambiente virtual

Windows:

``` powershell
python -m venv .venv
```

Ativar:

``` powershell
.venv\Scripts\activate
```

Linux / WSL:

``` bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Instalar dependências

``` bash
pip install cryptography argon2-cffi
```

### 4. Executar

``` bash
python main.py
```

O SQLite é disponibilizado pela biblioteca padrão do Python, não sendo
necessária uma instalação adicional.

------------------------------------------------------------------------

## Conceitos estudados

Durante o desenvolvimento do JonCrypt, são explorados conceitos
importantes de desenvolvimento e segurança:

-   Derivação de chaves criptográficas (KDF).
-   Argon2id e resistência a ataques de força bruta.
-   Criptografia simétrica autenticada.
-   AES-GCM e gerenciamento de nonces.
-   Hierarquia e separação de chaves (KEK e DEK).
-   Salt e parâmetros de derivação.
-   Persistência segura de dados.
-   Programação Orientada a Objetos.
-   Separação de responsabilidades.
-   Injeção de dependências.
-   Padrão Repository.
-   Organização modular de aplicações Python.

------------------------------------------------------------------------

**JonCrypt --- Um projeto de estudo sobre criptografia aplicada,
gerenciamento de chaves e desenvolvimento seguro com Python.**
