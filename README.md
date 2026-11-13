# 🛡️ PassValidator Pro — Validador de Senhas Vazadas & Gerador Multiperfil

> **SDK Universal e Auditor de Senhas em Tempo Real com detecção de vazamentos via *k-Anonymity* contra a base do Have I Been Pwned (850M+ senhas) e Gerador Criptográfico Seguro de 5 Perfis de Proteção.**
>
> 🚀 **Zero Servidor Próprio / Zero Conta Cloudflare Necessária:** Opera 100% no cliente (Navegador), em microsserviços Node.js ou Edge Anycast com privacidade matemática absoluta.

[![Testes](https://img.shields.io/badge/Testes-100%25%20Aprovados-success.svg)](#)
[![Base HIBP](https://img.shields.io/badge/Base-850M%2B%20Senhas%20Vazadas-red.svg)](#)
[![Privacidade](https://img.shields.io/badge/Privacidade-k--Anonymity%20SHA--1-blue.svg)](#)
[![Perfis](https://img.shields.io/badge/Gerador-5%20Perfis%20de%20Proteção-emerald.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

---

## ⚡ Por que Esta Arquitetura é Superior?

1. **Privacidade Matemática (*k-Anonymity*):** A senha do usuário **NUNCA** sai da máquina ou navegador. O hash SHA-1 é calculado localmente; apenas os **5 primeiros caracteres hexadecimais** do hash são enviados à API do Pwned Passwords. O casamento do sufixo ocorre na sua própria memória.
2. **Sem Custos ou Limites de Requisições:** A API do Pwned Passwords possui `Access-Control-Allow-Origin: *`, é 100% gratuita, não exige chave de API e é distribuída pela rede global Anycast da Cloudflare.
3. **Zero Dicionários Hardcoded:** Sem arquivos pesados em memória ou arrays de palavras estáticas. Base em nuvem com centenas de milhões de senhas reais e gerador procedural criptográfico nativo (`crypto.getRandomValues`).
4. **Conformidade Moderna NIST SP 800-63B:** Foco em comprimento, entropia de Shannon real e ausência em listas de vazamentos (em vez de regras antiquadas e frustrantes de caracteres forçados).

---

## 📦 Instalação e Importação

### Módulo ES (Node.js 18+ ou Bundlers / Vite / Webpack)

```bash
npm install passvalidator-pro
```

```javascript
import { PassValidatorPro } from 'passvalidator-pro';
```

### No Navegador (Direto via `<script>` ou HTML)

```html
<script type="module">
  import { PassValidatorPro } from './passvalidator-pro.js';
  // Ou disponível globalmente se importado via script
</script>
```

---

## 🔍 1. Validação Profunda de Senha

```javascript
import { PassValidatorPro } from './passvalidator-pro.js';

// Validação com checagem de vazamentos ao vivo
const relatorio = await PassValidatorPro.validar('admin123');

console.log(relatorio);
```

### Exemplo de Resposta do Relatório:

```json
{
  "valida": false,
  "score": 15,
  "nivel": "muito_fraca",
  "entropia_bits": 26.6,
  "tempo_estimado_quebra": "Instantâneo (< 1 segundo)",
  "criterios": {
    "comprimento": 8,
    "tem_minusculas": true,
    "tem_maiusculas": false,
    "tem_numeros": true,
    "tem_simbolos": false,
    "tem_repeticoes": false,
    "eh_sequencial": true,
    "nist_sp_800_63b": false
  },
  "vazamento": {
    "verificada": true,
    "vazada": true,
    "ocorrencias": 395840,
    "prefixo": "0A8F2"
  },
  "motivos": [
    "Comprometida: encontrada 395.840 vezes em listas públicas de senhas vazadas.",
    "Contém sequências óbvias de digitação (ex: \"12345\", \"qwerty\")."
  ],
  "sugestoes": [
    "Esta senha é de conhecimento público de invasores cibernéticos. Não a utilize de forma alguma.",
    "Aumente o comprimento para pelo menos 8 a 16 caracteres.",
    "Misture letras maiúsculas e minúsculas.",
    "Adicione símbolos especiais (!, @, #, $, %, etc.)."
  ]
}
```

---

## ⚡ 2. Gerador Criptográfico Multiperfil

A biblioteca disponibiliza **5 perfis especializados** que atendem desde sistemas bancários até tokens de APIs:

### Perfil 1: Forte / Completa (Padrão Corporativo & NIST)
Mistura maiúsculas, minúsculas, números e símbolos com exclusão automática de caracteres ambíguos (`0`, `O`, `l`, `1`, `I`).

```javascript
const senhaForte = PassValidatorPro.gerar('forte', { comprimento: 20 });
// Exemplo: "PvpJcL=PkbZ%G42$9CA5"
```

### Perfil 2: Alfanumérica (URL-Safe / Sem Símbolos)
Ideal para terminais, scripts bash, parâmetros de URL ou bancos de dados onde caracteres especiais (`&`, `<`, `"`) causam problemas de escape.

```javascript
const senhaAlfa = PassValidatorPro.gerar('alfanumerica', { comprimento: 16 });
// Exemplo: "BvHGjv4LfRprBrfS"
```

### Perfil 3: PIN Numérico (Bancos & 2FA)
Apenas dígitos criptograficamente seguros, com rejeição automática de padrões triviais (`0000`, `1234`, `1111`).

```javascript
const pin = PassValidatorPro.gerar('pin', { comprimento: 6 });
// Exemplo: "847291"
```

### Perfil 4: Pronunciável (Fácil de Ditar / Suporte Telefônico)
Padrão silábico fonético de fácil leitura humana, acompanhado de sufixo numérico e caractere especial para alta entropia.

```javascript
const senhaPronunciavel = PassValidatorPro.gerar('pronunciavel', { blocos: 3, separador: '-' });
// Exemplo: "bameto-kinuva-49!"
```

### Perfil 5: Token Criptográfico (Chaves de API & Webhooks)
Chaves hexadecimais de alta fidelidade baseadas em bytes aleatórios puros.

```javascript
const apiKey = PassValidatorPro.gerar('token', { bytes: 32, prefixo: 'key_live_' });
// Exemplo: "key_live_4d0bbdf516cb4ece5c4ba696ab23336fa9f08586c3243f44ae330b6c3531ed0f"
```

---

## 🧪 Como Executar os Testes

```bash
node test.js
```

Todos os testes validam o algoritmo SHA-1 nativo, a chamada real k-Anonymity contra a Cloudflare/HIBP, cálculo de entropia e os 5 perfis do gerador.

---

## 🖥️ Playground Interativo Local

Abra o arquivo [`index.html`](index.html) diretamente no seu navegador para testar a interface gráfica completa com:
- Medidor de força dinâmico com barra colorida.
- Contador de vazamentos em tempo real.
- Gerador de senhas com botão de copiar em 1 clique.

---

## 📄 Licença

Distribuído sob licença MIT. Consulte o arquivo [`LICENSE`](LICENSE) para mais detalhes.
