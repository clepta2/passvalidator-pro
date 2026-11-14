# 🛡️ PassValidator Pro — Validador de Senhas Vazadas & Gerador Multiperfil

> **SDK Universal, CLI e Auditor de Senhas em Tempo Real com detecção de vazamentos via *k-Anonymity* contra a base do Have I Been Pwned (860M+ senhas), cálculo de Entropia Efetiva de Shannon e Gerador Criptográfico Seguro de 6 Perfis.**
>
> 🚀 **Zero Servidor Próprio / Zero Conta Cloudflare Necessária:** Opera 100% no cliente (Navegador), em linha de comando (CLI), em microsserviços Node.js ou Edge Anycast com privacidade matemática absoluta.

[![Testes](https://img.shields.io/badge/Testes-100%25%20Aprovados-success.svg)](#)
[![Base HIBP](https://img.shields.io/badge/Base-860M%2B%20Senhas%20Vazadas-red.svg)](#)
[![Privacidade](https://img.shields.io/badge/Privacidade-k--Anonymity%20SHA--1-blue.svg)](#)
[![Perfis](https://img.shields.io/badge/Gerador-6%20Perfis%20de%20Proteção-emerald.svg)](#)
[![CLI](https://img.shields.io/badge/CLI-Nativo%20Terminal-orange.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

---

## ⚡ Por que Esta Arquitetura é Superior?

1. **Privacidade Matemática (*k-Anonymity*):** A senha do usuário **NUNCA** sai da máquina ou navegador. O hash SHA-1 é calculado localmente; apenas os **5 primeiros caracteres hexadecimais** do hash são enviados à API do Pwned Passwords. O casamento do sufixo ocorre na sua própria memória.
2. **Sem Custos ou Limites de Requisições:** A API do Pwned Passwords possui `Access-Control-Allow-Origin: *`, é 100% gratuita, não exige chave de API e é distribuída pela rede global Anycast da Cloudflare.
3. **Entropia Efetiva Real:** Penaliza senhas repetitivas como `aaaaaaaaaaaaaaaa` (que teriam alta entropia em calculadoras ingênuas) levando em conta a taxa de cardinalidade e blocos repetidos.
4. **4 Cenários Práticos de Força Bruta:** Estimativas reais de quebra para:
   - 🌐 Web com Rate-Limit (100 reqs/h)
   - ⚡ Web Sem Rate-Limit (1.000 reqs/s)
   - 🛡️ Offline Lento (bcrypt / Argon2id a 10.000 hashes/s)
   - 💥 Offline Rápido (GPU RTX 4090 / MD5 / NTLM a 100 bilhões hashes/s)
5. **Conformidade Avançada NIST SP 800-63B:** Detecção de dados pessoais (`nome`, `email`, `anoNascimento`), datas de calendário (`DDMMAAAA`), diagonais de teclado (`1qaz`, `2wsx`) e Leetspeak (`p@ssw0rd`).

---

## 💻 1. Uso via Terminal (CLI Nativo)

Você pode auditar ou gerar senhas diretamente pelo terminal:

```bash
# Auditar uma senha
npx passvalidator-pro "minhasenha123"

# Gerar senha forte com blocos agrupados (chunks)
npx passvalidator-pro -g --tipo=forte --comp=20 --chunks
# Saída: cykN-v}=G-qqzB-{cM^-2}WR

# Gerar frase memorável (Diceware)
npx passvalidator-pro -g --tipo=passphrase --palavras=4
# Saída: Diamante-Aurora-Falcão-Galaxia-48#

# Auditar arquivo de senhas em lote
npx passvalidator-pro --lote senhas_teste.txt
```

---

## 📦 2. Instalação como Biblioteca / SDK

### Módulo ES (Node.js 18+ ou Bundlers / Vite / Next.js / React)

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
</script>
```

---

## 🔍 3. Validação Profunda de Senha

```javascript
import { PassValidatorPro } from 'passvalidator-pro';

const relatorio = await PassValidatorPro.validar('Carlos@2024!', {
  verificarVazamento: true,
  dadosUsuario: {
    nome: 'Carlos',
    email: 'carlos@empresa.com.br'
  }
});

console.log(relatorio);
```

### Resposta Estruturada:

```json
{
  "valida": false,
  "score": 15,
  "nivel": "muito_fraca",
  "entropia_bits": 32.4,
  "entropia_teorica": 54.2,
  "tempo_estimado_quebra": "Instantâneo (< 1 segundo)",
  "cenarios_quebra": {
    "online_protegido": "Centenas de milhões de anos",
    "online_desprotegido": "25 dias",
    "offline_lento_bcrypt": "2.5 dias",
    "offline_rapido_gpu": "Instantâneo (< 1 segundo)"
  },
  "criterios": {
    "comprimento": 12,
    "tem_minusculas": true,
    "tem_maiusculas": true,
    "tem_numeros": true,
    "tem_simbolos": true,
    "tem_repeticoes": false,
    "eh_sequencial": false,
    "tem_ano_recente": true,
    "tem_data_calendario": false,
    "eh_leetspeak_fraco": false,
    "contem_dados_pessoais": true,
    "nist_sp_800_63b": false
  },
  "vazamento": {
    "verificada": true,
    "vazada": true,
    "ocorrencias": 12480,
    "prefixo": "4D9E2"
  },
  "motivos": [
    "Comprometida: encontrada 12.480 vezes em listas públicas de senhas vazadas.",
    "A senha contém seu nome (\"Carlos\").",
    "Contém um ano numérico recente, padrão muito explorado em ataques de dicionário."
  ]
}
```

---

## ⚡ 4. Gerador Criptográfico Multiperfil

| Perfil | Descrição | Exemplo Gerado |
|---|---|---|
| **`forte`** | Padrão Corporativo & NIST (maiúsculas, minúsculas, números e símbolos sem ambíguos) | `PvpJcL=PkbZ%G42$9CA5` |
| **`passphrase`** | Diceware Memorável (4 a 6 palavras em português) | `Cristal.Universo.Quasar.45%` |
| **`alfanumerica`** | URL-Safe / Sem Símbolos (para scripts bash e bancos) | `BvHGjv4LfRprBrfS` |
| **`pin`** | Numérico Puro (4 a 12 dígitos para cartões e 2FA) | `667650` |
| **`pronunciavel`** | Padrão silábico fonético de fácil leitura e suporte telefônico | `bow-neg-ne-81%` |
| **`token`** | Chave criptográfica hexadecimal de alta entropia | `pass_bbda819de8e7988e...` |

### Exemplo com Chunks (Blocos Legíveis):
```javascript
const senhaFormatada = PassValidatorPro.gerar('forte', {
  comprimento: 16,
  agruparChunks: true
});
// Exemplo: "cykN-v}=G-qqzB-{cM^"
```

---

## 📊 5. Auditoria em Lote (Batch)

Valide listas de senhas com desduplicação de chamadas ao HIBP:

```javascript
const auditoria = await PassValidatorPro.validarLote([
  '123456',
  'admin123',
  'Tx9#Kz2$Wp7!Lm8@'
]);

console.log(`Total: ${auditoria.total} | Vazadas: ${auditoria.comprometidas} | Aprovadas: ${auditoria.validas}`);
```

---

## 🧪 6. Testes Automatizados

```bash
node test.js
```

Todos os 9 conjuntos de testes validam Web Crypto SHA-1, k-Anonymity real no HIBP, cache LRU de prefixos, leetspeak, dados do usuário, datas, diagonais e perfis do gerador.

---

## 🖥️ 7. Playground Visual Interativo

Abra [`index.html`](index.html) no navegador para:
- Testar a senha em tempo real com **Live Checklist interativo** e medidor de força.
- Visualizar os **4 cenários práticos de quebra por força bruta**.
- Gerar senhas em 1 clique e transferi-las diretamente para auditoria.
- Rodar **Auditorias em Lote** com exportação em **CSV** e **JSON**.

---

## 📄 Licença

Distribuído sob licença MIT. Consulte o arquivo [`LICENSE`](LICENSE) para mais informações.
