#!/usr/bin/env node

/**
 * PassValidator Pro CLI
 * Auditoria de Senhas Vazadas e Gerador Criptográfico no Terminal
 *
 * @license MIT
 * @see https://github.com/clepta2/passvalidator-pro
 */

import fs from 'node:fs';
import path from 'node:path';
import { PassValidatorPro } from '../passvalidator-pro.js';

const args = process.argv.slice(2);

// Helpers de formatação ANSI
const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m'
};

function exibirAjuda() {
  console.log(`
${c.cyan}${c.bold}🛡️  PassValidator Pro CLI${c.reset} — Validador de Senhas Vazadas & Gerador Multiperfil

${c.bold}MODO DE USO:${c.reset}
  npx passvalidator-pro <senha>                     ${c.dim}# Auditar uma senha específica${c.reset}
  npx passvalidator-pro --gerar [opções]            ${c.dim}# Gerar senha criptográfica segura${c.reset}
  npx passvalidator-pro --lote <caminho-arquivo>    ${c.dim}# Auditar lista de senhas em arquivo txt${c.reset}

${c.bold}OPÇÕES DO GERADOR (--gerar / -g):${c.reset}
  --tipo=<perfil>      forte | passphrase | alfanumerica | pin | pronunciavel | token (padrão: forte)
  --comp=<número>      Comprimento da senha (padrão: 16)
  --palavras=<número>  Quantidade de palavras para passphrase (padrão: 4)
  --chunks             Agrupa em blocos de 4 (ex: abcd-efgh-ijkl)

${c.bold}EXEMPLOS:${c.reset}
  npx passvalidator-pro "minhasenha123"
  npx passvalidator-pro -g --tipo=forte --comp=24 --chunks
  npx passvalidator-pro -g --tipo=passphrase --palavras=4
  npx passvalidator-pro -g --tipo=pin --comp=6
  npx passvalidator-pro --lote senhas_teste.txt
`);
}

async function main() {
  if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
    exibirAjuda();
    process.exit(0);
  }

  // 1. MODO GERADOR
  if (args.includes('--gerar') || args.includes('-g')) {
    let tipo = 'forte';
    let comp = 16;
    let palavras = 4;
    let chunks = args.includes('--chunks');

    args.forEach(arg => {
      if (arg.startsWith('--tipo=')) tipo = arg.split('=')[1];
      if (arg.startsWith('--comp=')) comp = parseInt(arg.split('=')[1], 10);
      if (arg.startsWith('--palavras=')) palavras = parseInt(arg.split('=')[1], 10);
    });

    const senhaGerada = PassValidatorPro.gerar(tipo, {
      comprimento: comp,
      palavras,
      agruparChunks: chunks
    });

    const ent = PassValidatorPro.calcularEntropia(senhaGerada);
    console.log(`\n${c.green}${c.bold}🔑 Senha Gerada [${tipo}]:${c.reset} ${c.bold}${senhaGerada}${c.reset}`);
    console.log(`${c.dim}Entropia: ${ent.bits} bits | Tempo de quebra GPU: ${ent.tempoEstimadoQuebra}${c.reset}\n`);
    process.exit(0);
  }

  // 2. MODO LOTE VIA ARQUIVO
  if (args.includes('--lote') || args.includes('-l')) {
    const idx = args.findIndex(a => a === '--lote' || a === '-l');
    const arquivo = args[idx + 1];

    if (!arquivo || !fs.existsSync(arquivo)) {
      console.error(`${c.red}❌ Erro: Arquivo de senhas "${arquivo}" não encontrado.${c.reset}`);
      process.exit(1);
    }

    const conteudo = fs.readFileSync(arquivo, 'utf-8');
    const linhas = conteudo.split(/\r?\n/).map(l => l.trim()).filter(Boolean);

    console.log(`\n${c.cyan}⏳ Auditando ${linhas.length} senhas contra a base HIBP (860M+ vazamentos)...${c.reset}\n`);
    const resultado = await PassValidatorPro.validarLote(linhas);

    console.log(`${c.bold}RESULTADO DA AUDITORIA:${c.reset}`);
    console.log(`--------------------------------------------------------------------------------`);
    resultado.relatorios.forEach(r => {
      const status = r.vazamento.vazada
        ? `${c.red}${c.bold}VAZADA (${r.vazamento.ocorrencias.toLocaleString('pt-BR')}x)${c.reset}`
        : (r.valida ? `${c.green}${c.bold}SEGURA${c.reset}` : `${c.yellow}${c.bold}FRACA${c.reset}`);
      console.log(`• ${r.senha.padEnd(20)} | ${status.padEnd(25)} | Score: ${r.score}/100 | Entropia: ${r.entropia_bits} bits`);
    });
    console.log(`--------------------------------------------------------------------------------`);
    console.log(`Total: ${resultado.total} | Válidas: ${c.green}${resultado.validas}${c.reset} | Comprometidas: ${c.red}${resultado.comprometidas}${c.reset}\n`);
    process.exit(0);
  }

  // 3. MODO VALIDADOR INDIVIDUAL
  const senha = args[0];
  console.log(`\n${c.cyan}🔍 Auditando segurança da senha informada...${c.reset}`);

  const relatorio = await PassValidatorPro.validar(senha);

  const corNivel = {
    muito_fraca: c.red,
    fraca: c.red,
    media: c.yellow,
    forte: c.blue,
    excelente: c.green
  }[relatorio.nivel] || c.white;

  console.log(`\n${c.bold}RELATÓRIO DE SEGURANÇA:${c.reset}`);
  console.log(`--------------------------------------------------------------------------------`);
  console.log(`Status de Validação:    ${relatorio.valida ? `${c.green}✅ APROVADA${c.reset}` : `${c.red}❌ REPROVADA${c.reset}`}`);
  console.log(`Score de Segurança:     ${corNivel}${c.bold}${relatorio.score} / 100 (${relatorio.nivel.toUpperCase()})${c.reset}`);
  console.log(`Entropia Efetiva:       ${c.bold}${relatorio.entropia_bits} bits${c.reset} (Teórica: ${relatorio.entropia_teorica} bits)`);
  console.log(`Conformidade NIST:      ${relatorio.criterios.nist_sp_800_63b ? `${c.green}✅ Conforme NIST SP 800-63B${c.reset}` : `${c.red}❌ Não conforme${c.reset}`}`);

  if (relatorio.vazamento.vazada) {
    console.log(`\n${c.red}${c.bold}🚨 ALERTA DE VAZAMENTO:${c.reset}`);
    console.log(`${c.red}Esta senha foi encontrada ${relatorio.vazamento.ocorrencias.toLocaleString('pt-BR')} vezes no banco de credenciais vazadas (Have I Been Pwned).${c.reset}`);
  } else if (relatorio.vazamento.verificada) {
    console.log(`\n${c.green}🛡️  Have I Been Pwned: Nenhuma ocorrência em 860M+ de senhas vazadas.${c.reset}`);
  }

  if (relatorio.cenarios_quebra) {
    console.log(`\n${c.bold}⏱️  ESTIMATIVA DE TEMPO PARA QUEBRA POR FORÇA BRUTA:${c.reset}`);
    console.log(`  • Web com Rate-Limit (100 req/h):     ${c.cyan}${relatorio.cenarios_quebra.online_protegido}${c.reset}`);
    console.log(`  • Web Sem Rate-Limit (1.000 req/s):   ${c.cyan}${relatorio.cenarios_quebra.online_desprotegido}${c.reset}`);
    console.log(`  • Hash Lento (bcrypt / Argon2):       ${c.cyan}${relatorio.cenarios_quebra.offline_lento_bcrypt}${c.reset}`);
    console.log(`  • Hash Rápido (GPU RTX 4090 / MD5):   ${c.cyan}${relatorio.cenarios_quebra.offline_rapido_gpu}${c.reset}`);
  }

  if (relatorio.motivos.length > 0) {
    console.log(`\n${c.yellow}${c.bold}⚠️  Falhas Encontradas:${c.reset}`);
    relatorio.motivos.forEach(m => console.log(`  - ${m}`));
  }

  if (relatorio.sugestoes.length > 0) {
    console.log(`\n${c.cyan}${c.bold}💡 Recomendações:${c.reset}`);
    relatorio.sugestoes.forEach(s => console.log(`  - ${s}`));
  }

  console.log(`--------------------------------------------------------------------------------\n`);
}

main().catch(err => {
  console.error(`${c.red}Erro inesperado: ${err.message}${c.reset}`);
  process.exit(1);
});
