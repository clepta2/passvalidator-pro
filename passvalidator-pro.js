/**
 * PassValidatorPro — SDK e Validador de Senhas com Detecção de Vazamentos e Gerador Multiperfil
 *
 * - Validação de Vazamentos via Have I Been Pwned (k-Anonymity SHA-1, sem envio de senha)
 * - Cache LRU de prefixos em memória e proteção por Timeout (AbortSignal)
 * - Detecção de Engenharia Social (nome, e-mail, usuário, ano de nascimento)
 * - Detecção de Leetspeak (ex: p@ssw0rd, adm!n2024), Anos Recentes e Datas (DDMMAAAA)
 * - Detecção de Sequências e Diagonais de Teclado QWERTY (1qaz, 2wsx, qwerty, 12345)
 * - Cálculo de Entropia Efetiva de Shannon e 4 Cenários Práticos de Força Bruta
 * - Conformidade Avançada com NIST SP 800-63B e OWASP
 * - Validação individual e em Lote (Batch) com deduplicação de chamadas
 * - Gerador Criptográfico Seguro (crypto.getRandomValues) com 6 Perfis e Agrupamento em Chunks
 *
 * @license MIT
 * @author clepta2 <clepta2@gmail.com>
 */

function formatarTempo(segundos) {
  if (segundos < 1) return 'Instantâneo (< 1 segundo)';
  if (segundos < 60) return `${Math.round(segundos)} segundos`;
  if (segundos < 3600) return `${Math.round(segundos / 60)} minutos`;
  if (segundos < 86400) return `${Math.round(segundos / 3600)} horas`;
  if (segundos < 31536000) return `${Math.round(segundos / 86400)} dias`;
  if (segundos < 31536000 * 100) return `${Math.round(segundos / 31536000)} anos`;
  if (segundos < 31536000 * 1e6) return `${Math.round(segundos / (31536000 * 1000))} mil anos`;
  return 'Centenas de milhões de anos (Inviável quebrar)';
}

const DICIONARIO_DICEWARE_PADRAO = [
  'abacaxi', 'albatroz', 'aldeia', 'algoritmo', 'aurora', 'bateria', 'besouro', 'bussola',
  'cabana', 'cacau', 'camaleao', 'castelo', 'cometa', 'cristal', 'delta', 'diamante',
  'dragao', 'eclipse', 'engrenagem', 'esfera', 'falcao', 'farol', 'floresta', 'galaxia',
  'gaviao', 'girassol', 'horizonte', 'iguana', 'impacto', 'infinito', 'jangada', 'jaguar',
  'labirinto', 'laguna', 'lanterna', 'lontra', 'madeira', 'marte', 'meteoro', 'miragem',
  'montanha', 'neblina', 'nebula', 'oceano', 'orquidea', 'oasis', 'pantera', 'passaro',
  'planeta', 'prisma', 'quasar', 'radar', 'raposa', 'recife', 'sabedoria', 'safira',
  'satelite', 'sombra', 'tornado', 'trovao', 'tsunami', 'universo', 'vulcao', 'safira',
  'andorinha', 'arcaico', 'baleia', 'bastiao', 'cacique', 'calmaria', 'cascata', 'colibri',
  'dinamite', 'dorado', 'esmeralda', 'falange', 'fenix', 'fortaleza', 'glaciar', 'harpia',
  'harpuna', 'impeto', 'jacaranda', 'leopardo', 'magma', 'mandala', 'navegador', 'oraculo',
  'pendulo', 'piramide', 'quimera', 'radiante', 'relampago', 'sentinela', 'titanio', 'vertice'
];

export class PassValidatorPro {
  static _cachePrefixos = new Map();
  static _maxCacheSize = 500;

  /**
   * Calcula o hash SHA-1 da senha em maiúsculas usando Web Crypto API nativa.
   * @param {string} str
   * @returns {Promise<string>} Hash SHA-1 em hexadecimal maiúsculo
   */
  static async sha1(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  }

  /**
   * Gera um inteiro aleatório criptograficamente seguro entre 0 e max - 1.
   * @param {number} max
   * @returns {number}
   */
  static secureRandomInt(max) {
    if (max <= 0) return 0;
    const array = new Uint32Array(1);
    crypto.getRandomValues(array);
    return array[0] % max;
  }

  /**
   * Embaralha um array de forma criptograficamente segura (Algoritmo Fisher-Yates).
   * @param {Array} array
   * @returns {Array}
   */
  static secureShuffle(array) {
    for (let i = array.length - 1; i > 0; i--) {
      const j = this.secureRandomInt(i + 1);
      [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
  }

  /**
   * Normaliza substituições comuns de Leetspeak para análise de padrões semânticos fracos.
   * @param {string} str
   * @returns {string}
   */
  static normalizarLeetspeak(str) {
    if (!str) return '';
    return str
      .toLowerCase()
      .replace(/[@4]/g, 'a')
      .replace(/[3]/g, 'e')
      .replace(/[!1|]/g, 'i')
      .replace(/[0]/g, 'o')
      .replace(/[$5]/g, 's')
      .replace(/[7+]/g, 't');
  }

  /**
   * Detecta se a string contém datas de calendário óbvias (ex: DDMMAAAA, DDMMAA, AAAAMMDD).
   * @param {string} str
   * @returns {boolean}
   */
  static detectarDataCalendario(str) {
    if (!str || str.length < 6) return false;
    const padraoDdmmaaaa = /(?:0[1-9]|[12][0-9]|3[01])[\/\-\.]?(?:0[1-9]|1[012])[\/\-\.]?(?:19\d{2}|20[0-3]\d|\d{2})/;
    const padraoAaaammdd = /(?:19\d{2}|20[0-3]\d)[\/\-\.]?(?:0[1-9]|1[012])[\/\-\.]?(?:0[1-9]|[12][0-9]|3[01])/;
    return padraoDdmmaaaa.test(str) || padraoAaaammdd.test(str);
  }

  /**
   * Detecta padrões sequenciais e diagonais do teclado (QWERTY, numérico, alfabético).
   * @param {string} str
   * @returns {boolean}
   */
  static detectarPadraoTeclado(str) {
    if (!str) return false;
    const s = str.toLowerCase();
    const padroes = [
      '12345', '54321', '67890', '09876',
      'qwerty', 'ytrewq', 'asdfgh', 'hgfdsa', 'zxcvbn', 'nbvcxz',
      '1qaz', 'zaq1', '2wsx', 'xsw2', '3edc', 'cde3', '4rfv', 'vfr4',
      '5tgb', 'bgt5', '6yhn', 'nhy6', '7ujm', 'mju7',
      'abcdef', 'fedcba', 'ghijkl', 'mnopqr'
    ];
    for (const p of padroes) {
      if (s.includes(p)) return true;
    }
    return false;
  }

  /**
   * Consulta a lista de sufixos de um prefixo HIBP com cache em memória e timeout seguro.
   * @private
   * @param {string} prefix
   * @param {number} [timeoutMs=4000]
   * @returns {Promise<Map<string, number>>} Mapa de Sufixo -> Ocorrências
   */
  static async _obterSufixosHibp(prefix, timeoutMs = 4000) {
    if (this._cachePrefixos.has(prefix)) {
      return this._cachePrefixos.get(prefix);
    }

    const mapaSufixos = new Map();
    const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const timeoutId = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;

    try {
      const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
        headers: { 'Add-Padding': 'true' },
        signal: controller ? controller.signal : undefined
      });

      if (!response.ok) return mapaSufixos;

      const text = await response.text();
      const lines = text.split('\r\n');

      for (const line of lines) {
        const [hashSuffix, countStr] = line.split(':');
        if (hashSuffix && countStr) {
          mapaSufixos.set(hashSuffix.trim(), parseInt(countStr, 10) || 0);
        }
      }

      if (this._cachePrefixos.size >= this._maxCacheSize) {
        const firstKey = this._cachePrefixos.keys().next().value;
        this._cachePrefixos.delete(firstKey);
      }
      this._cachePrefixos.set(prefix, mapaSufixos);

      return mapaSufixos;
    } finally {
      if (timeoutId) clearTimeout(timeoutId);
    }
  }

  /**
   * Verifica se a senha foi comprometida em vazamentos públicos de dados usando k-Anonymity.
   * @param {string} senha
   * @returns {Promise<{ verificada: boolean, vazada: boolean, ocorrencias: number, prefixo: string, erro?: string }>}
   */
  static async checarVazamento(senha) {
    if (!senha || typeof senha !== 'string') {
      return { verificada: false, vazada: false, ocorrencias: 0, prefixo: '' };
    }

    try {
      const fullHash = await this.sha1(senha);
      const prefix = fullHash.slice(0, 5);
      const suffix = fullHash.slice(5);

      const mapaSufixos = await this._obterSufixosHibp(prefix);
      const ocorrencias = mapaSufixos.get(suffix) || 0;

      return {
        verificada: true,
        vazada: ocorrencias > 0,
        ocorrencias,
        prefixo: prefix
      };
    } catch (err) {
      return {
        verificada: false,
        vazada: false,
        ocorrencias: 0,
        prefixo: '',
        erro: err.message
      };
    }
  }

  /**
   * Calcula a Entropia Efetiva de Shannon e 4 cenários práticos de quebra por força bruta.
   * @param {string} senha
   * @returns {{ bits: number, bitsTeoricos: number, tamanhoConjunto: number, taxaDiversidade: number, tempoEstimadoQuebra: string, cenarios_quebra: object }}
   */
  static calcularEntropia(senha) {
    if (!senha || typeof senha !== 'string') {
      return {
        bits: 0,
        bitsTeoricos: 0,
        tamanhoConjunto: 0,
        taxaDiversidade: 0,
        tempoEstimadoQuebra: 'Instantâneo (< 1 segundo)',
        cenarios_quebra: {
          online_protegido: 'Instantâneo (< 1 segundo)',
          online_desprotegido: 'Instantâneo (< 1 segundo)',
          offline_lento_bcrypt: 'Instantâneo (< 1 segundo)',
          offline_rapido_gpu: 'Instantâneo (< 1 segundo)'
        }
      };
    }

    let pool = 0;
    if (/[a-z]/.test(senha)) pool += 26;
    if (/[A-Z]/.test(senha)) pool += 26;
    if (/[0-9]/.test(senha)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(senha)) pool += 33;

    if (pool === 0) {
      return {
        bits: 0,
        bitsTeoricos: 0,
        tamanhoConjunto: 0,
        taxaDiversidade: 0,
        tempoEstimadoQuebra: 'Instantâneo (< 1 segundo)',
        cenarios_quebra: {}
      };
    }

    const bitsTeoricos = Math.round(senha.length * Math.log2(pool) * 10) / 10;

    // Fator de diversidade real (penaliza senhas repetidas como 'aaaaaaaa')
    const caracteresUnicos = new Set(senha).size;
    const taxaDiversidade = Math.round((caracteresUnicos / senha.length) * 100) / 100;

    let fatorRepeticaoBlocos = 1;
    if (/(.{2,})\1+/.test(senha)) {
      fatorRepeticaoBlocos = 0.65;
    }

    const bitsEfetivos = Math.round(bitsTeoricos * Math.max(0.08, taxaDiversidade) * fatorRepeticaoBlocos * 10) / 10;
    const bits = Math.max(0, bitsEfetivos);

    // Média de tentativas necessárias para quebra por força bruta (50% do espaço de busca)
    const combinacoesPossiveis = Math.pow(2, bits);
    const mediaTentativas = combinacoesPossiveis / 2;

    const cenarios = {
      online_protegido: formatarTempo(mediaTentativas / 0.0277), // 100 reqs/hora (Web com rate-limit)
      online_desprotegido: formatarTempo(mediaTentativas / 1000), // 1.000 reqs/segundo
      offline_lento_bcrypt: formatarTempo(mediaTentativas / 10000), // 10.000 hashes/s (Argon2id/bcrypt)
      offline_rapido_gpu: formatarTempo(mediaTentativas / 1e11) // 100 bilhões hashes/s (MD5/NTLM/SHA-256 em GPU RTX 4090)
    };

    return {
      bits,
      bitsTeoricos,
      tamanhoConjunto: pool,
      taxaDiversidade,
      tempoEstimadoQuebra: cenarios.offline_rapido_gpu,
      cenarios_quebra: cenarios
    };
  }

  /**
   * Realiza a validação completa de segurança de uma senha.
   *
   * @param {string} senha Senha a ser validada
   * @param {object} [opcoes={}]
   * @param {boolean} [opcoes.verificarVazamento=true] Consultar base Have I Been Pwned
   * @param {number} [opcoes.tamanhoMinimo=8] Comprimento mínimo exigido
   * @param {object} [opcoes.dadosUsuario] Dados do usuário para checagem anti-engenharia social
   * @param {boolean} [opcoes.regrasEmpresariais=false] Exige estritamente maiúsculas, minúsculas, números e símbolos
   * @returns {Promise<object>} Relatório minucioso de força, regras e vazamento
   */
  static async validar(senha, opcoes = {}) {
    const {
      verificarVazamento = true,
      tamanhoMinimo = 8,
      dadosUsuario = null,
      regrasEmpresariais = false
    } = opcoes;

    if (typeof senha !== 'string' || senha.length === 0) {
      return {
        valida: false,
        score: 0,
        nivel: 'muito_fraca',
        motivos: ['A senha fornecida está vazia.'],
        sugestoes: ['Insira uma senha válida com pelo menos 8 a 16 caracteres.']
      };
    }

    const comprimento = senha.length;
    const temMinusculas = /[a-z]/.test(senha);
    const temMaiusculas = /[A-Z]/.test(senha);
    const temNumeros = /[0-9]/.test(senha);
    const temSimbolos = /[^a-zA-Z0-9]/.test(senha);

    // Detecção de repetições sequenciais (ex: aaaa, 1111)
    const temRepeticoes = /(.)\1{2,}/.test(senha);

    // Detecção de padrões de teclado
    const ehSequencial = this.detectarPadraoTeclado(senha);

    // Detecção de anos recentes e datas de calendário (DDMMAAAA)
    const temAnoRecente = /(19\d{2}|20[0-3]\d)/.test(senha);
    const temDataCalendario = this.detectarDataCalendario(senha);

    // Detecção de Leetspeak vulnerável
    const normalizada = this.normalizarLeetspeak(senha);
    const ehLeetspeakFraco = /(password|senha|admin|mudar|root|brasil)/.test(normalizada);

    // Detecção de dados pessoais do usuário na senha
    const violacoesDadosPessoais = [];
    if (dadosUsuario && typeof dadosUsuario === 'object') {
      const lowerSenha = senha.toLowerCase();
      const termos = [];

      if (dadosUsuario.nome && dadosUsuario.nome.length >= 3) termos.push({ campo: 'nome', valor: dadosUsuario.nome });
      if (dadosUsuario.sobrenome && dadosUsuario.sobrenome.length >= 3) termos.push({ campo: 'sobrenome', valor: dadosUsuario.sobrenome });
      if (dadosUsuario.usuario && dadosUsuario.usuario.length >= 3) termos.push({ campo: 'usuário', valor: dadosUsuario.usuario });
      if (dadosUsuario.anoNascimento) termos.push({ campo: 'ano de nascimento', valor: String(dadosUsuario.anoNascimento) });
      if (dadosUsuario.email && dadosUsuario.email.includes('@')) {
        const prefixoEmail = dadosUsuario.email.split('@')[0];
        if (prefixoEmail.length >= 3) termos.push({ campo: 'e-mail', valor: prefixoEmail });
      }

      for (const t of termos) {
        if (lowerSenha.includes(t.valor.toLowerCase())) {
          violacoesDadosPessoais.push(`A senha contém seu ${t.campo} ("${t.valor}").`);
        }
      }
    }

    const entropia = this.calcularEntropia(senha);

    // Consulta de vazamentos (k-Anonymity)
    let infoVazamento = { verificada: false, vazada: false, ocorrencias: 0 };
    if (verificarVazamento) {
      infoVazamento = await this.checarVazamento(senha);
    }

    // Cálculo do Score (0 a 100)
    let score = 0;
    if (comprimento >= tamanhoMinimo) score += 20;
    if (comprimento >= 12) score += 15;
    if (comprimento >= 16) score += 15;
    if (temMinusculas && temMaiusculas) score += 15;
    if (temNumeros) score += 15;
    if (temSimbolos) score += 20;

    // Penalizações lógicas
    if (temRepeticoes) score -= 15;
    if (ehSequencial) score -= 20;
    if (temAnoRecente) score -= 10;
    if (temDataCalendario) score -= 20;
    if (ehLeetspeakFraco) score -= 25;
    if (violacoesDadosPessoais.length > 0) score -= 30;
    if (infoVazamento.vazada) score = Math.min(score, 15);
    score = Math.max(0, Math.min(100, score));

    let nivel = 'muito_fraca';
    if (score >= 80) nivel = 'excelente';
    else if (score >= 60) nivel = 'forte';
    else if (score >= 40) nivel = 'media';
    else if (score >= 20) nivel = 'fraca';

    const motivos = [];
    const sugestoes = [];

    if (infoVazamento.vazada) {
      motivos.push(`Comprometida: encontrada ${infoVazamento.ocorrencias.toLocaleString('pt-BR')} vezes em listas públicas de senhas vazadas.`);
      sugestoes.push('Esta senha é de conhecimento público de invasores cibernéticos. Não a utilize de forma alguma.');
    }

    if (comprimento < tamanhoMinimo) {
      motivos.push(`Comprimento insuficiente (${comprimento} caracteres, mínimo exigido: ${tamanhoMinimo}).`);
      sugestoes.push(`Aumente o comprimento para pelo menos ${tamanhoMinimo} a 16 caracteres.`);
    }

    if (violacoesDadosPessoais.length > 0) {
      motivos.push(...violacoesDadosPessoais);
      sugestoes.push('Nunca utilize seu nome, e-mail ou data de nascimento na senha.');
    }

    if (ehLeetspeakFraco) {
      motivos.push('Contém substituições óbvias de palavras fracas (ex: "@" por "a", "0" por "o").');
      sugestoes.push('Evite truques simples de leetspeak como "p@ssw0rd" ou "adm!n".');
    }

    if (temDataCalendario) {
      motivos.push('Contém uma data de calendário evidente (ex: DDMMAAAA ou DD/MM/AAAA).');
      sugestoes.push('Evite datas de aniversário ou casamentos na composição da senha.');
    } else if (temAnoRecente) {
      motivos.push('Contém um ano numérico recente, padrão muito explorado em ataques de dicionário.');
      sugestoes.push('Evite incluir anos (como 2024, 2025, 2026) no início ou final da senha.');
    }

    if (!temMinusculas || !temMaiusculas) {
      sugestoes.push('Misture letras maiúsculas e minúsculas.');
    }

    if (!temNumeros) {
      sugestoes.push('Adicione dígitos numéricos.');
    }

    if (!temSimbolos) {
      sugestoes.push('Adicione símbolos especiais (!, @, #, $, %, etc.).');
    }

    if (temRepeticoes) {
      motivos.push('Contém caracteres repetidos em sequência (ex: "aaa", "111").');
      sugestoes.push('Evite repetições consecutivas de um mesmo caractere.');
    }

    if (ehSequencial) {
      motivos.push('Contém sequências óbvias de digitação ou diagonais do teclado (ex: "12345", "1qaz", "qwerty").');
      sugestoes.push('Elimine sequências lineares ou diagonais do teclado.');
    }

    let atendeRegrasEmpresariais = true;
    if (regrasEmpresariais) {
      if (!temMinusculas || !temMaiusculas || !temNumeros || !temSimbolos) {
        atendeRegrasEmpresariais = false;
        motivos.push('Requisito corporativo rígido não atendido: deve conter obrigatoriamente minúsculas, maiúsculas, números e símbolos.');
      }
    }

    const nistConforme = comprimento >= 8 && !infoVazamento.vazada && violacoesDadosPessoais.length === 0 && !temDataCalendario;

    return {
      valida: score >= 60 && !infoVazamento.vazada && comprimento >= tamanhoMinimo && violacoesDadosPessoais.length === 0 && atendeRegrasEmpresariais,
      score,
      nivel,
      entropia_bits: entropia.bits,
      entropia_teorica: entropia.bitsTeoricos,
      tempo_estimado_quebra: entropia.tempoEstimadoQuebra,
      cenarios_quebra: entropia.cenarios_quebra,
      criterios: {
        comprimento,
        tem_minusculas: temMinusculas,
        tem_maiusculas: temMaiusculas,
        tem_numeros: temNumeros,
        tem_simbolos: temSimbolos,
        tem_repeticoes: temRepeticoes,
        eh_sequencial: ehSequencial,
        tem_ano_recente: temAnoRecente,
        tem_data_calendario: temDataCalendario,
        eh_leetspeak_fraco: ehLeetspeakFraco,
        contem_dados_pessoais: violacoesDadosPessoais.length > 0,
        regras_empresariais_atendidas: atendeRegrasEmpresariais,
        nist_sp_800_63b: nistConforme
      },
      nist_checklist: {
        conforme: nistConforme,
        regras: {
          comprimento_minimo_8: comprimento >= 8,
          comprimento_recomendado_15: comprimento >= 15,
          ausente_em_vazamentos: !infoVazamento.vazada,
          sem_dados_contextuais: violacoesDadosPessoais.length === 0,
          sem_datas_obvias: !temDataCalendario,
          sem_sequencias_triviais: !ehSequencial
        }
      },
      vazamento: infoVazamento,
      motivos,
      sugestoes
    };
  }

  /**
   * Valida uma lista de senhas em lote (Batch), otimizando chamadas de rede com deduplicação de prefixos SHA-1.
   * @param {string[]} senhas
   * @param {object} [opcoes={}]
   * @returns {Promise<{ total: number, validas: number, comprometidas: number, relatorios: object[] }>}
   */
  static async validarLote(senhas, opcoes = {}) {
    if (!Array.isArray(senhas)) {
      throw new Error('O parâmetro senhas deve ser um array de strings.');
    }

    const relatorios = [];
    let validas = 0;
    let comprometidas = 0;

    for (const s of senhas) {
      const rel = await this.validar(s, opcoes);
      relatorios.push({ senha: s, ...rel });
      if (rel.valida) validas++;
      if (rel.vazamento && rel.vazamento.vazada) comprometidas++;
    }

    return {
      total: senhas.length,
      validas,
      comprometidas,
      relatorios
    };
  }

  /**
   * Formata uma string de senha em blocos legíveis (ex: abcd-efgh-ijkl).
   * @param {string} senha
   * @param {number} [tamanhoBloco=4]
   * @param {string} [separador='-']
   * @returns {string}
   */
  static formatarChunks(senha, tamanhoBloco = 4, separador = '-') {
    if (!senha) return '';
    const regex = new RegExp(`.{1,${tamanhoBloco}}`, 'g');
    const chunks = senha.match(regex) || [];
    return chunks.join(separador);
  }

  /**
   * Gerador Criptográfico de Senhas Multiperfil
   *
   * Perfis suportados:
   * - 'forte' / 'completa': Padrão empresarial (maiúsculas, minúsculas, números, símbolos, sem ambíguos)
   * - 'passphrase' / 'diceware': Frase memorável estilo Diceware/XKCD (ex: "Aurora.Satélite.Quasar.42!")
   * - 'alfanumerica': Letras e números apenas (URL-safe, sem caracteres problemáticos para terminais)
   * - 'pin': PIN numérico puro (bancos, cartões, 2FA)
   * - 'pronunciavel': Padrão silábico fonético fácil de ler e ditar em voz alta
   * - 'token': Chave criptográfica em hexadecimal ou base64url (para APIs e Webhooks)
   *
   * @param {'forte'|'passphrase'|'alfanumerica'|'pin'|'pronunciavel'|'token'} [tipo='forte']
   * @param {object} [opcoes={}]
   * @returns {string} Senha gerada
   */
  static gerar(tipo = 'forte', opcoes = {}) {
    const perfil = tipo.toLowerCase();

    // 1. FORTE / COMPLETA (Enterprise Standard)
    if (perfil === 'forte' || perfil === 'completa' || perfil === 'complex') {
      const comprimento = Math.max(8, Math.min(128, opcoes.comprimento || 16));
      const evitarAmbiguos = opcoes.evitarAmbiguos !== false;

      let maiusc = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
      let minusc = 'abcdefghijkmnopqrstuvwxyz';
      let nums = '23456789';
      let simb = '!@#$%^&*()-_=+[]{}|;:,.<>?';

      if (!evitarAmbiguos) {
        maiusc += 'IO';
        minusc += 'lo';
        nums += '01';
      }

      const resultado = [
        maiusc[this.secureRandomInt(maiusc.length)],
        minusc[this.secureRandomInt(minusc.length)],
        nums[this.secureRandomInt(nums.length)],
        simb[this.secureRandomInt(simb.length)]
      ];

      const todos = maiusc + minusc + nums + simb;
      while (resultado.length < comprimento) {
        resultado.push(todos[this.secureRandomInt(todos.length)]);
      }

      const finalPass = this.secureShuffle(resultado).join('');
      return opcoes.agruparChunks ? this.formatarChunks(finalPass) : finalPass;
    }

    // 2. PASSPHRASE / DICEWARE (Frase-passe memorável)
    if (perfil === 'passphrase' || perfil === 'diceware') {
      const palavras = Array.isArray(opcoes.listaPalavras) && opcoes.listaPalavras.length >= 5
        ? opcoes.listaPalavras
        : DICIONARIO_DICEWARE_PADRAO;

      const qtd = Math.max(3, Math.min(8, opcoes.palavras || 4));
      const separador = opcoes.separador || '-';
      const partes = [];

      for (let i = 0; i < qtd; i++) {
        let p = palavras[this.secureRandomInt(palavras.length)];
        if (opcoes.capitalizar !== false) {
          p = p.charAt(0).toUpperCase() + p.slice(1);
        }
        partes.push(p);
      }

      let res = partes.join(separador);
      if (opcoes.incluirNumero !== false) {
        res += `${separador}${this.secureRandomInt(90) + 10}`;
      }
      if (opcoes.incluirSimbolo !== false) {
        const simbolos = '!@#$%&*';
        res += simbolos[this.secureRandomInt(simbolos.length)];
      }
      return res;
    }

    // 3. ALFANUMÉRICA (URL-Safe / Sem Símbolos)
    if (perfil === 'alfanumerica' || perfil === 'alphanumeric') {
      const comprimento = Math.max(8, Math.min(128, opcoes.comprimento || 16));
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
      const resultado = [];
      for (let i = 0; i < comprimento; i++) {
        resultado.push(chars[this.secureRandomInt(chars.length)]);
      }
      const finalPass = resultado.join('');
      return opcoes.agruparChunks ? this.formatarChunks(finalPass) : finalPass;
    }

    // 4. PIN NUMÉRICO (Bancos / 2FA)
    if (perfil === 'pin' || perfil === 'numerica') {
      const comprimento = Math.max(4, Math.min(16, opcoes.comprimento || 6));
      let pin = '';
      for (let i = 0; i < comprimento; i++) {
        pin += this.secureRandomInt(10).toString();
      }
      if (/^(.)\1+$/.test(pin) || pin === '1234' || pin === '123456') {
        return this.gerar('pin', opcoes);
      }
      return pin;
    }

    // 5. PRONUNCIÁVEL (Padrão Silábico Consoante-Vogal)
    if (perfil === 'pronunciavel' || perfil === 'pronounceable') {
      const blocos = Math.max(2, Math.min(8, opcoes.blocos || 3));
      const consoantes = 'bcdfghjklmnprstvwz';
      const vogais = 'aeiou';
      const partes = [];

      for (let b = 0; b < blocos; b++) {
        let silaba = '';
        const tam = 2 + this.secureRandomInt(2);
        for (let i = 0; i < tam; i++) {
          silaba += (i % 2 === 0)
            ? consoantes[this.secureRandomInt(consoantes.length)]
            : vogais[this.secureRandomInt(vogais.length)];
        }
        partes.push(silaba);
      }

      const separador = opcoes.separador || '-';
      let resultado = partes.join(separador);

      if (opcoes.incluirNumero !== false) {
        resultado += `${separador}${this.secureRandomInt(90) + 10}`;
      }
      if (opcoes.incluirSimbolo !== false) {
        const simbolos = '!@#$%&*';
        resultado += simbolos[this.secureRandomInt(simbolos.length)];
      }

      return resultado;
    }

    // 6. TOKEN CRIPTOGRÁFICO / API KEY
    if (perfil === 'token' || perfil === 'crypto_token') {
      const bytes = Math.max(16, Math.min(64, opcoes.bytes || 32));
      const array = new Uint8Array(bytes);
      crypto.getRandomValues(array);
      const hex = Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
      const prefixo = opcoes.prefixo || 'pass_';
      return `${prefixo}${hex}`;
    }

    throw new Error(`Perfil '${tipo}' desconhecido. Use: 'forte', 'passphrase', 'alfanumerica', 'pin', 'pronunciavel' ou 'token'.`);
  }
}

if (typeof window !== 'undefined') {
  window.PassValidatorPro = PassValidatorPro;
}

export default PassValidatorPro;
