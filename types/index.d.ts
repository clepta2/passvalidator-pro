export interface DadosUsuario {
  nome?: string;
  sobrenome?: string;
  email?: string;
  usuario?: string;
  anoNascimento?: string | number;
}

export interface OpcoesValidacao {
  verificarVazamento?: boolean;
  tamanhoMinimo?: number;
  dadosUsuario?: DadosUsuario | null;
  regrasEmpresariais?: boolean;
}

export interface InfoVazamento {
  verificada: boolean;
  vazada: boolean;
  ocorrencias: number;
  prefixo: string;
  erro?: string;
}

export interface CriteriosValidacao {
  comprimento: number;
  tem_minusculas: boolean;
  tem_maiusculas: boolean;
  tem_numeros: boolean;
  tem_simbolos: boolean;
  tem_repeticoes: boolean;
  eh_sequencial: boolean;
  tem_ano_recente: boolean;
  tem_data_calendario?: boolean;
  eh_leetspeak_fraco: boolean;
  contem_dados_pessoais: boolean;
  regras_empresariais_atendidas?: boolean;
  nist_sp_800_63b: boolean;
}

export interface NistChecklist {
  conforme: boolean;
  regras: {
    comprimento_minimo_8: boolean;
    comprimento_recomendado_15: boolean;
    ausente_em_vazamentos: boolean;
    sem_dados_contextuais: boolean;
    sem_datas_obvias: boolean;
    sem_sequencias_triviais: boolean;
  };
}

export interface CenariosQuebra {
  online_protegido: string;
  online_desprotegido: string;
  offline_lento_bcrypt: string;
  offline_rapido_gpu: string;
}

export interface RelatorioValidacao {
  valida: boolean;
  score: number;
  nivel: 'muito_fraca' | 'fraca' | 'media' | 'forte' | 'excelente';
  entropia_bits: number;
  entropia_teorica?: number;
  tempo_estimado_quebra: string;
  cenarios_quebra?: CenariosQuebra;
  criterios: CriteriosValidacao;
  nist_checklist?: NistChecklist;
  vazamento: InfoVazamento;
  motivos: string[];
  sugestoes: string[];
}

export interface ResultadoLote {
  total: number;
  validas: number;
  comprometidas: number;
  relatorios: Array<RelatorioValidacao & { senha: string }>;
}

export interface OpcoesGerador {
  comprimento?: number;
  evitarAmbiguos?: boolean;
  blocos?: number;
  palavras?: number;
  listaPalavras?: string[];
  capitalizar?: boolean;
  separador?: string;
  incluirNumero?: boolean;
  incluirSimbolo?: boolean;
  bytes?: number;
  prefixo?: string;
  agruparChunks?: boolean;
}

export type PerfilGerador = 'forte' | 'completa' | 'complex' | 'alfanumerica' | 'alphanumeric' | 'pin' | 'numerica' | 'pronunciavel' | 'pronounceable' | 'passphrase' | 'diceware' | 'token' | 'crypto_token';

export declare class PassValidatorPro {
  static sha1(str: string): Promise<string>;
  static secureRandomInt(max: number): number;
  static secureShuffle<T>(array: T[]): T[];
  static normalizarLeetspeak(str: string): string;
  static detectarDataCalendario(str: string): boolean;
  static detectarPadraoTeclado(str: string): boolean;
  static formatarChunks(senha: string, tamanhoBloco?: number, separador?: string): string;
  static checarVazamento(senha: string): Promise<InfoVazamento>;
  static calcularEntropia(senha: string): {
    bits: number;
    bitsTeoricos: number;
    tamanhoConjunto: number;
    taxaDiversidade: number;
    tempoEstimadoQuebra: string;
    cenarios_quebra: CenariosQuebra;
  };
  static validar(senha: string, opcoes?: OpcoesValidacao): Promise<RelatorioValidacao>;
  static validarLote(senhas: string[], opcoes?: OpcoesValidacao): Promise<ResultadoLote>;
  static gerar(tipo?: PerfilGerador, opcoes?: OpcoesGerador): string;
}

export default PassValidatorPro;
