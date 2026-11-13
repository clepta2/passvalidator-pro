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
  eh_leetspeak_fraco: boolean;
  contem_dados_pessoais: boolean;
  nist_sp_800_63b: boolean;
}

export interface RelatorioValidacao {
  valida: boolean;
  score: number;
  nivel: 'muito_fraca' | 'fraca' | 'media' | 'forte' | 'excelente';
  entropia_bits: number;
  tempo_estimado_quebra: string;
  criterios: CriteriosValidacao;
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
  separador?: string;
  incluirNumero?: boolean;
  incluirSimbolo?: boolean;
  bytes?: number;
  prefixo?: string;
}

export type PerfilGerador = 'forte' | 'completa' | 'complex' | 'alfanumerica' | 'alphanumeric' | 'pin' | 'numerica' | 'pronunciavel' | 'pronounceable' | 'token' | 'crypto_token';

export declare class PassValidatorPro {
  static sha1(str: string): Promise<string>;
  static secureRandomInt(max: number): number;
  static secureShuffle<T>(array: T[]): T[];
  static normalizarLeetspeak(str: string): string;
  static checarVazamento(senha: string): Promise<InfoVazamento>;
  static calcularEntropia(senha: string): { bits: number; tamanhoConjunto: number; tempoEstimadoQuebra: string };
  static validar(senha: string, opcoes?: OpcoesValidacao): Promise<RelatorioValidacao>;
  static validarLote(senhas: string[], opcoes?: OpcoesValidacao): Promise<ResultadoLote>;
  static gerar(tipo?: PerfilGerador, opcoes?: OpcoesGerador): string;
}

export default PassValidatorPro;
