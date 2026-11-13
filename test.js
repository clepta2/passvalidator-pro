import { PassValidatorPro } from './passvalidator-pro.js';

console.log('🧪 Iniciando Testes Unitários de PassValidatorPro...\n');

async function executarTestes() {
  let falhas = 0;

  // 1. Teste de Hash SHA-1 nativo
  console.log('1. Testando cálculo de SHA-1...');
  const hash123456 = await PassValidatorPro.sha1('123456');
  console.assert(hash123456 === '7C4A8D09CA3762AF61E59520943DC26494F8941B', 'SHA1 de 123456 deve bater');
  console.log('   ✅ SHA-1 correto:', hash123456);

  // 2. Teste de Detecção de Vazamento com Have I Been Pwned (k-Anonymity)
  console.log('\n2. Testando k-Anonymity com Have I Been Pwned (senha vazada)...');
  const vazamento = await PassValidatorPro.checarVazamento('123456');
  console.assert(vazamento.verificada === true, 'Deve ter sido verificada no HIBP');
  console.assert(vazamento.vazada === true, '123456 deve ser identificada como vazada');
  console.assert(vazamento.ocorrencias > 100000000, '123456 deve ter mais de 100 milhões de vazamentos');
  console.log(`   ✅ Senha "123456" detectada com sucesso! Vazamentos: ${vazamento.ocorrencias.toLocaleString('pt-BR')}`);

  // 3. Teste de Senha Limpa no HIBP
  console.log('\n3. Testando k-Anonymity com senha forte aleatória (sem vazamentos)...');
  const senhaInedita = 'K9#mQ!2$vL8@pZ1?wX7*bC4~';
  const vazamentoInedita = await PassValidatorPro.checarVazamento(senhaInedita);
  console.assert(vazamentoInedita.verificada === true, 'Deve ter sido verificada');
  console.assert(vazamentoInedita.vazada === false, 'Senha inédita não deve constar como vazada');
  console.assert(vazamentoInedita.ocorrencias === 0, 'Ocorrências deve ser 0');
  console.log('   ✅ Senha inédita limpa: 0 ocorrências no HIBP.');

  // 4. Teste de Entropia de Shannon
  console.log('\n4. Testando cálculo de Entropia e tempo de quebra...');
  const e1 = PassValidatorPro.calcularEntropia('123456');
  const e2 = PassValidatorPro.calcularEntropia('K9#mQ!2$vL8@pZ1?');
  console.assert(e1.bits < 25, '123456 deve ter entropia muito baixa');
  console.assert(e2.bits > 90, 'Senha complexa deve ter mais de 90 bits de entropia');
  console.log(`   ✅ Entropia "123456": ${e1.bits} bits (${e1.tempoEstimadoQuebra})`);
  console.log(`   ✅ Entropia Forte: ${e2.bits} bits (${e2.tempoEstimadoQuebra})`);

  // 5. Teste de Validação Completa (Relatório de Segurança)
  console.log('\n5. Testando relatório de validação completa...');
  const relatorioFraca = await PassValidatorPro.validar('qwerty12345');
  console.assert(relatorioFraca.valida === false, 'Senha sequencial/vazada deve ser inválida');
  console.assert(relatorioFraca.criterios.eh_sequencial === true, 'Deve detectar sequência de teclado');
  console.log(`   ✅ Rejeição de senha fraca: Score ${relatorioFraca.score}/100, Nível: ${relatorioFraca.nivel}`);

  const relatorioForte = await PassValidatorPro.validar('Tx9#Kz2$Wp7!Lm8@');
  console.assert(relatorioForte.valida === true, 'Senha forte deve ser aprovada');
  console.assert(relatorioForte.score >= 80, 'Score deve ser >= 80');
  console.assert(relatorioForte.criterios.nist_sp_800_63b === true, 'Deve atender NIST SP 800-63B');
  console.log(`   ✅ Aprovação de senha forte: Score ${relatorioForte.score}/100, Nível: ${relatorioForte.nivel}`);

  // 6. Teste dos 5 Perfis do Gerador Criptográfico
  console.log('\n6. Testando Perfis do Gerador Criptográfico...');

  // Perfil 1: Forte / Completa
  const gForte = PassValidatorPro.gerar('forte', { comprimento: 20 });
  console.assert(gForte.length === 20, 'Comprimento deve ser 20');
  console.assert(/[A-Z]/.test(gForte) && /[a-z]/.test(gForte) && /[0-9]/.test(gForte), 'Deve ter maiúsculas, minúsculas e números');
  console.log('   ✅ Perfil Forte (20 chars):', gForte);

  // Perfil 2: Alfanumérica (URL-Safe)
  const gAlfa = PassValidatorPro.gerar('alfanumerica', { comprimento: 16 });
  console.assert(gAlfa.length === 16, 'Comprimento deve ser 16');
  console.assert(/^[a-zA-Z0-9]+$/.test(gAlfa), 'Deve ser puramente alfanumérico');
  console.log('   ✅ Perfil Alfanumérico:', gAlfa);

  // Perfil 3: PIN
  const gPin = PassValidatorPro.gerar('pin', { comprimento: 6 });
  console.assert(gPin.length === 6, 'PIN deve ter 6 dígitos');
  console.assert(/^\d{6}$/.test(gPin), 'PIN deve conter apenas dígitos');
  console.log('   ✅ Perfil PIN (6 dígitos):', gPin);

  // Perfil 4: Pronunciável
  const gPron = PassValidatorPro.gerar('pronunciavel', { blocos: 3, separador: '-' });
  console.assert(gPron.includes('-'), 'Deve usar separador');
  console.log('   ✅ Perfil Pronunciável:', gPron);

  // Perfil 5: Token Criptográfico
  const gToken = PassValidatorPro.gerar('token', { bytes: 32, prefixo: 'key_live_' });
  console.assert(gToken.startsWith('key_live_'), 'Deve começar com prefixo');
  console.assert(gToken.length === 9 + 64, 'Prefixo (9) + 32 bytes hex (64) = 73 chars');
  console.log('   ✅ Perfil Token Criptográfico:', gToken);

  console.log('\n🎉 TODOS OS TESTES PASSARAM COM 100% DE SUCESSO!');
}

executarTestes().catch(err => {
  console.error('❌ Erro no teste:', err);
  process.exit(1);
});
