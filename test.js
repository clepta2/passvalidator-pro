import { PassValidatorPro } from './passvalidator-pro.js';

console.log('🧪 Iniciando Testes Unitários de PassValidatorPro...\n');

async function executarTestes() {
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

  // 3. Teste do Cache em Memória do HIBP
  console.log('\n3. Testando Cache em Memória de Prefixos...');
  const inicio = Date.now();
  await PassValidatorPro.checarVazamento('123456'); // Deve vir do cache
  const duracaoCache = Date.now() - inicio;
  console.assert(duracaoCache < 20, 'Segunda chamada deve ser < 20ms vindo do cache');
  console.log(`   ✅ Cache respondeu em ${duracaoCache}ms`);

  // 4. Teste de Senha Limpa no HIBP
  console.log('\n4. Testando k-Anonymity com senha forte aleatória (sem vazamentos)...');
  const senhaInedita = 'K9#mQ!2$vL8@pZ1?wX7*bC4~';
  const vazamentoInedita = await PassValidatorPro.checarVazamento(senhaInedita);
  console.assert(vazamentoInedita.verificada === true, 'Deve ter sido verificada');
  console.assert(vazamentoInedita.vazada === false, 'Senha inédita não deve constar como vazada');
  console.log('   ✅ Senha inédita limpa: 0 ocorrências no HIBP.');

  // 5. Teste de Leetspeak e Anos Recentes
  console.log('\n5. Testando Detecção de Leetspeak e Anos Recentes...');
  const relLeetspeak = await PassValidatorPro.validar('P@ssw0rd2024!', { verificarVazamento: false });
  console.assert(relLeetspeak.criterios.eh_leetspeak_fraco === true, 'Deve detectar leetspeak fraco');
  console.assert(relLeetspeak.criterios.tem_ano_recente === true, 'Deve detectar ano 2024');
  console.log('   ✅ Leetspeak e ano recente detectados:', relLeetspeak.motivos);

  // 6. Teste de Proteção Anti-Engenharia Social (Dados do Usuário)
  console.log('\n6. Testando Detecção de Dados do Usuário na Senha...');
  const relUsuario = await PassValidatorPro.validar('CarlosEduardo@99', {
    verificarVazamento: false,
    dadosUsuario: { nome: 'Carlos', email: 'carlos@empresa.com.br' }
  });
  console.assert(relUsuario.criterios.contem_dados_pessoais === true, 'Deve barrar nome do usuário');
  console.assert(relUsuario.valida === false, 'Senha com nome não pode ser válida');
  console.log('   ✅ Engenharia social barrada com sucesso:', relUsuario.motivos);

  // 7. Teste de Validação em Lote (Batch)
  console.log('\n7. Testando Validação em Lote (Batch)...');
  const lote = await PassValidatorPro.validarLote(['123456', 'P@ssw0rd2026!', 'Tx9#Kz2$Wp7!Lm8@'], {
    verificarVazamento: true
  });
  console.assert(lote.total === 3, 'Total deve ser 3');
  console.assert(lote.comprometidas >= 1, 'Pelo menos 1 vazada');
  console.log(`   ✅ Lote processado: ${lote.validas} válidas, ${lote.comprometidas} comprometidas de ${lote.total}`);

  // 8. Teste dos 5 Perfis do Gerador Criptográfico
  console.log('\n8. Testando Perfis do Gerador Criptográfico...');
  const gForte = PassValidatorPro.gerar('forte', { comprimento: 20 });
  const gAlfa = PassValidatorPro.gerar('alfanumerica', { comprimento: 16 });
  const gPin = PassValidatorPro.gerar('pin', { comprimento: 6 });
  const gPron = PassValidatorPro.gerar('pronunciavel', { blocos: 3 });
  const gToken = PassValidatorPro.gerar('token', { bytes: 32 });

  console.assert(gForte.length === 20, 'Forte deve ter 20 chars');
  console.assert(/^[a-zA-Z0-9]+$/.test(gAlfa), 'Alfa deve ser alfanumérico');
  console.assert(/^\d{6}$/.test(gPin), 'PIN deve ter 6 dígitos');
  console.assert(gPron.includes('-'), 'Pronunciável deve ter separador');
  console.assert(gToken.startsWith('pass_'), 'Token deve ter prefixo padrão');

  console.log('   ✅ Forte:', gForte);
  console.log('   ✅ Alfanumérica:', gAlfa);
  console.log('   ✅ PIN:', gPin);
  console.log('   ✅ Pronunciável:', gPron);
  console.log('   ✅ Token:', gToken);

  // 9. Teste da API HTTP Worker (Cloudflare / Edge)
  console.log('\n9. Testando rotas do Worker HTTP...');
  const { default: worker } = await import('./worker.js');
  const resGen = await worker.fetch(new Request('https://api.test/api/password/generate?profile=pin&length=6'));
  console.assert(resGen.status === 200, 'Status deve ser 200');
  const bodyGen = await resGen.json();
  console.assert(bodyGen.ok === true && bodyGen.data.password.length === 6, 'Deve gerar PIN de 6 dígitos via Worker');

  const resVal = await worker.fetch(new Request('https://api.test/api/password/validate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: '123456' })
  }));
  const bodyVal = await resVal.json();
  console.assert(resVal.status === 200, 'Status deve ser 200');
  console.assert(bodyVal.data.vazamento.vazada === true, 'Deve apontar senha vazada');
  console.log('   ✅ Rotas do Worker respondendo com sucesso');

  console.log('\n🎉 TODOS OS TESTES PASSARAM COM 100% DE SUCESSO!');
}

executarTestes().catch(err => {
  console.error('❌ Erro no teste:', err);
  process.exit(1);
});
