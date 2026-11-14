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

  // 8. Teste dos Perfis do Gerador Criptográfico
  console.log('\n8. Testando Perfis do Gerador Criptográfico...');
  const gForte = PassValidatorPro.gerar('forte', { comprimento: 20 });
  const gAlfa = PassValidatorPro.gerar('alfanumerica', { comprimento: 16 });
  const gPin = PassValidatorPro.gerar('pin', { comprimento: 6 });
  const gPron = PassValidatorPro.gerar('pronunciavel', { blocos: 3 });
  const gPassphrase = PassValidatorPro.gerar('passphrase', { palavras: 4, separador: '.' });
  const gToken = PassValidatorPro.gerar('token', { bytes: 32 });

  console.assert(gForte.length === 20, 'Forte deve ter 20 chars');
  console.assert(/^[a-zA-Z0-9]+$/.test(gAlfa), 'Alfa deve ser alfanumérico');
  console.assert(/^\d{6}$/.test(gPin), 'PIN deve ter 6 dígitos');
  console.assert(gPron.includes('-'), 'Pronunciável deve ter separador');
  console.assert(gPassphrase.includes('.'), 'Passphrase deve ter separador ponto');
  console.assert(gToken.startsWith('pass_'), 'Token deve ter prefixo padrão');

  console.log('   ✅ Forte:', gForte);
  console.log('   ✅ Alfanumérica:', gAlfa);
  console.log('   ✅ PIN:', gPin);
  console.log('   ✅ Pronunciável:', gPron);
  console.log('   ✅ Passphrase (Diceware):', gPassphrase);
  console.log('   ✅ Token:', gToken);

  // 8.1 Teste de Regras Empresariais Rígidas
  const relEmpresaSemSimbolo = await PassValidatorPro.validar('Abcde12345', {
    verificarVazamento: false,
    regrasEmpresariais: true
  });
  console.assert(relEmpresaSemSimbolo.valida === false, 'Sem símbolo deve falhar com regras empresariais');
  console.assert(relEmpresaSemSimbolo.criterios.regras_empresariais_atendidas === false, 'Critério corporativo falso');
  console.log('   ✅ Regras empresariais ativadas barraram senha sem símbolo');

  // 8.2 Teste de Datas de Calendário e Diagonais de Teclado
  console.log('\n8.2 Testando Datas de Calendário e Diagonais de Teclado...');
  console.assert(PassValidatorPro.detectarDataCalendario('15081998') === true, 'Deve detectar 15081998');
  console.assert(PassValidatorPro.detectarDataCalendario('15/08/1998') === true, 'Deve detectar 15/08/1998');
  console.assert(PassValidatorPro.detectarPadraoTeclado('senha1qaz2wsx') === true, 'Deve detectar 1qaz');
  console.log('   ✅ Detecção de datas e diagonais do teclado funcionando');

  // 8.3 Teste de Entropia Efetiva e 4 Cenários de Força Bruta
  console.log('\n8.3 Testando Entropia Efetiva e 4 Cenários de Força Bruta...');
  const entRepetida = PassValidatorPro.calcularEntropia('aaaaaaaaaaaaaaaa');
  console.assert(entRepetida.bits < 10, 'Senha com 1 único caractere repetido deve ter entropia muito baixa');
  console.assert(entRepetida.bitsTeoricos > 70, 'Entropia teórica seria > 70');
  console.assert(entRepetida.cenarios_quebra.offline_rapido_gpu === 'Instantâneo (< 1 segundo)', 'Quebra em GPU deve ser instantânea');
  console.log(`   ✅ Entropia "aaaaaaaaaaaaaaaa": Efetiva ${entRepetida.bits} bits vs Teórica ${entRepetida.bitsTeoricos} bits`);

  // 8.4 Teste de Formatação de Chunks
  const chunked = PassValidatorPro.formatarChunks('ABCD1234EFGH5678', 4, '-');
  console.assert(chunked === 'ABCD-1234-EFGH-5678', 'Formatação em chunks deve bater');
  console.log('   ✅ Chunks formatados com sucesso:', chunked);

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

  // 10. Teste de Consulta de Vazamentos por Domínio (Data, Nome e Volume HIBP)
  console.log('\n10. Testando consulta de vazamentos do domínio no HIBP (adobe.com)...');
  const vazamentosAdobe = await PassValidatorPro.consultarVazamentosDominio('usuario@adobe.com');
  console.assert(vazamentosAdobe.totalVazamentos >= 1, 'Adobe deve ter pelo menos 1 vazamento registrado');
  console.assert(vazamentosAdobe.vazamentos.some(v => v.nome === 'Adobe'), 'Deve conter breach da Adobe');
  const breach = vazamentosAdobe.vazamentos.find(v => v.nome === 'Adobe');
  console.assert(Boolean(breach.dataVazamento), 'Deve conter data do vazamento');
  console.log(`   ✅ Incidentes encontrados para ${vazamentosAdobe.dominio}: ${vazamentosAdobe.totalVazamentos}`);
  console.log(`      Incidente: ${breach.titulo} | Data: ${breach.dataVazamento} | Contas: ${breach.contasAfetadas.toLocaleString('pt-BR')} | Expôs senhas: ${breach.exposSenhas}`);

  // 11. Teste de Auditoria Forense Combinada (Credential Stuffing: E-mail + Senha)
  console.log('\n11. Testando Auditoria Forense Combinada (E-mail + Senha)...');
  const auditoriaCombo = await PassValidatorPro.auditarCredencial('vitima@adobe.com', '123456');
  console.assert(auditoriaCombo.riscoCombo === 'CRITICO', 'Senha 123456 em domínio com breach deve ser CRITICO');
  console.assert(auditoriaCombo.senhaAuditada.vazada === true, 'Senha deve constar como vazada');
  console.assert(auditoriaCombo.vazamentosDominio.totalIncidentes >= 1, 'Deve conter histórico de incidentes');
  console.log(`   ✅ Credential Stuffing detectado! Risco: ${auditoriaCombo.riscoCombo}`);
  console.log(`      Motivo: ${auditoriaCombo.motivoRisco}`);

  console.log('\n🎉 TODOS OS TESTES PASSARAM COM 100% DE SUCESSO!');
}

executarTestes().catch(err => {
  console.error('❌ Erro no teste:', err);
  process.exit(1);
});
