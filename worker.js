/**
 * worker.js
 * Cloudflare Worker Anycast para PassValidator Pro API
 * Validação de Senhas, Verificação de Vazamentos via HIBP e Gerador Multiperfil.
 *
 * @license MIT
 * @see https://github.com/clepta2/passvalidator-pro
 */

import { PassValidatorPro } from './passvalidator-pro.js';
import { STYLES_CSS, HTML_INDEX, CLIENT_JS, OZPRO_MARK_SVG } from './site-assets.js';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-api-key',
  'Access-Control-Max-Age': '86400'
};

const ipBuckets = new Map();

function checkRateLimit(ipOrKey, limit = 60, windowMs = 60000) {
  const now = Date.now();
  let entry = ipBuckets.get(ipOrKey);
  if (!entry || now > entry.resetAt) {
    entry = { count: 1, resetAt: now + windowMs };
    ipBuckets.set(ipOrKey, entry);
    if (ipBuckets.size > 10000) {
      for (const [k, v] of ipBuckets) {
        if (now > v.resetAt) ipBuckets.delete(k);
      }
    }
    return { ok: true, remaining: limit - 1, resetAt: entry.resetAt };
  }
  entry.count++;
  if (entry.count > limit) {
    return { ok: false, remaining: 0, resetAt: entry.resetAt };
  }
  return { ok: true, remaining: limit - entry.count, resetAt: entry.resetAt };
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/$/, '') || '/';

    // 1. CORS Preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    // 2. Health Check
    if (path === '/health' || path === '/status') {
      return new Response(JSON.stringify({ status: 'healthy', timestamp: new Date().toISOString() }), {
        status: 200,
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
      });
    }

    // 3. Rate Limiting
    const apiKey = request.headers.get('x-api-key') ||
                   request.headers.get('Authorization')?.replace(/^Bearer\s+/i, '') ||
                   url.searchParams.get('api_key') || '';
    const cleanKey = String(apiKey).trim();
    const isPro = Boolean(
      cleanKey && (
        cleanKey.startsWith('pas_live_') || 
        cleanKey.startsWith('pas_pro_') || 
        cleanKey.startsWith('pas_master_') || 
        cleanKey.startsWith('pnt_live_') ||
        (env && (env.API_KEY === cleanKey || env.PRO_KEY === cleanKey))
      ) && cleanKey.length >= 16
    );
    const clientIp = request.headers.get('CF-Connecting-IP') || request.headers.get('x-real-ip') || '127.0.0.1';
    const maxReqs = isPro ? 300 : 60;
    const rl = checkRateLimit(isPro ? apiKey : clientIp, maxReqs, 60000);

    if (!rl.ok && path !== '/') {
      return new Response(JSON.stringify({
        ok: false,
        error: 'Limite temporário de requisições excedido. Aguarde o período indicado.',
        retryAfterSeconds: Math.ceil((rl.resetAt - Date.now()) / 1000)
      }, null, 2), {
        status: 429,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          ...CORS_HEADERS,
          'Retry-After': String(Math.max(1, Math.ceil((rl.resetAt - Date.now()) / 1000)))
        }
      });
    }

    // 4. Rota: Gerador de Senhas
    if (path === '/api/password/generate' || path === '/api/gerar-senha') {
      const perfil = url.searchParams.get('profile') || url.searchParams.get('tipo') || 'forte';
      const comprimento = parseInt(url.searchParams.get('length') || url.searchParams.get('comprimento') || '16', 10);
      const blocos = parseInt(url.searchParams.get('blocks') || '3', 10);
      const count = Math.min(20, Math.max(1, parseInt(url.searchParams.get('count') || '1', 10)));

      const passwords = [];
      for (let i = 0; i < count; i++) {
        const pass = PassValidatorPro.gerar(perfil, { comprimento, blocos });
        passwords.push({
          password: pass,
          entropy_bits: PassValidatorPro.calcularEntropia(pass).bits,
          profile: perfil
        });
      }

      return new Response(JSON.stringify({
        ok: true,
        total: passwords.length,
        data: count === 1 ? passwords[0] : passwords
      }, null, 2), {
        status: 200,
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
      });
    }

    // 5. Rota: Validação Individual
    if (path === '/api/password/validate' || path === '/api/validar-senha') {
      let senha = '';
      let dadosUsuario = null;

      if (request.method === 'POST') {
        try {
          const body = await request.json();
          senha = body.password || body.senha || '';
          dadosUsuario = body.user_data || body.dados_usuario || null;
        } catch (_) {}
      } else if (request.method === 'GET') {
        senha = url.searchParams.get('password') || url.searchParams.get('senha') || '';
      }

      if (!senha) {
        return new Response(JSON.stringify({
          ok: false,
          error: 'Parâmetro password obrigatório via POST JSON ou query string.'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
        });
      }

      const relatorio = await PassValidatorPro.validar(senha, { dadosUsuario });
      return new Response(JSON.stringify({
        ok: true,
        data: relatorio
      }, null, 2), {
        status: 200,
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
      });
    }

    // 6. Rota: Validação em Lote (Batch)
    if ((path === '/api/password/lote' || path === '/api/password/batch') && request.method === 'POST') {
      try {
        const body = await request.json();
        const senhas = body.passwords || body.senhas || [];

        if (!Array.isArray(senhas) || senhas.length === 0) {
          return new Response(JSON.stringify({ ok: false, error: 'Array passwords obrigatório no corpo da requisição.' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
          });
        }

        const maxLote = isPro ? 100 : 10;
        if (senhas.length > maxLote) {
          return new Response(JSON.stringify({
            ok: false,
            error: `Limite de lote excedido (${senhas.length} itens). Máximo permitido: ${maxLote}.`
          }), {
            status: 413,
            headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
          });
        }

        const resultado = await PassValidatorPro.validarLote(senhas);
        return new Response(JSON.stringify({ ok: true, data: resultado }, null, 2), {
          status: 200,
          headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
        });
      } catch (err) {
        return new Response(JSON.stringify({ ok: false, error: 'JSON inválido: ' + err.message }), {
          status: 400,
          headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
        });
      }
    }

    // 7. Rota: Consulta de Vazamentos Históricos por Domínio/Provedor
    if (path === '/api/vazamentos/dominio' || path === '/api/breaches' || path === '/api/password/breaches') {
      const dominio = url.searchParams.get('domain') || url.searchParams.get('dominio') || url.searchParams.get('email') || '';
      if (!dominio) {
        return new Response(JSON.stringify({
          ok: false,
          error: 'Informe o parâmetro domain ou email (ex: /api/vazamentos/dominio?domain=adobe.com)'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
        });
      }

      const dadosVazamento = await PassValidatorPro.consultarVazamentosDominio(dominio);
      return new Response(JSON.stringify({
        ok: true,
        data: dadosVazamento
      }, null, 2), {
        status: 200,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'public, max-age=86400, s-maxage=604800',
          ...CORS_HEADERS
        }
      });
    }

    // 8. Rota: Auditoria Forense Completa de Credencial (E-mail + Senha)
    if (path === '/api/password/auditar-credencial' || path === '/api/credencial/auditar') {
      let email = '';
      let senha = '';

      if (request.method === 'POST') {
        try {
          const body = await request.json();
          email = body.email || body.usuario || '';
          senha = body.password || body.senha || '';
        } catch (_) {}
      } else {
        email = url.searchParams.get('email') || '';
        senha = url.searchParams.get('password') || url.searchParams.get('senha') || '';
      }

      if (!senha) {
        return new Response(JSON.stringify({
          ok: false,
          error: 'Informe a senha para auditar (parâmetro password).'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
        });
      }

      const parecerForense = await PassValidatorPro.auditarCredencial(email, senha);
      return new Response(JSON.stringify(parecerForense, null, 2), {
        status: 200,
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
      });
    }

    // ── ROTA: ARQUIVOS ESTÁTICOS DO SITE PRÓPRIO (TEMPLATE PONTE API MARKETPLACE) ──
    if (path === '/styles.css' || path === '/ponte-suite.css') {
      return new Response(STYLES_CSS, {
        headers: {
          ...CORS_HEADERS,
          'Content-Type': 'text/css; charset=utf-8',
          'Cache-Control': 'public, max-age=604800, s-maxage=2592000'
        }
      });
    }

    if (path === '/brand/ozpro-mark.svg') {
      return new Response(OZPRO_MARK_SVG, {
        headers: {
          ...CORS_HEADERS,
          'Content-Type': 'image/svg+xml; charset=utf-8',
          'Cache-Control': 'public, max-age=2592000, s-maxage=2592000'
        }
      });
    }

    if (path === '/passvalidator-pro.js') {
      return new Response(CLIENT_JS, {
        headers: {
          ...CORS_HEADERS,
          'Content-Type': 'application/javascript; charset=utf-8',
          'Cache-Control': 'no-cache, no-store, must-revalidate'
        }
      });
    }

    // ── ROTA: SITE PRÓPRIO OFICIAL (TEMPLATE SUÍTE PONTE / OZPRO) ──
    const acceptHeader = request.headers.get('Accept') || '';
    if ((path === '/' || path === '/app') && !acceptHeader.includes('application/json')) {
      return new Response(HTML_INDEX, {
        headers: {
          ...CORS_HEADERS,
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'public, max-age=300, s-maxage=3600'
        }
      });
    }

    // Rota Raiz: Documentação rápida JSON
    return new Response(JSON.stringify({
      api: 'PassValidator Pro API',
      status: 'online',
      version: '1.2.0',
      description: 'API de Borda Anycast de Validação de Senhas, Análise Forense de Vazamentos (HIBP) e Gerador Criptográfico.',
      endpoints: [
        { method: 'POST', path: '/api/password/validate', body: { password: 'sua_senha_aqui' } },
        { method: 'POST', path: '/api/password/auditar-credencial', body: { email: 'usuario@empresa.com', password: 'sua_senha_aqui' } },
        { method: 'GET', path: '/api/vazamentos/dominio?domain=adobe.com' },
        { method: 'GET', path: '/api/password/generate?profile=forte&length=16' },
        { method: 'POST', path: '/api/password/lote', body: { passwords: ['senha1', 'senha2'] } }
      ]
    }, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS }
    });
  }
};
