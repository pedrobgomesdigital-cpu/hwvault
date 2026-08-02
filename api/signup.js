// Cria contas de afiliado de forma segura (sem enviar email de confirmacao).
// Usa a chave secreta (service_role) guardada nas variaveis de ambiente do Vercel.
module.exports = async (req, res) => {
  if (req.method !== 'POST') { res.status(405).json({ error: 'Method not allowed' }); return; }
  try {
    let body = req.body;
    if (typeof body === 'string') { try { body = JSON.parse(body); } catch (e) { body = {}; } }
    body = body || {};
    const name = (body.name || '').toString().trim();
    const email = (body.email || '').toString().trim().toLowerCase();
    const password = (body.password || '').toString();
    const code = (body.code || '').toString().trim();

    if (!name || !email || !password || !code) { res.status(400).json({ error: 'Preencha todos os campos.' }); return; }
    if (password.length < 6) { res.status(400).json({ error: 'A senha precisa ter pelo menos 6 caracteres.' }); return; }

    const URL = process.env.SUPABASE_URL;
    const KEY = process.env.SUPABASE_SERVICE_ROLE;
    if (!URL || !KEY) { res.status(500).json({ error: 'Servidor nao configurado (faltam variaveis de ambiente).' }); return; }

    // 1) Valida o codigo de convite
    const chk = await fetch(URL + '/rest/v1/invite_codes?select=code&code=eq.' + encodeURIComponent(code) + '&active=eq.true', {
      headers: { apikey: KEY, Authorization: 'Bearer ' + KEY }
    });
    const rows = await chk.json();
    if (!Array.isArray(rows) || rows.length === 0) { res.status(403).json({ error: 'Codigo de convite invalido.' }); return; }

    // 2) Cria o usuario ja confirmado (sem enviar email)
    const cr = await fetch(URL + '/auth/v1/admin/users', {
      method: 'POST',
      headers: { apikey: KEY, Authorization: 'Bearer ' + KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email, password: password, email_confirm: true, user_metadata: { name: name, role: 'affiliate' } })
    });
    const out = await cr.json();
    if (!cr.ok) {
      const m = (out && (out.msg || out.message || out.error_description || out.error)) || 'Erro ao criar conta.';
      if (/registered|already|exists/i.test(m)) { res.status(409).json({ error: 'Este email ja esta cadastrado. Faca login.' }); return; }
      res.status(400).json({ error: m }); return;
    }

    res.status(200).json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Erro interno ao criar conta.' });
  }
};
