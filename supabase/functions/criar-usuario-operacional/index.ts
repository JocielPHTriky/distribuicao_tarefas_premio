import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json",
    },
  });
}

function getServiceRoleKey() {
  const directKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

  if (directKey) return directKey;

  const secretKeysRaw = Deno.env.get("SUPABASE_SECRET_KEYS");

  if (secretKeysRaw) {
    try {
      const parsed = JSON.parse(secretKeysRaw);
      return parsed.service_role;
    } catch {
      return null;
    }
  }

  return null;
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return jsonResponse({ error: "Método não permitido." }, 405);
  }

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceRoleKey = getServiceRoleKey();

    if (!supabaseUrl) {
      return jsonResponse({ error: "SUPABASE_URL não configurada." }, 500);
    }

    if (!serviceRoleKey) {
      return jsonResponse({
        error: "Service Role Key não encontrada. Configure SUPABASE_SERVICE_ROLE_KEY ou use SUPABASE_SECRET_KEYS.service_role.",
      }, 500);
    }

    const authHeader = req.headers.get("Authorization") || "";
    const jwt = authHeader.replace("Bearer ", "");

    if (!jwt) {
      return jsonResponse({ error: "Usuário não autenticado." }, 401);
    }

    const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey);
    const supabaseUserClient = createClient(supabaseUrl, serviceRoleKey, {
      global: {
        headers: {
          Authorization: `Bearer ${jwt}`,
        },
      },
    });

    const { data: authData, error: authError } = await supabaseUserClient.auth.getUser(jwt);

    if (authError || !authData?.user) {
      return jsonResponse({ error: "Sessão inválida ou expirada." }, 401);
    }

    const usuarioLogadoId = authData.user.id;

    const { data: perfilAdmin, error: perfilError } = await supabaseAdmin
      .from("perfis_usuarios")
      .select("id, perfil, ativo")
      .eq("auth_user_id", usuarioLogadoId)
      .eq("ativo", true)
      .maybeSingle();

    if (perfilError) {
      return jsonResponse({ error: `Erro ao validar perfil do administrador: ${perfilError.message}` }, 500);
    }

    if (!perfilAdmin || String(perfilAdmin.perfil || "").toLowerCase() !== "admin") {
      return jsonResponse({ error: "Apenas administradores podem cadastrar usuários." }, 403);
    }

    const body = await req.json();

    const nome = String(body.nome || "").trim();
    const email = String(body.email || "").trim().toLowerCase();
    const setor = String(body.setor || "").trim();
    const perfil = String(body.perfil || "Analista").trim();
    const senha = String(body.senha || "").trim();

    if (!nome || !email || !setor || !perfil || !senha) {
      return jsonResponse({
        error: "Informe nome, e-mail, setor, perfil e senha.",
      }, 400);
    }

    if (senha.length < 6) {
      return jsonResponse({
        error: "A senha deve possuir pelo menos 6 caracteres.",
      }, 400);
    }

    if (!["Admin", "Analista", "Auditor"].includes(perfil)) {
      return jsonResponse({
        error: "Perfil inválido. Use Admin, Analista ou Auditor.",
      }, 400);
    }

    // Não sobrescrever contas existentes, senhas ou perfis inativos.
    for (const tabela of ["usuarios", "perfis_usuarios"]) {
      const { data: existente, error: lookupError } = await supabaseAdmin
        .from(tabela).select("id").eq("email", email).maybeSingle();
      if (lookupError) return jsonResponse({ error: "Não foi possível verificar o cadastro existente." }, 500);
      if (existente) return jsonResponse({ error: "E-mail já cadastrado. Nenhuma conta existente foi alterada." }, 409);
    }

    const { data: createdUser, error: createUserError } = await supabaseAdmin.auth.admin.createUser({
      email,
      password: senha,
      email_confirm: true,
      user_metadata: { nome, setor, perfil },
    });
    if (createUserError || !createdUser?.user) {
      return jsonResponse({ error: "Não foi possível criar a conta. Verifique se o e-mail já está cadastrado; nenhuma senha existente foi alterada." }, 409);
    }
    const authUserId = createdUser.user.id;

    const { error: usuariosError } = await supabaseAdmin
      .from("usuarios")
      .insert({
          nome,
          email,
          setor,
          perfil,
        });

    if (usuariosError) {
      return jsonResponse({
        error: `Conta Auth criada (${authUserId}), mas o cadastro operacional não foi concluído. Solicite revisão ao administrador antes de tentar novamente.`,
      }, 500);
    }

    const { error: perfisError } = await supabaseAdmin
      .from("perfis_usuarios")
      .insert({
          auth_user_id: authUserId,
          nome,
          email,
          setor,
          perfil,
          ativo: true,
        });

    if (perfisError) {
      return jsonResponse({
        error: `Conta Auth e registro usuarios criados (${authUserId}), mas o perfil não foi concluído. Solicite revisão ao administrador antes de tentar novamente.`,
      }, 500);
    }

    return jsonResponse({
      ok: true,
      message: "Usuário criado/sincronizado com sucesso.",
      user: {
        auth_user_id: authUserId,
        nome,
        email,
        setor,
        perfil,
      },
    });

  } catch (e) {
    return jsonResponse({
      error: e?.message || String(e),
    }, 500);
  }
});
