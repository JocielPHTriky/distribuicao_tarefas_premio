-- Implantação autorizada pelo usuário; não modifica registros existentes.
SET LOCAL lock_timeout = '5s';
ALTER TABLE public.perfis_usuarios DROP CONSTRAINT perfis_usuarios_perfil_check;
ALTER TABLE public.perfis_usuarios ADD CONSTRAINT perfis_usuarios_perfil_check
  CHECK (perfil IN ('Admin','Analista','Auditor')) NOT VALID;
ALTER TABLE public.perfis_usuarios VALIDATE CONSTRAINT perfis_usuarios_perfil_check;

DROP POLICY acesso_publico_base_cnpj ON public.base_cnpj;
DROP POLICY acesso_publico_tarefas ON public.tarefas;
DROP POLICY acesso_publico_usuarios ON public.usuarios;
REVOKE ALL PRIVILEGES ON public.base_cnpj, public.tarefas, public.usuarios, public.perfis_usuarios FROM anon;

ALTER POLICY base_cnpj_select_analista ON public.base_cnpj
USING (
  lower(coalesce(analista_email,'')) = lower(coalesce((select auth.jwt()->>'email'),''))
  AND EXISTS (
    SELECT 1 FROM public.perfis_usuarios p
    WHERE p.auth_user_id = (select auth.uid()) AND p.ativo
      AND p.perfil IN ('Analista','Auditor')
  )
);
ALTER POLICY base_cnpj_update_analista ON public.base_cnpj
USING (
  lower(coalesce(analista_email,'')) = lower(coalesce((select auth.jwt()->>'email'),''))
  AND EXISTS (
    SELECT 1 FROM public.perfis_usuarios p
    WHERE p.auth_user_id = (select auth.uid()) AND p.ativo
      AND p.perfil IN ('Analista','Auditor')
  )
)
WITH CHECK (
  lower(coalesce(analista_email,'')) = lower(coalesce((select auth.jwt()->>'email'),''))
  AND EXISTS (
    SELECT 1 FROM public.perfis_usuarios p
    WHERE p.auth_user_id = (select auth.uid()) AND p.ativo
      AND p.perfil IN ('Analista','Auditor')
  )
);

CREATE FUNCTION public.proteger_edicao_atividade_operacional()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public, auth
AS $function$
BEGIN
  -- Mantém operações administrativas e integrações de backend existentes.
  IF current_user = 'authenticated' AND NOT public.is_admin() THEN
    IF (to_jsonb(NEW) - ARRAY['status','observacao','data_atualizacao'])
       IS DISTINCT FROM
       (to_jsonb(OLD) - ARRAY['status','observacao','data_atualizacao']) THEN
      RAISE EXCEPTION 'Perfil operacional pode alterar somente status e observação de suas atividades.'
        USING ERRCODE = '42501';
    END IF;
  END IF;
  RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION public.proteger_edicao_atividade_operacional() FROM PUBLIC;
CREATE TRIGGER proteger_edicao_atividade_operacional
BEFORE UPDATE ON public.base_cnpj
FOR EACH ROW EXECUTE FUNCTION public.proteger_edicao_atividade_operacional();
