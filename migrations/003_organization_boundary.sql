ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY organization_tenant ON organizations USING (id=nullif(current_setting('app.org_id',true),'')::uuid OR current_user='atlantik_worker') WITH CHECK (id=nullif(current_setting('app.org_id',true),'')::uuid OR current_user='atlantik_worker');
-- Narrow control-plane functions authenticate the caller again. They never return settings, members or resource content.
CREATE FUNCTION platform_organizations(credential text) RETURNS TABLE(id uuid,name text,slug text,status text,plan text,subscription_status text,created_at timestamptz) LANGUAGE sql SECURITY DEFINER SET search_path=public,pg_temp AS $$
 SELECT o.id,o.name,o.slug,o.status,o.plan,o.subscription_status,o.created_at FROM organizations o WHERE EXISTS(SELECT 1 FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.digest=credential AND s.expires_at>now() AND u.status='ACTIVE' AND u.platform_admin) ORDER BY o.created_at DESC LIMIT 100
$$;
CREATE FUNCTION platform_organization_status(credential text,target uuid,new_status text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$
BEGIN
 IF new_status NOT IN ('ACTIVE','SUSPENDED','PENDING','DELETED') OR NOT EXISTS(SELECT 1 FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.digest=credential AND s.expires_at>now() AND u.status='ACTIVE' AND u.platform_admin) THEN RAISE EXCEPTION 'Forbidden'; END IF;
 UPDATE organizations SET status=new_status WHERE id=target AND status<>'DELETED'; RETURN FOUND;
END $$;
CREATE FUNCTION platform_statistics(credential text) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=public,pg_temp AS $$
 SELECT jsonb_build_object('organizations',(SELECT jsonb_agg(r) FROM (SELECT status,count(*) FROM organizations GROUP BY status) r),'users',(SELECT count(*) FROM users),'queue',(SELECT jsonb_build_object('pending',count(*) FILTER(WHERE completed_at IS NULL AND attempts<8),'dead',count(*) FILTER(WHERE attempts>=8 AND completed_at IS NULL)) FROM outbox)) WHERE EXISTS(SELECT 1 FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.digest=credential AND s.expires_at>now() AND u.status='ACTIVE' AND u.platform_admin)
$$;
REVOKE ALL ON FUNCTION platform_organizations(text),platform_organization_status(text,uuid,text),platform_statistics(text) FROM PUBLIC;
CREATE TABLE service_heartbeats(name text PRIMARY KEY,updated_at timestamptz NOT NULL DEFAULT now());
