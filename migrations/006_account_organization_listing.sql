CREATE FUNCTION account_organizations(credential text) RETURNS TABLE(id uuid,name text,slug text,status text,role text) LANGUAGE sql SECURITY DEFINER SET search_path=public,pg_temp AS $$
 SELECT o.id,o.name,o.slug,o.status,m.role FROM sessions s JOIN users u ON u.id=s.user_id JOIN memberships m ON m.user_id=u.id JOIN organizations o ON o.id=m.org_id WHERE s.digest=credential AND s.expires_at>now() AND u.status='ACTIVE' AND o.status<>'DELETED' ORDER BY o.created_at DESC LIMIT 100
$$;
REVOKE ALL ON FUNCTION account_organizations(text) FROM PUBLIC;
