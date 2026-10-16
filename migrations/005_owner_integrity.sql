CREATE UNIQUE INDEX organization_single_owner ON memberships(org_id) WHERE role='owner';
ALTER TABLE organizations ADD CONSTRAINT organization_owner_membership FOREIGN KEY(id,owner_id) REFERENCES memberships(org_id,user_id) DEFERRABLE INITIALLY DEFERRED;
