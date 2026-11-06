-- AI Forge — PostgreSQL Row-Level Security (RLS) Multi-Tenant Defence-in-Depth (SEC-08)
-- Enforces tenant isolation at the database engine layer using `app.current_organization_id`.

ALTER TABLE "Organization" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Organization" FORCE ROW LEVEL SECURITY;

ALTER TABLE "Workspace" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Workspace" FORCE ROW LEVEL SECURITY;

ALTER TABLE "ApprovalRequest" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "ApprovalRequest" FORCE ROW LEVEL SECURITY;

ALTER TABLE "AuditLog" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "AuditLog" FORCE ROW LEVEL SECURITY;

-- Tenant isolation policies keyed on session variable `app.current_organization_id`
CREATE POLICY tenant_isolation_organization ON "Organization"
  USING ("id" = current_setting('app.current_organization_id', true));

CREATE POLICY tenant_isolation_workspace ON "Workspace"
  USING ("organizationId" = current_setting('app.current_organization_id', true))
  WITH CHECK ("organizationId" = current_setting('app.current_organization_id', true));

CREATE POLICY tenant_isolation_approval_request ON "ApprovalRequest"
  USING ("organizationId" = current_setting('app.current_organization_id', true))
  WITH CHECK ("organizationId" = current_setting('app.current_organization_id', true));

CREATE POLICY tenant_isolation_audit_log ON "AuditLog"
  USING ("organizationId" = current_setting('app.current_organization_id', true))
  WITH CHECK ("organizationId" = current_setting('app.current_organization_id', true));

