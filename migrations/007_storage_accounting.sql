ALTER TABLE usage_events DROP CONSTRAINT usage_events_quantity_check;
ALTER TABLE usage_events ADD CONSTRAINT usage_event_quantity_valid CHECK(quantity<>0 AND (quantity>0 OR metric='storage'));
-- Storage measures retained bytes across billing periods, not a renewable monthly allowance.
INSERT INTO usage(org_id,period,metric,quantity) SELECT org_id,date '1970-01-01','storage',sum(quantity) FROM usage WHERE metric='storage' GROUP BY org_id ON CONFLICT(org_id,period,metric) DO UPDATE SET quantity=excluded.quantity;
DELETE FROM usage WHERE metric='storage' AND period<>date '1970-01-01';
