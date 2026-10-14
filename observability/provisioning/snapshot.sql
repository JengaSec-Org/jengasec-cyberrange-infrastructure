BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '15s';
SET LOCAL lock_timeout = '5s';
SET LOCAL idle_in_transaction_session_timeout = '15s';
SET LOCAL timezone = 'UTC';
SELECT json_build_object(
  'captured_at', CURRENT_TIMESTAMP,
  'read_only', current_setting('transaction_read_only') = 'on',
  'tls', coalesce((SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()), false),
  'database', current_database(),
  'participants', coalesce((SELECT json_agg(row_to_json(item)) FROM (
    SELECT participant_id::text, team_id::text,
      CASE WHEN role IN ('blue_participant','red_participant','judge','infrastructure_staff') THEN role ELSE 'unknown' END AS role,
      eligible,
      CASE WHEN status IN ('pending','active','revoked','expired') THEN status ELSE 'unknown' END AS status,
      created_at, updated_at
    FROM public.participants AS source ORDER BY source.participant_id LIMIT 10001
  ) item), '[]'::json),
  'teams', coalesce((SELECT json_agg(row_to_json(item)) FROM (
    SELECT team_id::text,
      CASE WHEN category IN ('application','ai') THEN category ELSE 'unknown' END AS category,
      CASE WHEN side IN ('blue','red') THEN side ELSE 'unknown' END AS side,
      created_at
    FROM public.teams AS source ORDER BY source.team_id LIMIT 10001
  ) item), '[]'::json),
  'allocations', coalesce((SELECT json_agg(row_to_json(item)) FROM (
    SELECT allocation_id::text, participant_id::text, host(vpn_address) AS vpn_address,
      CASE WHEN interface_name ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$' THEN interface_name ELSE NULL END AS interface_name,
      CASE WHEN status IN ('reserved','active','revoked','expired') THEN status ELSE 'unknown' END AS status,
      allocated_at, last_changed_at
    FROM public.vpn_allocations AS source ORDER BY source.allocation_id LIMIT 10001
  ) item), '[]'::json),
  'targets', coalesce((SELECT json_agg(row_to_json(item)) FROM (
    SELECT target_id::text, owner_team_id::text,
      CASE WHEN category IN ('application','ai','infrastructure') THEN category ELSE 'unknown' END AS category,
      CASE WHEN length(namespace) <= 63 AND namespace ~ '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$' THEN namespace ELSE NULL END AS namespace,
      CASE WHEN length(endpoint) <= 45 AND (endpoint ~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' OR endpoint ~ '^[0-9A-Fa-f:]{2,45}$') THEN endpoint ELSE NULL END AS endpoint_ip,
      CASE WHEN lower(permitted_protocol) IN ('tcp','udp','icmp','icmpv6','sctp','any') THEN lower(permitted_protocol) ELSE 'unknown' END AS protocol,
      CASE WHEN cardinality(permitted_ports) <= 64 THEN permitted_ports ELSE NULL END AS ports,
      enabled
    FROM public.targets AS source ORDER BY source.target_id LIMIT 10001
  ) item), '[]'::json),
  'assignments', coalesce((SELECT json_agg(row_to_json(item)) FROM (
    SELECT assignment_id::text, red_team_id::text, target_id::text, starts_at, ends_at
    FROM public.target_assignments AS source ORDER BY source.assignment_id LIMIT 10001
  ) item), '[]'::json),
  'event_windows', coalesce((SELECT json_agg(row_to_json(item)) FROM (
    SELECT event_id::text, starts_at, ends_at
    FROM public.event_config AS source ORDER BY source.event_id LIMIT 10001
  ) item), '[]'::json)
);
ROLLBACK;
