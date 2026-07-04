defmodule TamanduaServer.Repo.Migrations.SyncMobileDevicesToAgents do
  use Ecto.Migration

  def up do
    execute("""
    CREATE OR REPLACE FUNCTION set_mobile_device_endpoint_active()
    RETURNS trigger AS $$
    BEGIN
      IF NEW.platform IN ('android', 'ios') THEN
        NEW.status := 'active';
        NEW.last_seen_at := COALESCE(NEW.last_seen_at, NOW());
        NEW.enrolled_at := COALESCE(NEW.enrolled_at, NOW());
      END IF;

      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;
    """)

    execute("""
    CREATE OR REPLACE FUNCTION sync_mobile_device_agent()
    RETURNS trigger AS $$
    BEGIN
      IF NEW.platform NOT IN ('android', 'ios') THEN
        RETURN NEW;
      END IF;

      UPDATE agents
      SET
        hostname = COALESCE(NULLIF(NEW.model, ''), hostname),
        ip_address = COALESCE(NEW.ip_address, ip_address),
        os_type = NEW.platform,
        os_version = NEW.os_version,
        agent_version = NEW.agent_version,
        status = 'online',
        last_seen_at = COALESCE(NEW.last_seen_at, NOW()),
        config = COALESCE(config, '{}'::jsonb) || jsonb_build_object(
          'source', 'tamandua_mobile',
          'mobile_device_id', NEW.id,
          'mobile_device_external_id', NEW.device_id,
          'manufacturer', NEW.manufacturer,
          'model', NEW.model,
          'platform', NEW.platform,
          'user_email', NEW.user_email,
          'user_name', NEW.user_name,
          'mdm_enrolled', NEW.mdm_enrolled
        ),
        tags = ARRAY(
          SELECT DISTINCT UNNEST(
            COALESCE(tags, ARRAY[]::varchar[]) ||
            ARRAY['mobile', 'mobile_endpoint', NEW.platform]::varchar[]
          )
        ),
        updated_at = NOW()
      WHERE organization_id = NEW.organization_id
        AND machine_id = convert_to(NEW.device_id, 'UTF8');

      IF NOT FOUND THEN
        INSERT INTO agents (
          id,
          hostname,
          ip_address,
          os_type,
          os_version,
          agent_version,
          machine_id,
          status,
          last_seen_at,
          config,
          tags,
          organization_id,
          inserted_at,
          updated_at
        )
        VALUES (
          gen_random_uuid(),
          COALESCE(NULLIF(NEW.model, ''), 'mobile-' || LEFT(NEW.device_id, 12)),
          NEW.ip_address,
          NEW.platform,
          NEW.os_version,
          NEW.agent_version,
          convert_to(NEW.device_id, 'UTF8'),
          'online',
          COALESCE(NEW.last_seen_at, NOW()),
          jsonb_build_object(
            'source', 'tamandua_mobile',
            'mobile_device_id', NEW.id,
            'mobile_device_external_id', NEW.device_id,
            'manufacturer', NEW.manufacturer,
            'model', NEW.model,
            'platform', NEW.platform,
            'user_email', NEW.user_email,
            'user_name', NEW.user_name,
            'mdm_enrolled', NEW.mdm_enrolled
          ),
          ARRAY['mobile', 'mobile_endpoint', NEW.platform]::varchar[],
          NEW.organization_id,
          NOW(),
          NOW()
        );
      END IF;

      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;
    """)

    execute("""
    DROP TRIGGER IF EXISTS mobile_devices_endpoint_active_trigger ON mobile_devices;
    CREATE TRIGGER mobile_devices_endpoint_active_trigger
    BEFORE INSERT OR UPDATE ON mobile_devices
    FOR EACH ROW
    EXECUTE FUNCTION set_mobile_device_endpoint_active();
    """)

    execute("""
    DROP TRIGGER IF EXISTS mobile_devices_agent_sync_trigger ON mobile_devices;
    CREATE TRIGGER mobile_devices_agent_sync_trigger
    AFTER INSERT OR UPDATE ON mobile_devices
    FOR EACH ROW
    EXECUTE FUNCTION sync_mobile_device_agent();
    """)

    execute("""
    UPDATE mobile_devices
    SET updated_at = NOW()
    WHERE platform IN ('android', 'ios');
    """)
  end

  def down do
    execute("DROP TRIGGER IF EXISTS mobile_devices_agent_sync_trigger ON mobile_devices;")
    execute("DROP TRIGGER IF EXISTS mobile_devices_endpoint_active_trigger ON mobile_devices;")
    execute("DROP FUNCTION IF EXISTS sync_mobile_device_agent();")
    execute("DROP FUNCTION IF EXISTS set_mobile_device_endpoint_active();")
  end
end
