import { KeycloakButton } from "metabase/auth/components/KeycloakButton";
import { PLUGIN_AUTH_PROVIDERS } from "metabase/plugins";
import MetabaseSettings from "metabase/utils/settings";

PLUGIN_AUTH_PROVIDERS.providers.push((providers) => {
  if (!MetabaseSettings.isKeycloakSsoEnabled()) {
    return providers;
  }

  return [{ name: "keycloak", Button: KeycloakButton }, ...providers];
});
