(ns metabase.sso.api.keycloak
  "Public routes for Keycloak authentication."
  (:require
   [metabase.api.macros :as api.macros]
   [metabase.sso.integrations.keycloak :as keycloak]))

#_{:clj-kondo/ignore [:metabase/validate-defendpoint-has-response-schema]}
(api.macros/defendpoint :get "/"
  "Start Keycloak sign-in."
  [_route-params _query-params _body request]
  (keycloak/sso-initiate request))

#_{:clj-kondo/ignore [:metabase/validate-defendpoint-has-response-schema]}
(api.macros/defendpoint :get "/callback"
  "Handle the Keycloak OIDC callback."
  [_route-params _query-params _body request]
  (keycloak/sso-callback request))

(def ^{:arglists '([request respond raise])} routes
  "`/auth/sso/keycloak` routes."
  (api.macros/ns-handler *ns*))
