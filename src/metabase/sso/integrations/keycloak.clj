(ns metabase.sso.integrations.keycloak
  "OIDC login flow for the Keycloak provider in the free Metabase edition."
  (:require
   [java-time.api :as t]
   [metabase.auth-identity.core :as auth-identity]
   [metabase.request.core :as request]
   [metabase.sso.oidc.state :as oidc.state]
   [metabase.sso.providers.keycloak :as keycloak.provider]
   [metabase.sso.settings :as sso.settings]
   [metabase.system.core :as system]
   [metabase.util.i18n :refer [tru]]
   [ring.util.response :as response]))

(set! *warn-on-reflection* true)

(defn- ensure-enabled! []
  (when-not (sso.settings/keycloak-sso-enabled)
    (throw (ex-info (tru "Keycloak sign-in is not configured.") {:status-code 400}))))

(defn- callback-uri []
  (keycloak.provider/keycloak-redirect-uri))

(defn sso-initiate
  "Start Keycloak authentication and set the encrypted OIDC state cookie."
  [request]
  (ensure-enabled!)
  (let [requested-redirect (get-in request [:params :redirect])
        redirect-url (if (oidc.state/valid-redirect-url? requested-redirect)
                       requested-redirect
                       "/")
        auth-result (auth-identity/authenticate :provider/keycloak
                                                (assoc request
                                                       :redirect-uri (callback-uri)
                                                       :final-redirect redirect-url))]
    (if (= :redirect (:success? auth-result))
      (oidc.state/wrap-oidc-redirect auth-result request :provider/keycloak redirect-url
                                     {:browser-id (:browser-id request)})
      (throw (ex-info (or (:message auth-result) (tru "Failed to initiate Keycloak authentication."))
                      {:status-code 500})))))

(defn sso-callback
  "Validate the OIDC callback, link the verified subject to an existing user, and create a Metabase session."
  [request]
  (ensure-enabled!)
  (let [{:keys [code state]} (:params request)
        validation (oidc.state/validate-oidc-callback request state :provider/keycloak
                                                      {:validate-browser-id (:browser-id request)})]
    (when-not (and code state (:valid? validation))
      (throw (ex-info (or (:message validation) (tru "The Keycloak callback is incomplete or invalid."))
                      {:status-code 401})))
    (let [login-result (auth-identity/login! :provider/keycloak
                                             (merge request
                                                    (:params request)
                                                    {:code code
                                                     :state state
                                                     :oidc-nonce (:nonce validation)
                                                     :redirect-url (:redirect validation)
                                                     :redirect-uri (callback-uri)
                                                     :device-info (request/device-info request)}))]
      (if (:success? login-result)
        (let [base-response (-> (response/redirect (or (:redirect-url login-result) "/"))
                                (oidc.state/clear-oidc-state-cookie))]
          (if-let [session (:session login-result)]
            (request/set-session-cookies request base-response session
                                         (t/zoned-date-time (t/zone-id "GMT")))
            (throw (ex-info (tru "Keycloak sign-in did not create a Metabase session.") {:status-code 500}))))
        (throw (ex-info (or (:message login-result) (tru "Keycloak sign-in failed."))
                        {:status-code 401}))))))
