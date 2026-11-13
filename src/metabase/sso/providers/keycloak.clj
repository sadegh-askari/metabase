(ns metabase.sso.providers.keycloak
  "Keycloak OIDC login for existing Metabase accounts.

  Unlike the generic OIDC provider, this provider never provisions users or updates their profile. It links a verified
  Keycloak subject to an active Metabase account with the same email, while leaving the password AuthIdentity intact."
  (:require
   [metabase.auth-identity.core :as auth-identity]
   [metabase.auth-identity.db :as auth-identity.db]
   [metabase.auth-identity.provider :as provider]
   [metabase.config.core :as config]
   [metabase.sso.providers.oidc]
   [metabase.sso.settings :as sso.settings]
   [metabase.system.core :as system]
   [metabase.util.i18n :refer [tru]]
   [methodical.core :as methodical]))

(set! *warn-on-reflection* true)

(auth-identity/derive! :provider/keycloak ::provider/provider)

(defn- oidc-config [request]
  (when (sso.settings/keycloak-sso-enabled)
    {:issuer-uri    (config/config-str :mb-keycloak-oidc-issuer-uri)
     :client-id     (config/config-str :mb-keycloak-oidc-client-id)
     :client-secret (config/config-str :mb-keycloak-oidc-client-secret)
     :redirect-uri  (:redirect-uri request)
     :scopes        ["openid" "email" "profile"]}))

(defn- failure [error message]
  {:success? false :error error :message message})

(methodical/defmethod auth-identity/authenticate :provider/keycloak
  [_provider request]
  (if-let [config (oidc-config request)]
    (let [result (auth-identity/authenticate :provider/oidc (assoc request :oidc-config config))]
      (if (and (:success? result) (:user-data result))
        (let [claims (:claims result)
              email-verified? (or (true? (:email_verified claims))
                                  (= "true" (:email_verified claims)))]
          (if email-verified?
            ;; Once linked, the stable Keycloak subject wins over an email change. The account is not rematched to a
            ;; different Metabase user just because an email address was later reassigned.
            (if-let [linked-identity (and (:provider-id result)
                                          (auth-identity.db/auth-identity-by-provider-id "keycloak"
                                                                                       (:provider-id result)))]
              (assoc result :user-id (:user_id linked-identity))
              result)
            (failure :email-not-verified
                     (tru "Keycloak must return a verified email address for this account."))))
        result))
    (failure :keycloak-not-configured (tru "Keycloak sign-in is not configured."))))

(methodical/defmethod auth-identity/login! :provider/keycloak
  [_provider {:keys [success? user provider-id redirect-url] :as request}]
  (cond
    (not success?) request
    (nil? user)
    (failure :account-not-found
             (tru "No existing Metabase account matches this Keycloak email. Contact your administrator."))
    (not (and (string? provider-id) (seq provider-id)))
    (failure :missing-keycloak-subject (tru "Keycloak did not return a user identifier."))
    :else
    (let [user-id (long (:id user))
          linked-for-user (auth-identity.db/auth-identity user-id "keycloak")
          linked-subject (auth-identity.db/auth-identity-by-provider-id "keycloak" provider-id)]
      (cond
        (and linked-subject (not= user-id (:user_id linked-subject)))
        (failure :keycloak-account-already-linked
                 (tru "This Keycloak account is already linked to another Metabase account."))

        (and linked-for-user (not= provider-id (:provider_id linked-for-user)))
        (failure :metabase-account-already-linked
                 (tru "This Metabase account is already linked to a different Keycloak account."))

        :else
        (do
          (when-not linked-for-user
            ;; No password identity or user profile fields are touched here.
            (auth-identity.db/insert-auth-identity! {:user_id user-id
                                                     :provider "keycloak"
                                                     :provider_id provider-id}))
          (assoc request
                 :success? true
                 :redirect-url (or redirect-url "/")))))))

(defn keycloak-redirect-uri
  "Return the callback URL that must be registered on the Keycloak client."
  []
  (str (system/site-url) "/auth/sso/keycloak/callback"))
