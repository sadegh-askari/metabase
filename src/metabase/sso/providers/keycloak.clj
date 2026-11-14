(ns metabase.sso.providers.keycloak
  "Keycloak OIDC login for linked and new Metabase accounts.

  Existing users are linked by exact Keycloak subject or verified email without removing their password identity.
  New verified Keycloak identities use Metabase's standard passwordless SSO account provisioning path."
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
(auth-identity/derive! :provider/keycloak ::provider/create-user-if-not-exists)

(defn- oidc-config [request]
  (when (sso.settings/keycloak-sso-enabled)
    {:issuer-uri    (config/config-str :mb-keycloak-oidc-issuer-uri)
     :client-id     (config/config-str :mb-keycloak-oidc-client-id)
     :client-secret (config/config-str :mb-keycloak-oidc-client-secret)
     :redirect-uri  (:redirect-uri request)
     :scopes        ["openid" "email" "profile"]
     ;; Existing admin-linked subjects do not depend on mutable or unverified email claims. Unlinked
     ;; identities are still required to present a verified email before matching an account.
     :allow-unverified-email? true
     :allow-missing-email? true}))

(defn- failure [error message]
  {:success? false :error error :message message})

(methodical/defmethod auth-identity/authenticate :provider/keycloak
  [_provider request]
  (if-let [config (oidc-config request)]
    (let [result (auth-identity/authenticate :provider/oidc (assoc request :oidc-config config))]
      (if (and (:success? result) (:user-data result))
        (let [claims (:claims result)
              provider-id (:provider-id result)
              linked-identity (when (and (string? provider-id) (seq provider-id))
                                (auth-identity.db/auth-identity-by-provider-id "keycloak" provider-id))
              email-verified? (or (true? (:email_verified claims))
                                  (= "true" (:email_verified claims)))]
          (cond
            ;; An administrator can pre-link an existing account to the immutable Keycloak subject. This
            ;; association takes precedence over email, which may be unverified or later changed.
            linked-identity
            (assoc result :user-id (:user_id linked-identity))

            (and email-verified?
                 (string? (get-in result [:user-data :email]))
                 (seq (get-in result [:user-data :email])))
            (assoc-in result [:user-data :sso_source] :keycloak)

            (and (not linked-identity) email-verified?)
            (failure :email-required (tru "Keycloak must provide a verified email address for this account."))

            :else
            (failure :email-not-verified
                     (tru "Keycloak must return a verified email address for this account."))))
        result))
    (failure :keycloak-not-configured (tru "Keycloak sign-in is not configured."))))

(methodical/defmethod auth-identity/login! :provider/keycloak
  [_provider {:keys [success? user provider-id redirect-url] :as request}]
  (cond
    (not success?) request
    (not (and (string? provider-id) (seq provider-id)))
    (failure :missing-keycloak-subject (tru "Keycloak did not return a user identifier."))
    ;; New Keycloak users are created through Metabase's normal SSO provisioning path. It creates
    ;; an SSO-only account without a password identity; existing email-matched accounts still take
    ;; the linking path below and retain their local password identity.
    (nil? user)
    (next-method _provider request)
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
