(ns metabase.sso.integrations.keycloak
  "OIDC login flow for the Keycloak provider in the free Metabase edition."
  (:require
   [java-time.api :as t]
   [metabase.auth-identity.core :as auth-identity]
   [metabase.auth-identity.db :as auth-identity.db]
   [metabase.request.core :as request]
   [metabase.sso.oidc.state :as oidc.state]
   [metabase.sso.providers.keycloak :as keycloak.provider]
   [metabase.sso.settings :as sso.settings]
   [metabase.system.core :as system]
   [metabase.util.i18n :refer [tru]]
   [metabase.users-rest.db :as users-rest.db]
   [ring.util.response :as response])

  (:import
   (java.nio.charset StandardCharsets)
   (java.security MessageDigest)))

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

(def ^:private keycloak-subject-pattern #"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

(defn- valid-provisioner-token? [request]
  (let [expected (System/getenv "MB_KEYCLOAK_PROVISIONER_TOKEN")
        authorization (get-in request [:headers "authorization"])
        supplied (when (and (string? authorization)
                            (.startsWith ^String authorization "Bearer "))
                   (subs authorization 7))]
    (and (string? expected)
         (>= (count expected) 32)
         (string? supplied)
         (MessageDigest/isEqual (.getBytes ^String expected StandardCharsets/UTF_8)
                                (.getBytes ^String supplied StandardCharsets/UTF_8)))))

(defn reconcile-linked-accounts
  "Reconcile active state only for Metabase users linked to the exact Keycloak subject.

  `managed-inactive` maps subjects to Metabase user IDs that this reconciler disabled previously.
  This lets us restore only our own deactivations while preserving administrator-disabled accounts."
  [{:keys [targets managed_inactive dry_run]}]
  (let [managed-inactive (into {}
                               (map (fn [[subject user-id]]
                                      [(if (keyword? subject) (name subject) subject) user-id]))
                               (or managed_inactive {}))
        dry-run (boolean dry_run)]
    (when-not (and (sequential? targets)
                   (<= (count targets) 500)
                   (map? managed-inactive)
                   (<= (count managed-inactive) 500))
      (throw (ex-info "Invalid Keycloak account reconciliation request." {:status-code 400})))
    (let [subjects (map :subject targets)]
      (when-not (= (count subjects) (count (distinct subjects)))
        (throw (ex-info "Duplicate Keycloak subjects in reconciliation request." {:status-code 400})))
      (doseq [subject subjects]
        (when-not (and (string? subject) (re-matches keycloak-subject-pattern subject))
          (throw (ex-info "Invalid Keycloak subject." {:status-code 400}))))
      (doseq [[subject user-id] managed-inactive]
        (when-not (and (string? subject)
                       (re-matches keycloak-subject-pattern subject)
                       (integer? user-id)
                       (pos-int? user-id))
          (throw (ex-info "Invalid managed-account state." {:status-code 400}))))
      (doseq [{:keys [subject active]} targets]
        (when-not (instance? Boolean active)
          (throw (ex-info "Invalid desired account state." {:status-code 400}))))
      (let [accounts
            (mapv
             (fn [{:keys [subject active]}]
               (let [identity (auth-identity.db/auth-identity-by-provider-id "keycloak" subject)
                     user-id (:user_id identity)
                     user (when user-id (auth-identity.db/user user-id))
                     user-state (when user-id (users-rest.db/user-active-type-and-sso-source user-id))
                     managed-id (get managed-inactive subject)
                     managed-before? (= managed-id user-id)]
                 (cond
                   (nil? user)
                   {:subject subject :user_id user-id :status "missing" :managed_inactive false :action "missing"}

                   (or (not (contains? #{:personal "personal"} (:type user-state))) (:is_superuser user))
                   {:subject subject :user_id user-id :status "protected" :managed_inactive false :action "protected"}

                   (and active (:is_active user-state))
                   {:subject subject :user_id user-id :status "linked" :active true :managed_inactive false :action "unchanged"}

                   (and active (not (:is_active user-state)) managed-before?)
                   (do
                     (when-not dry-run
                       (users-rest.db/update-personal-user! user-id {:is_active true}))
                     {:subject subject :user_id user-id :status "linked" :active true :managed_inactive false
                      :action (if dry-run "would_reactivate" "reactivated")})

                   (and active (not (:is_active user-state)))
                   {:subject subject :user_id user-id :status "linked" :active false :managed_inactive false
                    :action "skipped_manual_deactivation"}

                   (and (not active) (:is_active user-state))
                   (do
                     (when-not dry-run
                       (users-rest.db/update-personal-user! user-id {:is_active false}))
                     {:subject subject :user_id user-id :status "linked" :active false :managed_inactive true
                      :action (if dry-run "would_deactivate" "deactivated")})

                   managed-before?
                   {:subject subject :user_id user-id :status "linked" :active false :managed_inactive true
                    :action "unchanged"}

                   :else
                   {:subject subject :user_id user-id :status "linked" :active false :managed_inactive false
                    :action "skipped_manual_deactivation"})))
             targets)
            counts (frequencies (map :action accounts))]
        {:matched (count (filter #(= "linked" (:status %)) accounts))
         :counts counts
         :accounts accounts}))))

(defn keycloak-account-reconciliation [body request]
  (when-not (valid-provisioner-token? request)
    (throw (ex-info "Not authorized." {:status-code 403})))
  (reconcile-linked-accounts body))
