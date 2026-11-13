(ns metabase.sso.providers.keycloak-test
  (:require
   [clojure.test :refer :all]
   [metabase.auth-identity.core :as auth-identity]
   [metabase.auth-identity.db :as auth-identity.db]
   [metabase.auth-identity.provider :as provider]
   [metabase.config.core :as config]
   [metabase.sso.oidc.discovery :as oidc.discovery]
   [metabase.sso.oidc.http :as oidc.http]
   [metabase.sso.oidc.tokens :as oidc.tokens]
   [metabase.sso.settings :as sso.settings]
   [metabase.sso.providers.keycloak]
   [metabase.test :as mt]
   [metabase.test.fixtures :as fixtures]))

(use-fixtures :once (fixtures/initialize :db :test-users))

(deftest keycloak-provider-hierarchy-test
  (testing "Keycloak is a normal auth provider and does not inherit user provisioning"
    (is (auth-identity/isa? :provider/keycloak ::provider/provider))
    (is (not (auth-identity/isa? :provider/keycloak ::provider/create-user-if-not-exists)))))

(deftest keycloak-links-existing-user-without-changing-password-test
  (mt/with-temp [:model/User user {:email "keycloak-link@example.com"}]
    (let [user-id (:id user)]
      (auth-identity/set-password! user-id "StrongPassword123!")
      (let [password-identity-before (auth-identity.db/auth-identity user-id "password")
            result (with-redefs [provider/authenticate
                                 (fn [_provider _request]
                                   {:success? true
                                    :provider-id "keycloak-subject-1"
                                    :user-data {:email "keycloak-link@example.com"}})]
                     (auth-identity/login! :provider/keycloak {}))]
        (is (:success? result))
        (is (= user-id (get-in result [:user :id])))
        (is (= "keycloak-subject-1"
               (:provider_id (auth-identity.db/auth-identity user-id "keycloak"))))
        (is (= password-identity-before (auth-identity.db/auth-identity user-id "password")))
        (is (some? (:session result)))))))

(deftest keycloak-uses-prelinked-subject-with-unverified-or-changed-email-test
  (mt/with-temp [:model/User user {:email "existing-metabase@example.com"}]
    (let [subject "prelinked-keycloak-subject"]
      (auth-identity.db/insert-auth-identity! {:user_id (:id user)
                                               :provider "keycloak"
                                               :provider_id subject})
      (mt/with-dynamic-fn-redefs [sso.settings/keycloak-sso-enabled (constantly true)
                                  config/config-str (fn [key]
                                                      (case key
                                                        :mb-keycloak-oidc-issuer-uri
                                                        "https://keycloak.example.com/realms/test"
                                                        :mb-keycloak-oidc-client-id "metabase"
                                                        :mb-keycloak-oidc-client-secret "secret"))
                                  oidc.discovery/discover-oidc-configuration
                                  (fn [_]
                                    {:authorization_endpoint "https://keycloak.example.com/auth"
                                     :token_endpoint "https://keycloak.example.com/token"
                                     :jwks_uri "https://keycloak.example.com/jwks"})
                                  oidc.http/oidc-post
                                  (fn [_ _]
                                    {:status 200 :body {:id_token "valid-token"}})
                                  oidc.tokens/validate-id-token
                                  (fn [& _]
                                    {:valid? true
                                     :claims {:sub subject
                                              :email "different-unverified@example.com"
                                              :email_verified false}})]
        (let [result (auth-identity/authenticate :provider/keycloak
                                                 {:code "auth-code"
                                                  :state "state"
                                                  :oidc-nonce "nonce"
                                                  :redirect-uri
                                                  "https://metabase.example.com/auth/sso/keycloak/callback"})]
          (is (true? (:success? result)))
          (is (= (:id user) (:user-id result)))
          (is (= subject (:provider-id result))))))))

(deftest keycloak-does-not-allow-unverified-unlinked-subject-test
  (mt/with-dynamic-fn-redefs [sso.settings/keycloak-sso-enabled (constantly true)
                              config/config-str (fn [key]
                                                  (case key
                                                    :mb-keycloak-oidc-issuer-uri
                                                    "https://keycloak.example.com/realms/test"
                                                    :mb-keycloak-oidc-client-id "metabase"
                                                    :mb-keycloak-oidc-client-secret "secret"))
                              oidc.discovery/discover-oidc-configuration
                              (fn [_]
                                {:authorization_endpoint "https://keycloak.example.com/auth"
                                 :token_endpoint "https://keycloak.example.com/token"
                                 :jwks_uri "https://keycloak.example.com/jwks"})
                              oidc.http/oidc-post
                              (fn [_ _]
                                {:status 200 :body {:id_token "valid-token"}})
                              oidc.tokens/validate-id-token
                              (fn [& _]
                                {:valid? true
                                 :claims {:sub "unlinked-keycloak-subject"
                                          :email "unverified@example.com"
                                          :email_verified false}})]
    (let [result (auth-identity/authenticate :provider/keycloak
                                             {:code "auth-code"
                                              :state "state"
                                              :oidc-nonce "nonce"
                                              :redirect-uri
                                              "https://metabase.example.com/auth/sso/keycloak/callback"})]
      (is (false? (:success? result)))
      (is (= :email-not-verified (:error result))))))

(deftest keycloak-does-not-provision-unmatched-user-test
  (let [result (with-redefs [provider/authenticate
                             (fn [_provider _request]
                               {:success? true
                                :provider-id "unmatched-subject"
                                :user-data {:email "no-metabase-user@example.com"}})]
                 (auth-identity/login! :provider/keycloak {}))]
    (is (false? (:success? result)))
    (is (= :account-not-found (:error result)))))

(deftest keycloak-subject-cannot-be-linked-to-a-second-user-test
  (mt/with-temp [:model/User first-user  {:email "first-keycloak-user@example.com"}
                 :model/User second-user {:email "second-keycloak-user@example.com"}]
    (auth-identity.db/insert-auth-identity! {:user_id (:id first-user)
                                             :provider "keycloak"
                                             :provider_id "already-linked-subject"})
    (let [result (with-redefs [provider/authenticate
                               (fn [_provider _request]
                                 {:success? true
                                  :provider-id "already-linked-subject"
                                  :user-data {:email "second-keycloak-user@example.com"}})]
                   (auth-identity/login! :provider/keycloak {}))]
      (is (false? (:success? result)))
      (is (= :keycloak-account-already-linked (:error result)))
      (is (nil? (auth-identity.db/auth-identity (:id second-user) "keycloak"))))))
