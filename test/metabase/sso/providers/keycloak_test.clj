(ns metabase.sso.providers.keycloak-test
  (:require
   [clojure.test :refer :all]
   [metabase.auth-identity.core :as auth-identity]
   [metabase.auth-identity.db :as auth-identity.db]
   [metabase.auth-identity.provider :as provider]
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
