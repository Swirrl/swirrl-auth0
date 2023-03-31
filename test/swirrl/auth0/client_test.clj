(ns swirrl.auth0.client-test
  (:require [clojure.java.io :as io]
            [clojure.spec.alpha :as s]
            [clojure.test :as t :refer [deftest is testing]]
            [environ.core :refer [env]]
            [integrant.core :as ig]
            [swirrl.auth0.client :as sut]))

(defn auth0-system []
  (let [config {:swirrl.auth0/client
                {:swagger-json (io/resource "swirrl/auth0/swagger.json")
                 :endpoint (env :auth0-domain)
                 :client-id (env :auth0-client-id)
                 :client-secret (env :auth0-client-secret)
                 :aud (env :auth0-aud)}
                :swirrl.auth0/jwk
                {:endpoint (env :auth0-domain)}}]
    (ig/init config (keys config))))

(s/def ::access_token string?)
(s/def ::scope string?)
(s/def ::expires_in integer?)
(s/def ::token_type #{"Bearer"})
(s/def ::client-id-token
  (s/keys :req-un [::access_token ::expires_in ::token_type]))

(deftest auth0-client-test
  (testing "Client instantiation"
    (let [sys (auth0-system)
          client (:swirrl.auth0/client sys)
          jwk (:swirrl.auth0/jwk sys)]      (is (instance? swirrl.auth0.client.Auth0Client client))
      (is (instance? com.auth0.jwk.JwkProvider jwk))
      (let [token (sut/get-client-id-token client)]
        (sut/client-id-token-expiry-time client)
        (is (s/valid? ::client-id-token token))
        (is (-> token meta :timestamp)))
      
      (testing "Client remembers last refresh time"
        (sut/set-client-id-token! client)
        (is (sut/client-id-token-expiry-time client))))))

(s/def ::email string?)
(s/def ::name string?)
(s/def ::user_id string?)
(s/def ::user (s/keys :req-un [::email ::name ::user_id]))

(deftest auth0-client-api-test
  (testing "User api access"
    (let [config {:swirrl.auth0/client
                  {:swagger-json (io/resource "swirrl/auth0/swagger.json")
                   :endpoint (env :auth0-domain)
                   :client-id (env :auth0-client-id)
                   :client-secret (env :auth0-client-secret)
                   :api "https://dev-kkt-m758.eu.auth0.com/api/v2/"
                   :aud "https://dev-kkt-m758.eu.auth0.com/api/v2/"}
                  :swirrl.auth0/jwk
                  {:endpoint (env :auth0-domain)}}
          sys (ig/init config [:swirrl.auth0/client])
          client (:swirrl.auth0/client sys)]
      (let [[user] (sut/api client :users-by-email {:email "editor@swirrl.com"})]
        (is (s/valid? ::user user))))))
