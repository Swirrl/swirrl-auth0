(ns swirrl.auth0.mock
  (:require [clj-time.coerce :refer [to-date]]
            [clj-time.core :as time]
            [clojure.java.io :as io]
            [integrant.core :as ig])
  (:import [com.auth0.jwk Jwk JwkProvider]
           com.auth0.jwt.algorithms.Algorithm
           com.auth0.jwt.JWT
           java.net.URI
           [java.nio.file Files Paths]))

(defn read-private-key [uri]
  (let [bytes (Files/readAllBytes (Paths/get uri))
        spec  (java.security.spec.PKCS8EncodedKeySpec. bytes)
        kf    (java.security.KeyFactory/getInstance "RSA")]
    (.generatePrivate kf spec)))

(defn read-public-key [uri]
  (let [bytes (Files/readAllBytes (Paths/get uri))
        spec  (java.security.spec.X509EncodedKeySpec. bytes)
        kf    (java.security.KeyFactory/getInstance "RSA")]
    (.generatePublic kf spec)))

(defn token [pub priv iss aud sub role]
  (let [alg (Algorithm/RSA256 pub priv)]
    (-> (JWT/create)
        (.withIssuer (str iss \/))
        (.withSubject sub)
        (.withAudience (into-array String [aud]))
        (.withExpiresAt (to-date (time/plus (time/now) (time/minutes 10))))
        (.withClaim "scope" role)
        (.sign alg))))

(defn mock-jwk [public-key]
  (reify JwkProvider
    (get [_ _]
      (proxy [Jwk] ["" "" "RSA" "" '() "" '() "" {}]
        (getPublicKey [] public-key)))))

(defmethod ig/init-key :swirrl.auth0.mock/public-key [_ {:keys [resource]}]
  (read-public-key (.toURI resource)))

(defmethod ig/init-key :swirrl.auth0.mock/private-key [_ {:keys [resource]}]
  (read-private-key (.toURI resource)))

(defmethod ig/init-key :swirrl.auth0.mock/jwk [_ {:keys [public-key]}]
  (mock-jwk public-key))
