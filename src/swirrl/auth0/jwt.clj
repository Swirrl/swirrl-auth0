(ns swirrl.auth0.jwt
  (:require [cheshire.core :as json]
            [clojure.tools.logging :as log])
  (:import com.auth0.jwt.algorithms.Algorithm
           [com.auth0.jwt.exceptions InvalidClaimException
            JWTVerificationException TokenExpiredException]
           com.auth0.jwt.JWT
           [org.apache.commons.codec.binary Base64]))

(defn decode [jwt]
  (.decodeJwt (JWT.) jwt))

(defn pub-key [jwk jwt]
  (-> jwk (.get (.getKeyId (decode jwt))) .getPublicKey))

(defn decode-part
  "Decodes a JWT part and returns parsed JSON"
  [s]
  ;;NOTE: This uses the commons-codec Base64 class instead of
  ;;java.util.base64. This is for consistency with the method the
  ;;Auth0 JWT library uses to decode token parts.
  (-> (Base64/decodeBase64 s)
      (String. "UTF-8")
      (json/parse-string keyword)))

(defn verify-token [jwk iss aud leeway jwt] ;; throws if not verified
  (try
    (let [key (pub-key jwk jwt)
          alg (Algorithm/RSA256 key nil)
          ver (-> (JWT/require alg)
                  (.withIssuer (into-array String [(str iss \/)]))
                  ;; Ensure iss is correct
                  (.withAudience (into-array String [aud]))
                  ;; Ensure aud is correct
                  (.acceptExpiresAt 0)
                  ;; Ensure token not expired
                  (.acceptLeeway leeway)
                  (.build))
          tok (.verify ver jwt)]      
      {:status ::token-verified
       :header (-> tok .getHeader decode-part)
       :payload (-> tok .getPayload decode-part)})
    (catch TokenExpiredException e
      (let [msg (.getMessage e)]
        (log/warn (str "Token expired: " msg))
        {:status ::token-expired :msg msg}))
    (catch InvalidClaimException e
      (let [msg (.getMessage e)]
        (log/warn (str "Token claims invalid: " msg))
        {:status ::claim-invalid :msg msg}))
    (catch JWTVerificationException e
      (let [msg (.getMessage e)]
        (log/warn (str "Token not verified: " msg))
        {:status ::token-invalid :msg msg}))))

(defn verified? [jwk iss aud leeway jwt]
  (-> (verify-token jwk iss aud leeway jwt) :status (= ::token-verified)))
