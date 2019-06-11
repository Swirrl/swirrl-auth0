(ns swirrl.auth0.jwt
  (:require [cheshire.core :as json])
  (:import com.auth0.jwt.algorithms.Algorithm
           [com.auth0.jwt.exceptions InvalidClaimException
            JWTVerificationException TokenExpiredException]
           com.auth0.jwt.JWT
           java.util.Base64))

(defn decode [jwt]
  (.decodeJwt (JWT.) jwt))

(defn pub-key [jwk jwt]
  (-> jwk (.get (.getKeyId (decode jwt))) .getPublicKey))

(defn decode-part [s]
  (-> (.decode (Base64/getDecoder) s)
      (String.  "UTF-8")
      (json/parse-string keyword)))

(defn verify-token [jwk iss aud jwt] ;; throws if not verified
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
                  (.build))
          tok (.verify ver jwt)]
      {:status ::token-verified
       :header (-> tok .getHeader decode-part)
       :payload (-> tok .getPayload decode-part)})
    (catch TokenExpiredException e
      {:status ::token-expired :msg (.getMessage e)})
    (catch InvalidClaimException e
      {:status ::claim-invalid :msg (.getMessage e)})
    (catch JWTVerificationException e
      {:status ::token-invalid :msg (.getMessage e)})))
