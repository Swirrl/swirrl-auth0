(ns swirrl.auth0.middleware
  (:require [clojure.spec.alpha :as s]
            [clojure.string :as string]
            [swirrl.auth0.jwt :as jwt]
            [integrant.core :as ig]
            [clojure.edn :as edn])
  (:import com.auth0.jwk.JwkProviderBuilder
           java.util.concurrent.TimeUnit))

(defn- normalize-roles [{:keys [payload] :as token} read-role]
  (when token
    (let [permissions (some-> payload :scope (string/split #" ")
                              (concat (:permissions payload)))
          roles (some->> permissions seq (map read-role) (remove nil?) set)]
      (assoc token :roles roles))))

(defn- find-header [request header]
  (->> (:headers request)
       (filter (fn [[k v]] (re-matches (re-pattern (str "(?i)" header)) k)))
       (first)
       (second)))

(defn- parse-header [request token-name]
  (some->> (find-header request "authorization")
           (re-find (re-pattern (str "^" token-name " (.+)$")))
           (second)))

(defn- access-token-request
  [request access-token jwk iss aud leeway]
  (if access-token
    (let [token (jwt/verify-token jwk iss aud leeway access-token)
          status (:status token)]
      (cond-> (assoc request :swirrl.auth0/authenticated status)
        (= ::jwt/token-verified status)
        (assoc :swirrl.auth0/access-token token)))
    request))

(defn- id-token-request
  [request id-token jwk iss aud leeway]
  (if-let [token (some->> id-token (jwt/verify-token jwk iss aud leeway))]
    (let [status (:status token)]
      (cond-> request
        (= ::jwt/token-verified status)
        (assoc :swirrl.auth0/id-token token)))
    request))

(defmethod ig/init-key :swirrl.auth0.middleware/bearer-token
  [_ {{:keys [aud iss leeway] :or {leeway 0}} :auth0 :keys [auth0 jwk] :as opts}]
  (fn [handler]
    (fn [request]
      (let [token (parse-header request "Bearer")]
        (handler (access-token-request request token jwk iss aud leeway))))))

(defmethod ig/init-key :swirrl.auth0.middleware/session-token
  [_ {{:keys [iss aud leeway client-id] :or {leeway 0}} :auth0 :keys [jwk]}]
  (fn [handler]
    (fn [{{{:keys [access_token id_token]} :auth0} :session :as request}]
      (-> request
          (access-token-request access_token jwk iss aud leeway)
          (id-token-request id_token jwk iss client-id leeway)
          (handler)))))

(defmethod ig/init-key :swirrl.auth0.middleware/normalize-roles
  [_ {:keys [role-reader] :as opts}]
  (fn [handler]
    (fn [request]
      (handler (update request :swirrl.auth0/access-token normalize-roles role-reader)))))

(defmethod ig/init-key :swirrl.auth0.middleware/dev-token
  [_ opts]
  (fn [handler]
    (fn [request]
      (handler (merge request opts)))))
