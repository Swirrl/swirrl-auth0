(ns swirrl.auth0.client
  (:require [cheshire.core :as json]
            [clj-http.client :refer [unexceptional-status?]]
            [clj-time.core :as time]
            [clojure.set :as set]
            [clojure.walk :as walk]
            [integrant.core :as ig]
            [martian.core :as martian]
            [ring.util.codec :refer [form-encode]]
            [swirrl.auth0.martian :refer :all])
  (:import com.auth0.jwk.JwkProviderBuilder
           java.util.Base64
           java.util.concurrent.TimeUnit))

(deftype Auth0Client [martian opts]
  clojure.lang.ILookup
  (valAt [this k] (.valAt this k nil))
  (valAt [this k default]
    (case k
      :martian martian
      :opts opts
      (or (.valAt opts k nil) (.valAt martian k default)))))

(defn client? [x]
  (instance? Auth0Client x))

(defn client [endpoint swagger {:as opts}]
  (-> endpoint
      (martian/bootstrap-swagger swagger {:interceptors default-interceptors})
      (->Auth0Client (assoc opts
                            :client-id-token (atom nil)
                            :leeway (get opts :leeway 0)))))

(defn intercept
  {:style/indent :defn}
  [{:keys [martian opts]} & interceptors]
  (-> (apply update martian :interceptors conj interceptors)
      (->Auth0Client opts)))

(defn get-client-id-token [auth0]
  (-> auth0
      (intercept (content-type "application/x-www-form-urlencoded"))
      (martian/response-for :oauth-token
                            {:grant-type "client_credentials"
                             :client-id (:client-id auth0)
                             :client-secret (:client-secret auth0)
                             :audience (:aud auth0)})
      (:body)
      (vary-meta assoc :timestamp (time/now))))

(defn client-id-token-expiry-time
  "Takes auth0 client and returns clj-time/date-time or nil.
  The returned date-time marks the instant the token expires."
  [auth0]
  (let [{expires-in :expires_in :as token} (some-> auth0 :client-id-token deref)
        updated-at (or (-> token meta :timestamp)
                       (time/now))]
    (when expires-in
      (time/plus updated-at (time/seconds expires-in)))))

(defn get-auth-code-token [auth0 auth-code aud]
  (-> auth0
      (martian/response-for :oauth-token
                            {:grant-type "authorization_code"
                             :code auth-code
                             :client-id (:client-id auth0)
                             :client-secret (:client-secret auth0)
                             :redirect-uri (:redirect-uri auth0)
                             :audience aud})
      (:body)))

(defn login-uri
  [auth0 state & {:keys [prompt redirect-uri response-type response-mode scope]}]
  (-> {:state state
       :client_id (:client-id auth0)
       :protocol "oauth2"
       :response_type (or response-type "code")
       :redirect_uri (or redirect-uri (:redirect-uri auth0))
       :audience (:aud auth0)
       :scope (or scope "openid profile email")}
      (cond-> prompt (assoc :prompt prompt))
      (cond-> response-mode (assoc :response_mode response-mode))
      (form-encode)
      (->> (str (martian/url-for auth0 :authorize) \?))))

(defn logout-uri [auth0 return-to]
  (->> {:returnTo return-to
        :client_id (:client-id auth0)}
       (form-encode)
       (str (martian/url-for auth0 :logout) \?)))

(defn nonce []
  (let [bs (byte-array 32)]
    (.nextBytes (java.security.SecureRandom.) bs)
    (-> (Base64/getUrlEncoder) .withoutPadding (.encodeToString bs))))

(defn re-authenticate-redirect [auth0 & {:keys [prompt]}]
  (let [state (nonce)]
    {:status 302
     :headers {"Location" (login-uri auth0 state :prompt prompt)}
     :session {:state state}}))

(defn set-client-id-token! [auth0]
  (reset! (:client-id-token auth0) (get-client-id-token auth0))
  auth0)

(defn client-id-token? [auth0]
  (-> auth0 :client-id-token deref boolean))

(defn with-client-id-token [auth0]
  (when-not (client-id-token? auth0)
    (set-client-id-token! auth0))
  (intercept auth0 (bearer-token (:access_token @(:client-id-token auth0)))))

(defn unauthenticated? [response]
  (contains? #{401 403} (:status response)))

(def unexceptional?
  (set/union #{401 403} unexceptional-status?))

(defn ^:deprecated api
  ([auth0 route-name]
   (api auth0 route-name {}))
  ([auth0 route-name params]
   (letfn [(call [client attempts]
             (when (pos? attempts)
               (let [response (-> client
                                  (with-client-id-token)
                                  (intercept (unexceptional unexceptional?))
                                  (martian/response-for route-name params))]
                 (if (unauthenticated? response)
                   (-> client set-client-id-token! (recur (dec attempts)))
                   (:body response)))))]
     (let [api-opts (assoc (:opts auth0) :aud (:api auth0))
           api-client (->Auth0Client (:martian auth0) api-opts)]
       (call api-client 1)))))


(defmethod ig/init-key :swirrl.auth0/client
  [_ {:keys [endpoint swagger-json] :as opts}]
  (when (and endpoint swagger-json)
    (client endpoint (json/parse-string (slurp swagger-json) keyword) opts)))

(defmethod ig/init-key :swirrl.auth0/jwk [_ {:keys [endpoint] :as opts}]
  (-> (JwkProviderBuilder. endpoint)
      (.cached 10 24 TimeUnit/HOURS)
      (.rateLimited 10 1 TimeUnit/MINUTES)
      (.build)))
