(ns server
  (:require [cheshire.core :as json]
            [clj-http.client :as http]
            [ring.middleware.params :refer [wrap-params]]
            [ring.middleware.session :refer [wrap-session]]
            [ring.util.codec :refer [form-decode form-encode]])
  (:import [com.auth0.jwk Jwk JwkProviderBuilder]
           [com.auth0.jwt JWT JWTDecoder]
           com.auth0.jwt.algorithms.Algorithm
           java.security.interfaces.RSAPublicKey
           java.util.Base64
           java.util.concurrent.TimeUnit))

(def domain "https://dev-kkt-m758.eu.auth0.com/")
(def client-id "7klE25HUY333vTEx7rM1dmsnO6vHkaSG")
(def client-secret "QYoWNwf11dzWNh6XYd3jH8-j5j8r36UKuoFgrPakE_aw_Gy_EwWSppvqSULRICY4")
(def redirect-uri "http://localhost:3000/auth/callback")
(def audience "https://pmd")

(defn jwk [uri]
  (-> (JwkProviderBuilder. uri)
      (.cached 10 24 TimeUnit/HOURS)
      (.rateLimited 10 1 TimeUnit/MINUTES)
      (.build)))

(defn decode-part [s]
  (-> (.decode (Base64/getDecoder) s)
      (String. "UTF-8")
      (json/parse-string keyword)))

(defn decode [jwt]
  (.decodeJwt (JWT.) jwt))

(defn pub-key [jwt]
  (-> domain jwk (.get (.getKeyId (decode jwt))) .getPublicKey))

(defn verify-token [jwt audience] ;; throws if not verified
  (let [key (pub-key jwt)
        alg (Algorithm/RSA256 key nil)
        ver (-> (JWT/require alg)
                (.withIssuer (into-array String [domain]))
                ;; Ensure iss is correct
                (.withAudience (into-array String [audience]))
                ;; Ensure audience is correct
                (.acceptExpiresAt 0)
                ;; Ensure token not expired
                (.build))
        tok (.verify ver jwt)]
    {:header (-> tok .getHeader decode-part)
     :payload (-> tok .getPayload decode-part)}))

(defn get-auth-code-token [auth-code]
  (http/post (str domain "oauth/token")
             {:form-params
              {:grant_type "authorization_code"
               :code auth-code
               :client_id client-id
               :client_secret client-secret
               :redirect_uri redirect-uri
               :audience audience}}))

(defn login-uri [state & {:keys [prompt]}]
  (-> {:state state
       :client_id client-id
       :protocol "oauth2"
       :response_type "code"
       :redirect_uri redirect-uri
       :audience audience
       :scope "openid profile email"}
      (cond-> prompt (assoc :prompt prompt))
      (form-encode)
      (->> (str domain "authorize" \?))))

(defn login-handler [request]
  (let [bs    (byte-array 32)
        _     (.nextBytes (java.security.SecureRandom.) bs)
        state (-> (Base64/getUrlEncoder) .withoutPadding (.encodeToString bs))]
    {:status 200
     :headers {"Content-Type" "text/html"}
     :body (str "<a href=\"" (login-uri state :prompt "none") "\">login</a>")
     :session {:state state}}))

(defn auth-handler
  [{{:strs [error code state]} :query-params :as request}]
  (cond (= error "login_required") ;; user not logged in, or using dev-keys
        {:status 302
         :headers {"Location" (login-uri state)}}
        (= error "consent_required")
        {:status 302
         :headers {"Location" (login-uri state :prompt "consent")}}
        (= error "access_denied")
        {:status 302
         :headers {"Location" "/login"}}
        (= state (-> request :session :state))
        (let [response (get-auth-code-token code)
              {:keys [access_token id_token]}
              (-> (:body response)
                  (json/parse-string keyword)
                  (update :access_token verify-token audience)
                  (update :id_token verify-token client-id))]
          (println (:body response))
          (clojure.pprint/pprint access_token)
          (clojure.pprint/pprint id_token)
          {:status 200
           :headers {"Content-Type" "text/plain"}
           :body "See console"})
        :else
        {:status 401 :body "Not authenticated"}))

(defn handler [{:keys [uri] :as request}]
  (case uri
    "/login"         (login-handler request)
    "/auth/callback" (auth-handler  request)
    {:status 404 :body "Not found."}))

(defonce server (atom nil))

(defonce app
  (-> handler wrap-params wrap-session))

(require '[ring.adapter.jetty :as jetty])

(defn -main [& args]
  (jetty/run-jetty #'app {:port 3000 :join? true}))

(comment

  (reset! server (jetty/run-jetty #'app {:port 3000 :join? false}))
  (.stop @server)

  )
