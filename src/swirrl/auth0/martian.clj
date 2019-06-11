(ns swirrl.auth0.martian
  (:require [martian.clj-http :as martian-http]
            [martian.core :as martian]
            [martian.encoders :as encoders]
            [martian.interceptors :as interceptors]
            [ring.util.codec :refer [form-decode form-encode]]))

(def form-encoder
  {:encode form-encode :decode form-decode})

(def default-encoders
  (assoc (encoders/default-encoders)
         "application/x-www-form-urlencoded" form-encoder))

(defn content-type [content-type]
  {:name ::content-type
   :enter (fn [ctx]
            (assoc-in ctx [:request :headers "Content-Type"] content-type))})

(def never-coerce-response-body
  {:name ::content-type
   :enter (fn [ctx] (assoc-in ctx [:request :coerce] :never))})

(defn bearer-token [access-token]
  (let [token (str "Bearer " access-token)]
    {:name ::bearer-token
     :enter #(assoc-in % [:request :headers "Authorization"] token)}))

(defn authorize [token]
  {:name ::content-type
   :enter (fn [ctx] (assoc-in ctx [:request :headers "Authorization"] token))})

(defn unexceptional [pred]
  {:name ::unexceptional
   :enter (fn [ctx] (assoc-in ctx [:request :unexceptional-status] pred))})

(def default-interceptors
  (conj martian/default-interceptors
        never-coerce-response-body
        (interceptors/encode-body default-encoders)
        (interceptors/coerce-response default-encoders)
        martian-http/perform-request))
