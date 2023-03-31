(ns swirrl.auth0.refresher
  "Most access tokens expire and need to be refreshed. This namespace
  lets us schedule a periodic refresh.

  See [[default-id-token-opts]] for options you can pass from config.

  The refrehs relies on the value returned by
  `swirrl.auth0.client/client-id-expiry-token`"
  (:require [clj-time.core :as time]
            [clojure.tools.logging :as log]
            [integrant.core :as ig]
            [swirrl.auth0.client :as auth0])
  (:import [java.util.concurrent
            RejectedExecutionException
            ThreadFactory 
            ScheduledThreadPoolExecutor 
            ScheduledExecutorService
            TimeUnit]))

(defn- refresh-interval
  "Returns an interval between now and expiry time.

  Note: the returned interval may be zero (e.g. when we're past the
  expiry time). See [[clj-time.core/interval]]"
  [now expiry-time]
  (if (time/after? now expiry-time)
    (time/interval now now)
    (time/interval now expiry-time)))

(defn- refresh-token!
  "Refreshes the token. Returns the expiry time of new token on success.
  Throws if request failed. `ex-data` will be tagged with one of
  the following tags: ::refresh-failed, ::no-expiry-time."
  [auth0]
  (try
    (auth0/set-client-id-token! (auth0/management-api-client auth0))
    (catch Exception ex
      (throw (ex-info "Failed to refresh token" {:tag ::refresh-failed} ex))))
  (if-let [t (auth0/client-id-token-expiry-time auth0)]
    t
    (throw (ex-info "No expiry time token" {:tag ::no-expiry-time}))))

(def ^:private default-id-token-opts
  {:initial-delay-in-seconds 0 :retry-delay-in-seconds 30})

(defn- refresher-fn
  "Schedules an auth0 id-token refresh based on expiry time cashed by
  the auth0 client (if any). Retries when refresh fails."
  [{:keys [auth0 retry-delay-in-seconds]} ^ScheduledExecutorService executor]
  (try
    (let [expiry-time (refresh-token! auth0)
          ^long interval-minutes (->> (refresh-interval (time/now) expiry-time)
                                      (time/in-minutes))]
      (log/info (format "Refreshed. New token expires in %s minutes" interval-minutes)
                {:new-expiry-time expiry-time})
      (.schedule executor
                 ^Runnable (partial refresher-fn auth0 executor) 
                 interval-minutes 
                 TimeUnit/MINUTES))
    (catch clojure.lang.ExceptionInfo ex
      (when (contains? #{:refresh-failed ::no-expiry-time} (-> ex ex-data :tag))
        (log/info ex "Failed to refresh the auth0 token. Will retry")
        (.schedule executor 
                   ^Runnable (partial refresher-fn auth0 executor)
                   retry-delay-in-seconds
                   TimeUnit/SECONDS)))
    (catch Exception ex
      (log/warn ex "Failure when refreshing auth0 client token."))))

(defmethod ig/init-key :swirrl.auth0.refresher/id-token
  [_ {:keys [auth0] :as opts}]
  (let [exec (ScheduledThreadPoolExecutor. 1 (reify ThreadFactory
                                               (newThread [_ runnable]
                                                 (Thread. runnable "id-token-refresher"))))
        {:keys [initial-delay-in-seconds]
         :as opts} (merge default-id-token-opts opts)]
    (doto exec
      ;; let's not rely on remembering what the defaults are
      (.setExecuteExistingDelayedTasksAfterShutdownPolicy false)
      (.setContinueExistingPeriodicTasksAfterShutdownPolicy false))
    (try
      (log/debug "Token already present? " (auth0/client-id-token? auth0))
      (log/info "Scheduling initial id-token fetch.")
      (.schedule exec (partial refresher-fn opts exec)
                 initial-delay-in-seconds 
                 TimeUnit/SECONDS)
      (catch RejectedExecutionException ex
        ;; we can't periodically refresh, but we should still be able
        ;; to start the system, so not rethrowing
        (log/warn ex "could not schedule auth token refreshing thread:" (ex-message ex))))
    
    exec))

(defmethod ig/halt-key! :swirrl.auth0.refresher/id-token [_ executor]
  (.shutdown executor))
