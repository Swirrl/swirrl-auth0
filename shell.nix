let
  pkgs     = import <nixpkgs> { };
  stdenv   = pkgs.stdenv;
  unstable = import (fetchTarball https://nixos.org/channels/nixos-unstable/nixexprs.tar.xz) { };
in stdenv.mkDerivation {

  name = "swirrl-auth0";

  buildInputs = [
    unstable.clojure
    unstable.leiningen
    unstable.openjdk
  ];

  AUTH0_DOMAIN    = "https://dev-kkt-m758.eu.auth0.com";
  AUTH0_AUD       = "https://pmd";
  AUTH0_CLIENT_ID = "c0XjorYWAryVMINU8bX37ufMTW2OvItT";
  AUTH0_CLIENT_SECRET = "cnjl-W-VoXUUEUexw65algxMfrE1NhkfeAVL5GbMzswoZ7dJXK98Q2-2uR_MlsdE";
}
