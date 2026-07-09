{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.ekafleet;
in
{
  options.services.ekafleet = {
    enable = lib.mkEnableOption "ekafleet fleet management";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.ekaos-fleet;
      description = "The ekafleet package to use.";
    };

    mode = lib.mkOption {
      type = lib.types.enum [
        "server"
        "agent"
      ];
      default = "agent";
      description = "Whether to run as a server (control plane) or agent (data plane).";
    };

    token = lib.mkOption {
      type = lib.types.str;
      description = "Authentication token for cluster communication.";
    };

    serverAddr = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:7400";
      description = "Server address for agent mode (ignored in server mode).";
    };

    dataDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/ekafleet";
      description = "Data directory for persistent state.";
    };

    peers = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "List of peer server addresses for HA (server mode only).";
    };

    grpcListen = lib.mkOption {
      type = lib.types.str;
      default = "0.0.0.0:7400";
      description = "gRPC listen address (server mode only).";
    };

    httpListen = lib.mkOption {
      type = lib.types.str;
      default = "0.0.0.0:7402";
      description = "HTTP API listen address (server mode only).";
    };

    domain = lib.mkOption {
      type = lib.types.str;
      default = "fleet.internal";
      description = "SPIFFE trust domain for fleet identities.";
    };

    caCert = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Path to CA certificate PEM for TLS verification (agent mode).";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.ekafleet = {
      description = "ekafleet fleet management daemon";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      serviceConfig = {
        Type = "simple";
        Restart = "on-failure";
        RestartSec = 5;
        StateDirectory = "ekafleet";

        ExecStart =
          if cfg.mode == "server" then
            let
              peersArg = lib.optionalString (cfg.peers != [ ]) "--peers ${lib.concatStringsSep "," cfg.peers}";
            in
            "${cfg.package}/bin/ekafleet server --data-dir ${cfg.dataDir} --token ${cfg.token} --listen ${cfg.grpcListen} --http-listen ${cfg.httpListen} --domain ${cfg.domain} ${peersArg}"
          else
            let
              caCertArg = lib.optionalString (cfg.caCert != null) "--ca-cert ${cfg.caCert}";
            in
            "${cfg.package}/bin/ekafleet agent --join ${cfg.serverAddr} --token ${cfg.token} --data-dir ${cfg.dataDir} ${caCertArg}";

        # Hardening
        DynamicUser = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
        ReadWritePaths = [ cfg.dataDir ];
      };

      environment = {
        RUST_LOG = "info";
      };
    };
  };
}
