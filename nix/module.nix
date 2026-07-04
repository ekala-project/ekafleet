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
            "${pkgs.ekafleet}/bin/ekafleet server --data-dir ${cfg.dataDir} --token ${cfg.token} ${peersArg}"
          else
            "${pkgs.ekafleet}/bin/ekafleet agent --join ${cfg.serverAddr} --token ${cfg.token} --data-dir ${cfg.dataDir}";

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
