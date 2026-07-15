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
    server = {
      enable = lib.mkEnableOption "ekafleet server (control plane)";

      package = lib.mkOption {
        type = lib.types.package;
        default = pkgs.ekaos-fleet;
        description = "The ekafleet package to use.";
      };

      token = lib.mkOption {
        type = lib.types.str;
        description = "Authentication token for cluster communication.";
      };

      dataDir = lib.mkOption {
        type = lib.types.path;
        default = "/var/lib/ekafleet";
        description = "Data directory for persistent state.";
      };

      peers = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        description = "List of peer server addresses for HA.";
      };

      grpcListen = lib.mkOption {
        type = lib.types.str;
        default = "0.0.0.0:7400";
        description = "gRPC listen address.";
      };

      httpListen = lib.mkOption {
        type = lib.types.str;
        default = "0.0.0.0:7402";
        description = "HTTP API listen address.";
      };

      domain = lib.mkOption {
        type = lib.types.str;
        default = "fleet.internal";
        description = "SPIFFE trust domain for fleet identities.";
      };

      caSocketPath = lib.mkOption {
        type = lib.types.str;
        default = "/run/ekafleet/ca.sock";
        description = "Unix socket path for the CA signer.";
      };
    };

    agent = {
      enable = lib.mkEnableOption "ekafleet agent (data plane)";

      package = lib.mkOption {
        type = lib.types.package;
        default = pkgs.ekaos-fleet;
        description = "The ekafleet package to use.";
      };

      serverAddr = lib.mkOption {
        type = lib.types.str;
        description = "Server address to join.";
      };

      token = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = "Authentication token (legacy).";
      };

      dataDir = lib.mkOption {
        type = lib.types.path;
        default = "/var/lib/ekafleet";
        description = "Data directory for persistent state.";
      };

      domain = lib.mkOption {
        type = lib.types.str;
        default = "fleet.internal";
        description = "SPIFFE trust domain for fleet identities.";
      };

      caCert = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        default = null;
        description = "Path to CA certificate PEM for TLS verification.";
      };

      workloadApiSocketPath = lib.mkOption {
        type = lib.types.str;
        default = "/run/ekafleet/workload-api.sock";
        description = "Unix socket path for the Workload API.";
      };

      proxyListen = lib.mkOption {
        type = lib.types.str;
        default = "0.0.0.0:8080";
        description = "Listen address for the service mesh proxy.";
      };
    };
  };

  config = lib.mkMerge [
    # ── Server-side: ca-signer + server ──────────────────────────────
    (lib.mkIf cfg.server.enable {
      systemd.services.ekafleet-ca-signer = {
        description = "ekafleet CA signer (process-isolated)";
        wantedBy = [ "multi-user.target" ];
        after = [ "local-fs.target" ];

        serviceConfig = {
          Type = "simple";
          Restart = "on-failure";
          RestartSec = 5;

          ExecStart = "${cfg.server.package}/bin/ekafleet ca-signer --data-dir ${cfg.server.dataDir} --domain ${cfg.server.domain} --socket ${cfg.server.caSocketPath}";

          # Maximum hardening: no network, no capabilities, restricted syscalls.
          # This process holds the CA private key and nothing else.
          DynamicUser = true;
          StateDirectory = "ekafleet";
          PrivateNetwork = true;
          CapabilityBoundingSet = "";
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          PrivateDevices = true;
          RestrictNamespaces = true;
          RestrictRealtime = true;
          IPAddressDeny = "any";
          ReadWritePaths = [ cfg.server.dataDir ];
          RuntimeDirectory = "ekafleet";
        };

        environment.RUST_LOG = "info";
      };

      systemd.services.ekafleet-server = {
        description = "ekafleet control plane";
        wantedBy = [ "multi-user.target" ];
        after = [
          "network-online.target"
          "ekafleet-ca-signer.service"
        ];
        wants = [ "network-online.target" ];
        requires = [ "ekafleet-ca-signer.service" ];

        serviceConfig =
          let
            peersArg = lib.optionalString (
              cfg.server.peers != [ ]
            ) "--peers ${lib.concatStringsSep "," cfg.server.peers}";
          in
          {
            Type = "simple";
            Restart = "on-failure";
            RestartSec = 5;

            ExecStart = "${cfg.server.package}/bin/ekafleet server --data-dir ${cfg.server.dataDir} --token ${cfg.server.token} --listen ${cfg.server.grpcListen} --http-listen ${cfg.server.httpListen} --domain ${cfg.server.domain} --ca-socket ${cfg.server.caSocketPath} ${peersArg}";

            # The control plane does not hold the CA key (that's in ca-signer).
            DynamicUser = true;
            StateDirectory = "ekafleet";
            ProtectSystem = "strict";
            ProtectHome = true;
            PrivateTmp = true;
            PrivateDevices = true;
            NoNewPrivileges = true;
            MemoryDenyWriteExecute = true;
            RestrictNamespaces = true;
            RestrictRealtime = true;
            ReadWritePaths = [ cfg.server.dataDir ];
            RuntimeDirectory = "ekafleet";
          };

        environment.RUST_LOG = "info";
      };
    })

    # ── Agent-side: agent + workload-api + proxy ─────────────────────
    (lib.mkIf cfg.agent.enable {
      systemd.services.ekafleet-agent = {
        description = "ekafleet data plane agent";
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];

        serviceConfig =
          let
            caCertArg = lib.optionalString (cfg.agent.caCert != null) "--ca-cert ${cfg.agent.caCert}";
            tokenArg = lib.optionalString (cfg.agent.token != "") "--token ${cfg.agent.token}";
          in
          {
            Type = "simple";
            Restart = "on-failure";
            RestartSec = 5;

            ExecStart = "${cfg.agent.package}/bin/ekafleet agent --join ${cfg.agent.serverAddr} --data-dir ${cfg.agent.dataDir} ${tokenArg} ${caCertArg}";

            # The agent requires root for systemd unit management,
            # WireGuard, nftables, and systemd-nspawn containers.
            # Security isolation is provided by the separate workload-api
            # and proxy processes which run unprivileged.
            ProtectHome = true;
            PrivateTmp = true;
          };

        environment.RUST_LOG = "info";
      };

      systemd.services.ekafleet-workload-api = {
        description = "ekafleet SPIFFE Workload API (process-isolated)";
        wantedBy = [ "multi-user.target" ];
        after = [ "ekafleet-agent.service" ];
        wants = [ "ekafleet-agent.service" ];

        serviceConfig = {
          Type = "simple";
          Restart = "on-failure";
          RestartSec = 5;

          ExecStart = "${cfg.agent.package}/bin/ekafleet workload-api --data-dir ${cfg.agent.dataDir} --trust-domain ${cfg.agent.domain} --socket ${cfg.agent.workloadApiSocketPath}";

          # Unprivileged: only reads SVID files written by the agent
          # and serves them over a Unix socket. No network, no root.
          DynamicUser = true;
          PrivateNetwork = true;
          CapabilityBoundingSet = "";
          NoNewPrivileges = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          PrivateDevices = true;
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RuntimeDirectory = "ekafleet";
        };

        environment.RUST_LOG = "info";
      };

      systemd.services.ekafleet-proxy = {
        description = "ekafleet service mesh proxy (process-isolated)";
        wantedBy = [ "multi-user.target" ];
        after = [ "ekafleet-agent.service" ];
        wants = [ "ekafleet-agent.service" ];

        serviceConfig = {
          Type = "simple";
          Restart = "on-failure";
          RestartSec = 5;

          ExecStart = "${cfg.agent.package}/bin/ekafleet proxy --listen ${cfg.agent.proxyListen} --trust-domain ${cfg.agent.domain} --data-dir ${cfg.agent.dataDir}";

          # Unprivileged except CAP_NET_BIND_SERVICE for ports < 1024.
          # Handles untrusted network traffic but has no access to
          # root privileges, the fleet key, or systemd units.
          DynamicUser = true;
          CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
          AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
          NoNewPrivileges = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          PrivateDevices = true;
          RestrictNamespaces = true;
          RestrictRealtime = true;
        };

        environment.RUST_LOG = "info";
      };
    })
  ];
}
