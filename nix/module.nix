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
  imports = [
    (lib.mkRemovedOptionModule [
      "services"
      "ekafleet"
      "agent"
      "workloadApiSocketPath"
    ] "The agent serves the SPIFFE Workload API itself at /run/ekafleet/workload-api.sock.")
  ];

  options.services.ekafleet = {
    server = {
      enable = lib.mkEnableOption "ekafleet server (control plane)";

      package = lib.mkOption {
        type = lib.types.package;
        default = pkgs.ekaos-fleet;
        description = "The ekafleet package to use.";
      };

      tokenFile = lib.mkOption {
        type = lib.types.str;
        example = "/run/keys/ekafleet-admin-token";
        description = ''
          File holding the initial admin bearer token (e.g. from
          `ekafleet token create`). Passed to the server with systemd
          `LoadCredential`, so it may be readable by root only; it never
          appears in the Nix store or on the command line.
        '';
      };

      dataDir = lib.mkOption {
        type = lib.types.path;
        default = "/var/lib/ekafleet-server";
        description = ''
          Data directory for control-plane state. Must be under `/var/lib/`
          (it is the unit's systemd StateDirectory). Kept separate from the
          agent's `/var/lib/ekafleet` so a combined server+agent node never
          shares key material between the two users.
        '';
      };

      sealPassphraseFile = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "/run/keys/ekafleet-seal";
        description = ''
          File holding the passphrase that seals key material at rest (CA
          keys in the CA signer; fleet key and Raft keys in the server).
          Passed to both units with systemd `LoadCredential`, so it may be
          readable by root only. When `null`, keys are written unsealed and
          a warning is logged.
        '';
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
        default = "/run/ekafleet-ca/ca.sock";
        description = ''
          Unix socket of the CA signer. Only members of the `ekafleet-ca`
          group (the server user) can connect.
        '';
      };

      nixEvalTimeout = lib.mkOption {
        type = lib.types.ints.unsigned;
        default = 120;
        description = ''
          Timeout in seconds for `nix eval` of the fleet configuration.
          Set to 0 to use the built-in default.
        '';
      };

      nixBuildTimeout = lib.mkOption {
        type = lib.types.ints.unsigned;
        default = 600;
        description = ''
          Timeout in seconds for `nix build`. Increase for large or
          cache-cold closures. Set to 0 to use the built-in default.
        '';
      };

      nixCopyTimeout = lib.mkOption {
        type = lib.types.ints.unsigned;
        default = 300;
        description = ''
          Timeout in seconds for `nix-copy-closure`. Set to 0 to use the
          built-in default.
        '';
      };

      nixOptions = lib.mkOption {
        type = lib.types.attrsOf lib.types.str;
        default = { };
        example = {
          substituters = "https://cache.example.org";
          "trusted-public-keys" = "cache.example.org:AAAA...";
        };
        description = ''
          Extra `nix.conf`-style options passed through to every server-side
          Nix invocation as `--option <name> <value>` (e.g. extra
          substituters, trusted public keys, or
          `allow-import-from-derivation`).
        '';
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

      nodeName = lib.mkOption {
        type = lib.types.str;
        default = config.networking.hostName;
        defaultText = lib.literalExpression "config.networking.hostName";
        description = ''
          This node's fleet name. Must match the node's `machines.<name>`
          entry in the fleet config; it is the `<name>` in the node SVID
          `spiffe://<domain>/agent/<name>`.
        '';
      };

      joinTokenFile = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "/run/keys/ekafleet-join-token";
        description = ''
          File holding a one-time join token for this node, created with
          `ekafleet token create --type agent --node <nodeName>`. Used only
          while the agent has no valid node SVID; it may be deleted after
          the first successful start. Requires `caCert`.
        '';
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

      proxyListen = lib.mkOption {
        type = lib.types.str;
        default = "0.0.0.0:8080";
        description = "Listen address for the service mesh proxy.";
      };

      keepGenerations = lib.mkOption {
        type = lib.types.ints.unsigned;
        default = 10;
        description = ''
          Number of most-recent system generations to keep after each
          activation. Older generations are deleted so long-lived fleets do
          not fill the disk. Set to 0 to disable count-based pruning.
        '';
      };

      keepGenerationsDays = lib.mkOption {
        type = lib.types.nullOr lib.types.ints.unsigned;
        default = null;
        description = ''
          Delete system generations older than this many days after each
          activation. `null` disables age-based pruning. Combined with
          `keepGenerations`, a generation is removed only if it is outside
          both bounds.
        '';
      };
    };
  };

  config = lib.mkMerge [
    # ── Server-side: ca-signer + server ──────────────────────────────
    #
    # Two static users with disjoint state:
    #   ekafleet-ca  /var/lib/ekafleet-ca (CA keys), /run/ekafleet-ca/ca.sock
    #   ekafleet     cfg.server.dataDir, connects to ca.sock via the
    #                ekafleet-ca group
    # The agent (root) owns /var/lib/ekafleet and /run/ekafleet.
    (lib.mkIf cfg.server.enable (
      let
        sealCredential = lib.optionalAttrs (cfg.server.sealPassphraseFile != null) {
          LoadCredential = [ "seal-passphrase:${cfg.server.sealPassphraseFile}" ];
        };
        sealEnv = lib.optionalAttrs (cfg.server.sealPassphraseFile != null) {
          EKAFLEET_SEAL_PASSPHRASE_FILE = "%d/seal-passphrase";
        };
        sealCredentials = lib.optional (
          cfg.server.sealPassphraseFile != null
        ) "seal-passphrase:${cfg.server.sealPassphraseFile}";
      in
      {
        assertions = [
          {
            assertion = lib.hasPrefix "/var/lib/" cfg.server.dataDir;
            message = "services.ekafleet.server.dataDir must be under /var/lib/ (got ${cfg.server.dataDir}).";
          }
        ];

        users.users.ekafleet-ca = {
          isSystemUser = true;
          group = "ekafleet-ca";
          description = "ekafleet CA signer";
        };
        users.groups.ekafleet-ca = { };

        users.users.ekafleet = {
          isSystemUser = true;
          group = "ekafleet";
          description = "ekafleet control plane";
        };
        users.groups.ekafleet = { };

        systemd.services.ekafleet-ca-signer = {
          description = "ekafleet CA signer (process-isolated)";
          wantedBy = [ "multi-user.target" ];
          after = [ "local-fs.target" ];

          serviceConfig = {
            Type = "simple";
            Restart = "on-failure";
            RestartSec = 5;

            ExecStart = "${cfg.server.package}/bin/ekafleet ca-signer --data-dir /var/lib/ekafleet-ca --domain ${cfg.server.domain} --socket ${cfg.server.caSocketPath}";
            # Only report started once the socket accepts connections, so the
            # server (ordered after this unit) never races its creation.
            ExecStartPost = "${pkgs.bash}/bin/bash -c 'for _ in $(seq 300); do [ -S ${cfg.server.caSocketPath} ] && exit 0; sleep 0.1; done; exit 1'";

            User = "ekafleet-ca";
            Group = "ekafleet-ca";
            StateDirectory = "ekafleet-ca";
            StateDirectoryMode = "0700";
            # The socket is 0660; the directory admits the group so the
            # server (a member of ekafleet-ca) can reach it.
            RuntimeDirectory = "ekafleet-ca";
            RuntimeDirectoryMode = "0750";
            UMask = "0077";

            # Maximum hardening: no network, no capabilities, restricted syscalls.
            # This process holds the CA private key and nothing else.
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
          }
          // sealCredential;

          environment = {
            RUST_LOG = "info";
          }
          // sealEnv;
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

              ExecStart = "${cfg.server.package}/bin/ekafleet server --data-dir ${cfg.server.dataDir} --listen ${cfg.server.grpcListen} --http-listen ${cfg.server.httpListen} --domain ${cfg.server.domain} --ca-socket ${cfg.server.caSocketPath} ${peersArg}";

              # The control plane does not hold the CA key (that's in ca-signer).
              User = "ekafleet";
              Group = "ekafleet";
              SupplementaryGroups = [ "ekafleet-ca" ];
              StateDirectory = lib.removePrefix "/var/lib/" cfg.server.dataDir;
              StateDirectoryMode = "0700";
              UMask = "0077";
              ProtectSystem = "strict";
              ProtectHome = true;
              PrivateTmp = true;
              PrivateDevices = true;
              NoNewPrivileges = true;
              MemoryDenyWriteExecute = true;
              RestrictNamespaces = true;
              RestrictRealtime = true;
              LoadCredential = [ "admin-token:${cfg.server.tokenFile}" ] ++ sealCredentials;
            };

          environment = {
            RUST_LOG = "info";
            EKAFLEET_TOKEN_FILE = "%d/admin-token";
            EKAFLEET_NIX_EVAL_TIMEOUT = toString cfg.server.nixEvalTimeout;
            EKAFLEET_NIX_BUILD_TIMEOUT = toString cfg.server.nixBuildTimeout;
            EKAFLEET_NIX_COPY_TIMEOUT = toString cfg.server.nixCopyTimeout;
          }
          // sealEnv
          // lib.optionalAttrs (cfg.server.nixOptions != { }) {
            EKAFLEET_NIX_OPTIONS = lib.concatStringsSep ";" (
              lib.mapAttrsToList (name: value: "${name}=${value}") cfg.server.nixOptions
            );
          };
        };
      }
    ))

    # ── Agent-side: agent (incl. SPIFFE Workload API) + proxy ────────
    (lib.mkIf cfg.agent.enable {
      assertions = [
        {
          assertion = cfg.agent.joinTokenFile == null || cfg.agent.caCert != null;
          message = "services.ekafleet.agent.joinTokenFile requires services.ekafleet.agent.caCert.";
        }
      ];

      systemd.services.ekafleet-agent = {
        description = "ekafleet data plane agent";
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];

        serviceConfig =
          let
            caCertArg = lib.optionalString (cfg.agent.caCert != null) "--ca-cert ${cfg.agent.caCert}";
            # A path, not LoadCredential: the file is typically removed once
            # the node has joined, and a missing credential would fail the unit.
            joinTokenArg = lib.optionalString (
              cfg.agent.joinTokenFile != null
            ) "--join-token-file ${lib.escapeShellArg cfg.agent.joinTokenFile}";
          in
          {
            Type = "simple";
            Restart = "on-failure";
            RestartSec = 5;

            ExecStart = "${cfg.agent.package}/bin/ekafleet agent --join ${cfg.agent.serverAddr} --node-name ${lib.escapeShellArg cfg.agent.nodeName} --data-dir ${cfg.agent.dataDir} ${joinTokenArg} ${caCertArg}";

            # The agent requires root for systemd unit management,
            # WireGuard, nftables, and systemd-nspawn containers. It also
            # serves the SPIFFE Workload API (world-connectable socket in
            # /run/ekafleet; every call is attested via SO_PEERCRED + cgroup).
            # The proxy, which handles untrusted network traffic, runs
            # unprivileged in its own unit.
            ProtectHome = true;
            PrivateTmp = true;
            RuntimeDirectory = "ekafleet";
            RuntimeDirectoryMode = "0755";
            RuntimeDirectoryPreserve = "yes";
          };

        environment = {
          RUST_LOG = "info";
          EKAFLEET_KEEP_GENERATIONS = toString cfg.agent.keepGenerations;
        }
        // lib.optionalAttrs (cfg.agent.keepGenerationsDays != null) {
          EKAFLEET_KEEP_GENERATIONS_DAYS = toString cfg.agent.keepGenerationsDays;
        };
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
