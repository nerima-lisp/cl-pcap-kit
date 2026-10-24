{
  description = "Passive libpcap capture for Common Lisp";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    cl-nix-forge = {
      url = "github:nerima-lisp/cl-nix-forge/v0.5.0";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    cl-cffi-kit = {
      url = "github:nerima-lisp/cl-cffi-kit";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    cl-weave = {
      url = "github:nerima-lisp/cl-weave/v1.4.0";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      cl-nix-forge,
      cl-cffi-kit,
      cl-weave,
      treefmt-nix,
    }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-linux"
      ];
    in
    cl-nix-forge.lib.${builtins.head systems}.mkPackageFlake {
      inherit self systems nixpkgs;

      pname = "cl-pcap-kit";
      asd = ./cl-pcap-kit.asd;
      root = ./.;
      sourceInclude = [ ./tests/fixtures/minimal.pcap ];

      meta = {
        description = "Passive libpcap capture for Common Lisp";
        homepage = "https://github.com/nerima-lisp/cl-pcap-kit";
        license = nixpkgs.lib.licenses.mit;
        platforms = nixpkgs.lib.platforms.unix;
      };

      lispDependencies = ctx: [
        cl-cffi-kit.packages.${ctx.system}.cl-cffi-kit
        (cl-nix-forge.lib.${ctx.system}.fromNixpkgsLisp {
          drv = nixpkgs.legacyPackages.${ctx.system}.sbclPackages.cffi-grovel;
          lispImplementation = "sbcl";
        })
      ];

      lispCheckDependencies = ctx: [
        cl-weave.packages.${ctx.system}.cl-weave
      ];

      packageArgs = ctx: {
        buildInputs = [ ctx.pkgs.libpcap ];
        nativeBuildInputs = [ ctx.pkgs.pkg-config ];
        nativeLibraries = [ ctx.pkgs.libpcap ];
      };

      overrideOutputs = ctx: {
        devShells.default = ctx.generated.devShells.default.overrideAttrs (old: {
          shellHook = (old.shellHook or "") + ''
            if [ -z "''${CL_PCAP_KIT_LIBRARY:-}" ]; then
              export CL_PCAP_KIT_LIBRARY="${ctx.pkgs.libpcap}/lib/${
                if ctx.pkgs.stdenv.hostPlatform.isDarwin then "libpcap.dylib" else "libpcap.so"
              }"
            fi
          '';
        });
      };

      treefmt.evalModule = treefmt-nix.lib.evalModule;
    };
}
