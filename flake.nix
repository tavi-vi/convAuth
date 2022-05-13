{
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          inherit (pkgs) lib buildGoModule;
        in
        {
          defaultPackage = pkgs.buildGoModule rec {
            pname = "convauth";
            version = "0.1.1";

            src = pkgs.fetchFromGitHub {
              owner  = "tavi-vi";
              repo   = "convAuth";
              rev    = "v${version}";
              sha256 = "sha256-bivp8Mo6yBGPgUs62+K2Fb4xEjfL2OnHphU28UFmu6A=";
            };

            vendorSha256 = "sha256-RhQK8YiGkiLrGUKmH+LySUJzLrMWOgBsHPh72zt0n7o=";

            meta = with lib; {
              description  = "Simple authentication server for use with nginx.";
              homepage     = "https://github.com/tavi-vi/convAuth";
              license      = lib.licenses.bsd0;
            };
          };
        }
      );
}
