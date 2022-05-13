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
            version = "0.2";

            src = self;

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
