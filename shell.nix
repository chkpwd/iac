{pkgs ? import <nixpkgs> {}}:
pkgs.mkShell {
  packages = with pkgs; [terraform fluxcd packer ansible ansible-lint];
}
