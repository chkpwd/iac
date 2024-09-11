{pkgs ? import <nixpkgs> {}}:
pkgs.mkShell {
  packages = with pkgs; [terraform packer ansible ansible-lint];
}
