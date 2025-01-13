{ pkgs ? import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-unstable.tar.gz") {} }:

let
  frida-version = "16.2.1";
  
  frida-gum-arm64e = pkgs.fetchurl {
    url = "https://github.com/frida/frida/releases/download/${frida-version}/frida-gum-devkit-${frida-version}-macos-arm64e.tar.xz";
    sha256 = "sha256-s2MdQI18JIDAXcpTeuB2Ya5HujuryygWoYcyVGwzflc=";
  };
  frida-gum-arm64 = pkgs.fetchurl {
    url = "https://github.com/frida/frida/releases/download/${frida-version}/frida-gum-devkit-${frida-version}-macos-arm64.tar.xz";
    sha256 = "sha256-waQsdewxUbZCM5RwU+dBaxw2PKCcpXhgPp4rMQGPw8U=";
  };
  frida-gum-x86_64 = pkgs.fetchurl {
    url = "https://github.com/frida/frida/releases/download/${frida-version}/frida-gum-devkit-${frida-version}-macos-x86_64.tar.xz";
    sha256 = "sha256-yStFuKny+PEPq/Pf2+T3bQtOYQuTW39CS/ili2i8yDo=";
  };
  
in
pkgs.stdenv.mkDerivation rec {
  pname = "ammonia";
  version = "0.1.0";

  dontUnpack = true;
  dontPatch = true;
  dontConfigure = true;
  dontInstall = true;
  dontFixup = true;

  nativeBuildInputs = with pkgs; [
    darwin.cctools
    clang
  ];

  buildPhase = ''
    # Create directories
    mkdir -p $out/temp/arm64e
    mkdir -p $out/temp/arm64
    mkdir -p $out/temp/x86_64

    # Extract the archives
    tar xf ${frida-gum-arm64e} -C $out/temp/arm64e
    tar xf ${frida-gum-arm64} -C $out/temp/arm64
    tar xf ${frida-gum-x86_64} -C $out/temp/x86_64

    # Check architecture of each library
    ${pkgs.darwin.cctools}/bin/lipo -info $out/temp/arm64e/libfrida-gum.a
    ${pkgs.darwin.cctools}/bin/lipo -info $out/temp/arm64/libfrida-gum.a
    ${pkgs.darwin.cctools}/bin/lipo -info $out/temp/x86_64/libfrida-gum.a

    # Rename the libraries
    mv $out/temp/arm64e/libfrida-gum.a $out/temp/arm64e/libfrida-gum-arm64e.a
    mv $out/temp/arm64/libfrida-gum.a $out/temp/arm64/libfrida-gum-arm64.a
    mv $out/temp/x86_64/libfrida-gum.a $out/temp/x86_64/libfrida-gum-x86_64.a

    # Create FAT library with all architectures (arm64e, arm64, x86_64)
    ${pkgs.darwin.cctools}/bin/lipo -create \
      $out/temp/arm64e/libfrida-gum-arm64e.a \
      $out/temp/arm64/libfrida-gum-arm64.a \
      $out/temp/x86_64/libfrida-gum-x86_64.a \
      -output $out/temp/libfrida-gum-arm64e-arm64-x86_64.a

    # Check architectures in the FAT library
    echo "Checking architectures in libfrida-gum-arm64e-arm64-x86_64.a..."
    ${pkgs.darwin.cctools}/bin/lipo -info $out/temp/libfrida-gum-arm64e-arm64-x86_64.a

    # Create dynamic library
    ${pkgs.clang}/bin/clang -arch x86_64 -arch arm64e -arch arm64 \
      -lresolv -fpic -shared \
      -Wl,-all_load $out/temp/libfrida-gum-arm64e-arm64-x86_64.a \
      -o $out/fridagum.dylib

    # Clean up
    rm -rf $out/temp
  '';

  meta = with pkgs.lib; {
    description = "Ammonia - A macOS tweak system";
    homepage = "https://github.com/corebedtime/ammonia";
    license = licenses.mit;
    platforms = [ 
      "x86_64-darwin"
      "aarch64-darwin"
    ];
  };
}
