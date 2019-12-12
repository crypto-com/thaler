with import <nixpkgs> {};


let dependencies = rec {


  _apply_defaults = with python37Packages; buildPythonPackage rec {
  pname = "apply_defaults";
  version = "0.1.4";
  doCheck = false;
  src = fetchPypi {
    inherit pname version;
    sha256 =
 "1ce26326a61d8773d38a9726a345c6525a91a6120d7333af79ad792dacb6246c";
  };
};
  _click = with python37Packages; buildPythonPackage rec {
  pname = "click";
  version = "6.7.0";
  doCheck = false;
  src = fetchPypi {
    inherit pname version;
    sha256 =
 "f15516df478d5a56180fbf80e68f206010e6d160fc39fa508b65e035fd75130b";
  };
};
  _jsonschema = with python37Packages; buildPythonPackage rec {
  pname = "jsonschema";
  version = "3.2.0";
  doCheck = false;
  src = fetchPypi {
    inherit pname version;
    sha256 =
 "c8a85b28d377cc7737e46e2d9f2b4f44ee3c0e1deac6bf46ddefc7187d30797a";
  };
  buildInputs = [setuptools_scm importlib-metadata attrs pyrsistent];
};
  # Custom new packages using buildPythonPackage expression
  _jsonrpcclient = with python37Packages; buildPythonPackage rec {
  pname = "jsonrpcclient";
  version = "3.3.4";
  doCheck = false;
  src = fetchPypi {
    inherit pname version;
    sha256 =
 "c50860409b73af9f94b648439caae3b4af80d5ac937f2a8ac7783de3d1050ba9";
  };
  buildInputs = [_jsonschema _apply_defaults _click importlib-metadata attrs pyrsistent];
};
  _python-decouple = with python37Packages; buildPythonPackage rec {
  pname = "python-decouple";
  version = "3.3";
  doCheck = false;
  src = fetchPypi {
    inherit pname version;
    sha256 =
 "55c546b85b0c47a15a47a4312d451a437f7344a9be3e001660bccd93b637de95";
  };
};
};

in with dependencies;
stdenv.mkDerivation rec {
  name = "env";
  # Mandatory boilerplate for buildable env
  env = buildEnv { name = name; paths = buildInputs; };
  builder = builtins.toFile "builder.sh" ''
    source $stdenv/setup; ln -s $env $out
  '';
  # Customizable development requirements
    


  buildInputs = [
    
    gmp
    zeromq
    pkgconfig
    # With Python configuration requiring a special wrapper
    (python37.buildEnv.override {
      ignoreCollisions = true;
      extraLibs = with python37Packages; [
         _apply_defaults 
         jsonschema
         pip
         docker
         setuptools
         wheel
         jsonpatch
         fire
         toml
         pynacl
         mnemonic
         _jsonrpcclient
         _python-decouple
      ];
    })
  ];
  # Customizable development shell setup with at last SSL certs set
  shellHook = ''
    export SSL_CERT_FILE=${cacert}/etc/ssl/certs/ca-bundle.crt
    export LD_LIBRARY_PATH="/nix/store/$(ls /nix/store | grep -E "zeromq-[0-9\.]+$" | head -n1)/lib":$LD_LIBRARY_PATH
  '';
}
