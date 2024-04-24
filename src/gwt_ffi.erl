-module(gwt_ffi).

-export([rsa_public_key/2, rsa_private_key/3]).

% -include_lib("public_key/include/public_key.hrl").

rsa_public_key(Modulus, PublicExponent) ->
    [Modulus, PublicExponent].

rsa_private_key(Modulus, PublicExponent, PrivateExponent) ->
    [Modulus, PublicExponent, PrivateExponent].

% rsa_public_key(Modulus, PublicExponent) ->
%     #'RSAPublicKey'{modulus = Modulus, publicExponent = PublicExponent}.

% rsa_private_key(Modulus,
%                 PublicExponent,
%                 PrivateExponent,
%                 Prime1,
%                 Prime2,
%                 Exponent1,
%                 Exponent2,
%                 Coefficient) ->
%     #'RSAPrivateKey'{version = 'two-prime',
%                      otherPrimeInfos = asn1_NOVALUE,
%                      modulus = Modulus,
%                      publicExponent = PublicExponent,
%                      privateExponent = PrivateExponent,
%                      prime1 = Prime1,
%                      prime2 = Prime2,
%                      exponent1 = Exponent1,
%                      exponent2 = Exponent2,
%                      coefficient = Coefficient}.
