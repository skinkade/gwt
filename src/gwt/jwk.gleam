import gleam/bit_array
import gleam/crypto
import gleam/dynamic.{type DecodeError, type Dynamic, DecodeError}
import gleam/io
import gleam/json.{type Json}
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gwt

pub type PublicKey

pub type PrivateKey

pub type BigInt

pub opaque type JWKPublicKey {
  RSAPublicKey(inner: PublicKey)
}

pub opaque type JWKPrivateKey {
  RSAPrivateKey(inner: PrivateKey)
}

@external(erlang, "binary", "decode_unsigned")
fn decode_unsigned(bs: BitArray) -> BigInt

pub type KeyType {
  RSA
}

@external(erlang, "crypto", "sign")
fn do_sign(
  key_type: KeyType,
  digest: crypto.HashAlgorithm,
  message: BitArray,
  key: PrivateKey,
) -> BitArray

pub fn sign(message: BitArray, jwk: PrivateJwk) {
  let #(key_type, inner_key) = case jwk.key {
    RSAPrivateKey(inner) -> #(RSA, inner)
  }
  do_sign(key_type, signing_to_hashing(jwk.algorithm), message, inner_key)
}

@external(erlang, "crypto", "verify")
fn do_verify(
  key_type: KeyType,
  digest: crypto.HashAlgorithm,
  message: BitArray,
  signature: BitArray,
  key: PublicKey,
) -> Bool

pub fn verify(message: BitArray, signature: BitArray, jwk: PublicJwk) {
  let #(key_type, inner_key) = case jwk.key {
    RSAPublicKey(inner) -> #(RSA, inner)
  }
  do_verify(
    key_type,
    signing_to_hashing(jwk.algorithm),
    message,
    signature,
    inner_key,
  )
}

@external(erlang, "gwt_ffi", "rsa_public_key")
fn rsa_public_key(exponent: BigInt, public_exponent: BigInt) -> PublicKey

@external(erlang, "gwt_ffi", "rsa_private_key")
fn rsa_private_key(
  modulus: BigInt,
  public_exponent: BigInt,
  private_exponent: BigInt,
) -> PrivateKey

pub type PublicJwk {
  PublicRsaJwk(
    id: String,
    key: JWKPublicKey,
    key_use: Option(PublicKeyUse),
    key_operations: Option(KeyOperations),
    algorithm: SigningAlgorithm,
  )
}

pub type PrivateJwk {
  PrivateRsaJwk(
    id: String,
    key: JWKPrivateKey,
    key_use: Option(PublicKeyUse),
    key_operations: Option(KeyOperations),
    algorithm: SigningAlgorithm,
  )
}

pub type PublicKeyUse {
  Signature
  Encryption
}

pub type KeyOperation {
  Sign
  Verify
  Encrypt
  Decrypt
  WrapKey
  UnwrapKey
  DeriveKey
  DeriveBits
}

pub type KeyOperations =
  List(KeyOperation)

pub type SigningAlgorithm {
  RS256
  RS384
  RS512
}

fn signing_to_hashing(sa: SigningAlgorithm) -> crypto.HashAlgorithm {
  case sa {
    RS256 -> crypto.Sha256
    RS384 -> crypto.Sha384
    RS512 -> crypto.Sha512
  }
}

fn derive_rsa_public_key(
  value: Dynamic,
) -> Result(JWKPublicKey, List(DecodeError)) {
  use n <- result.try(
    value
    |> dynamic.field("n", dynamic.string),
  )
  use e <- result.try(
    value
    |> dynamic.field("e", dynamic.string),
  )

  use n <- result.try(
    n
    |> bit_array.base64_url_decode()
    // TODO meaningful error
    |> result.replace_error([DecodeError("n", "", [""])]),
  )
  use e <- result.try(
    e
    |> bit_array.base64_url_decode()
    // TODO meaningful error
    |> result.replace_error([DecodeError("e", "", [""])]),
  )

  // TODO assert n length is 2048, 3072, or 4096
  Ok(
    RSAPublicKey(inner: rsa_public_key(decode_unsigned(e), decode_unsigned(n))),
  )
}

fn derive_rsa_private_key(
  value: Dynamic,
) -> Result(JWKPrivateKey, List(DecodeError)) {
  use n <- result.try(
    value
    |> dynamic.field("n", dynamic.string),
  )
  use e <- result.try(
    value
    |> dynamic.field("e", dynamic.string),
  )
  use d <- result.try(
    value
    |> dynamic.field("d", dynamic.string),
  )

  use n <- result.try(
    n
    |> bit_array.base64_url_decode()
    |> result.replace_error([DecodeError("n", "", [""])]),
  )
  use e <- result.try(
    e
    |> bit_array.base64_url_decode()
    |> result.replace_error([DecodeError("e", "", [""])]),
  )
  use d <- result.try(
    d
    |> bit_array.base64_url_decode()
    |> result.replace_error([DecodeError("d", "", [""])]),
  )

  Ok(
    RSAPrivateKey(inner: rsa_private_key(
      decode_unsigned(e),
      decode_unsigned(n),
      decode_unsigned(d),
    )),
  )
}

pub fn decode_public_key(value: Dynamic) -> Result(PublicJwk, List(DecodeError)) {
  use key_type <- result.try(
    value
    |> dynamic.field("kty", dynamic.string),
  )

  case key_type {
    "RSA" -> {
      use alg <- result.try(
        value
        |> dynamic.field("alg", dynamic.string),
      )
      use kid <- result.try(
        value
        |> dynamic.field("kid", dynamic.string),
      )
      use key <- result.try(derive_rsa_public_key(value))
      Ok(PublicRsaJwk(
        id: kid,
        key: key,
        key_use: None,
        key_operations: None,
        algorithm: RS256,
      ))
    }
    // TODO meaningful error
    _ -> Error([DecodeError("key", "", [""])])
  }
}

pub fn decode_public_jwks(
  value: Dynamic,
) -> Result(List(PublicJwk), List(DecodeError)) {
  dynamic.field("keys", dynamic.list(decode_public_key))(value)
}

pub fn decode_private_key(
  value: Dynamic,
) -> Result(PrivateJwk, List(DecodeError)) {
  use key_type <- result.try(
    value
    |> dynamic.field("kty", dynamic.string),
  )

  case key_type {
    "RSA" -> {
      use alg <- result.try(
        value
        |> dynamic.field("alg", dynamic.string),
      )
      use kid <- result.try(
        value
        |> dynamic.field("kid", dynamic.string),
      )
      use key <- result.try(derive_rsa_private_key(value))
      Ok(PrivateRsaJwk(
        id: kid,
        key: key,
        key_use: None,
        key_operations: None,
        algorithm: RS256,
      ))
    }
    // TODO meaningful error
    _ -> Error([DecodeError("key", "", [""])])
  }
}

pub fn from_signed_string(
  jwt_string: String,
  jwks: List(PublicJwk),
) -> Result(gwt.Jwt(gwt.Verified), gwt.JwtDecodeError) {
  use #(header, payload, signature) <- result.try(gwt.parts(jwt_string))
  use signature <- result.try(option.to_result(signature, gwt.MissingSignature))

  use _ <- result.try(gwt.ensure_valid_expiration(payload))
  use _ <- result.try(gwt.ensure_valid_not_before(payload))
  use alg <- result.try(gwt.ensure_valid_alg(header))

  let assert [encoded_header, encoded_payload, ..] =
    string.split(jwt_string, ".")
  case alg {
    "RS256" | "RS384" | "RS512" -> {
      let alg = case alg {
        "RS256" -> RS256
        "RS384" -> RS384
        "RS512" -> RS512
        _ -> panic as "Should not be reachable"
      }

      case
        verify_signature(
          encoded_header <> "." <> encoded_payload,
          signature,
          alg,
          jwks,
        )
      {
        Ok(True) -> {
          Ok(gwt.Jwt(header: header, payload: payload))
        }
        Ok(False) -> Error(gwt.InvalidSignature)
        Error(e) -> {
          io.debug(e)
          panic as "dweowjoiewj"
        }
      }
    }
    _ -> Error(gwt.UnsupportedSigningAlgorithm)
  }
}

import gleam/list

pub fn verify_signature(
  header_and_payload: String,
  signature: String,
  algorithm: SigningAlgorithm,
  jwks: List(PublicJwk),
) {
  let header_and_payload = bit_array.from_string(header_and_payload)
  use signature <- result.try(bit_array.base64_url_decode(signature))
  jwks
  |> list.filter(fn(jwk) { jwk.algorithm == algorithm })
  |> list.any(verify(header_and_payload, signature, _))
  |> Ok
}

import gleam/dict

pub fn to_signed_string(jwt: gwt.Jwt(status), key: PrivateJwk) -> String {
  case key.algorithm {
    RS256 | RS384 | RS512 -> {
      let #(alg_string, hash_alg) = case key.algorithm {
        RS256 -> #("RS256", crypto.Sha256)
        RS384 -> #("RS384", crypto.Sha384)
        RS512 -> #("RS512", crypto.Sha512)
      }

      let header_with_alg =
        dict.insert(jwt.header, "alg", dynamic.from(alg_string))
      let jwt_body =
        gwt.Jwt(..jwt, header: header_with_alg)
        |> gwt.to_string()

      let jwt_signature =
        jwt_body
        |> bit_array.from_string()
        |> sign(key)
        |> bit_array.base64_url_encode(False)

      jwt_body <> "." <> jwt_signature
    }
  }
}
