import birl
import gleam/bit_array
import gleam/dynamic
import gleam/json
import gleeunit
import gleeunit/should
import gwt
import gwt/jwk

const signing_secret = "gleam"

pub fn main() {
  gleeunit.main()
}

pub fn encode_decode_unsigned_jwt_test() {
  let jwt_string =
    gwt.new()
    |> gwt.set_subject("1234567890")
    |> gwt.set_audience("0987654321")
    |> gwt.set_not_before(1_704_043_160)
    |> gwt.set_expiration(1_704_046_160)
    |> gwt.set_jwt_id("2468")
    |> gwt.to_string()

  let maybe_jwt = gwt.from_string(jwt_string)

  maybe_jwt
  |> should.be_ok()

  let assert Ok(jwt) = gwt.from_string(jwt_string)

  gwt.get_subject(jwt)
  |> should.equal(Ok("1234567890"))

  jwt
  |> gwt.get_payload_claim("aud", dynamic.string)
  |> should.equal(Ok("0987654321"))

  jwt
  |> gwt.get_payload_claim("iss", dynamic.string)
  |> should.equal(Error(gwt.MissingClaim))
}

pub fn encode_decode_signed_jwt_test() {
  let jwt_string =
    gwt.new()
    |> gwt.set_subject("1234567890")
    |> gwt.set_audience("0987654321")
    |> gwt.to_signed_string(gwt.HS256, signing_secret)

  gwt.from_signed_string(jwt_string, "bad secret")
  |> should.be_error

  gwt.from_signed_string(jwt_string, "bad secret")
  |> should.equal(Error(gwt.InvalidSignature))

  let maybe_jwt = gwt.from_signed_string(jwt_string, signing_secret)
  maybe_jwt
  |> should.be_ok()

  let assert Ok(jwt) = gwt.from_signed_string(jwt_string, signing_secret)

  gwt.get_subject(jwt)
  |> should.equal(Ok("1234567890"))

  jwt
  |> gwt.get_payload_claim("aud", dynamic.string)
  |> should.equal(Ok("0987654321"))

  jwt
  |> gwt.get_payload_claim("iss", dynamic.string)
  |> should.equal(Error(gwt.MissingClaim))

  let jwt =
    gwt.new()
    |> gwt.set_subject("1234567890")
    |> gwt.set_audience("0987654321")

  jwt
  |> gwt.to_signed_string(gwt.HS256, signing_secret)
  |> gwt.from_signed_string(signing_secret)
  |> should.be_ok()

  jwt
  |> gwt.to_signed_string(gwt.HS384, signing_secret)
  |> gwt.from_signed_string(signing_secret)
  |> should.be_ok()

  jwt
  |> gwt.to_signed_string(gwt.HS512, signing_secret)
  |> gwt.from_signed_string(signing_secret)
  |> should.be_ok()
}

pub fn exp_jwt_test() {
  gwt.new()
  |> gwt.set_subject("1234567890")
  |> gwt.set_audience("0987654321")
  |> gwt.set_expiration(
    {
      birl.now()
      |> birl.to_unix()
    }
    + 100_000,
  )
  |> gwt.to_signed_string(gwt.HS256, signing_secret)
  |> gwt.from_signed_string(signing_secret)
  |> should.be_ok()

  gwt.new()
  |> gwt.set_subject("1234567890")
  |> gwt.set_audience("0987654321")
  |> gwt.set_expiration(0)
  |> gwt.to_signed_string(gwt.HS256, signing_secret)
  |> gwt.from_signed_string(signing_secret)
  |> should.equal(Error(gwt.TokenExpired))
}

pub fn nbf_jwt_test() {
  gwt.new()
  |> gwt.set_subject("1234567890")
  |> gwt.set_audience("0987654321")
  |> gwt.set_not_before(
    {
      birl.now()
      |> birl.to_unix()
    }
    + 100_000,
  )
  |> gwt.to_signed_string(gwt.HS256, signing_secret)
  |> gwt.from_signed_string(signing_secret)
  |> should.equal(Error(gwt.TokenNotValidYet))

  gwt.new()
  |> gwt.set_subject("1234567890")
  |> gwt.set_audience("0987654321")
  |> gwt.set_not_before(0)
  |> gwt.to_signed_string(gwt.HS256, signing_secret)
  |> gwt.from_signed_string(signing_secret)
  |> should.be_ok()
}

/// JWK Tests
/// 
pub fn parse_jwk_and_sign_test() {
  let pub_key_json =
    "{\"kty\":\"RSA\",
      \"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",
      \"e\":\"AQAB\",
      \"alg\":\"RS256\",
      \"kid\":\"2011-04-29\"}"
  let pub_key =
    json.decode(pub_key_json, jwk.decode_public_key)
    |> should.be_ok()

  let priv_key_json =
    "{\"kty\": \"RSA\",
      \"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",
      \"e\": \"AQAB\",
      \"d\": \"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q\",
      \"alg\": \"RS256\",
      \"kid\": \"2011-04-29\"}"
  let priv_key =
    json.decode(priv_key_json, jwk.decode_private_key)
    |> should.be_ok()

  let message = bit_array.from_string("hello")
  let signature = jwk.sign(message, priv_key)
  jwk.verify(message, signature, pub_key)
  |> should.be_true()
}

pub fn the_big_test() {
  let pub_keys_json =
    "{\"keys\": [
     {\"kty\":\"RSA\",
      \"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",
      \"e\":\"AQAB\",
      \"alg\":\"RS256\",
      \"kid\":\"2011-04-29\"}]}"
  let assert Ok(jwks) = json.decode(pub_keys_json, jwk.decode_public_jwks)

  let priv_key_json =
    "{\"kty\": \"RSA\",
      \"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",
      \"e\": \"AQAB\",
      \"d\": \"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q\",
      \"alg\": \"RS256\",
      \"kid\": \"2011-04-29\"}"
  let assert Ok(priv_key) = json.decode(priv_key_json, jwk.decode_private_key)

  let jwt =
    gwt.new()
    |> gwt.set_expiration(
      {
        birl.now()
        |> birl.to_unix()
      }
      + 100_000,
    )

  jwt
  |> jwk.to_signed_string(priv_key)
  |> jwk.from_signed_string(jwks)
  |> should.be_ok()
}
