# frozen_string_literal: true

# Generates deterministic cross-language fixtures with the same primitives and
# canonical JSON implementation used by the LicenseSeat Ruby core.
#
# From a normal sibling checkout:
#   ruby crates/licenseseat/tests/fixtures/generate_ruby_compat_fixtures.rb
#
# For a worktree elsewhere:
#   LICENSE_SEAT_CORE=~/GitHub/license_seat ruby ...

require "base64"
require "ed25519"
require "json"
require "openssl"
require "time"

core_path = ENV.fetch(
  "LICENSE_SEAT_CORE",
  File.expand_path("../../../../../license_seat", __dir__)
)
require File.join(core_path, "lib/license_seat/utils/json_utils")

SEED = ["9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"].pack("H*")
KEY_ID = "ruby-fixture-key-v1"
LICENSE_KEY = "RUBY-FIXTURE-LICENSE"
PRODUCT_SLUG = "ruby-fixture-product"
FINGERPRINT = "ruby-fixture-installation"
ACTIVATION_ID = "act-12345-uuid"
ISSUED_AT = Time.utc(2025, 1, 1)
EXPIRES_AT = Time.utc(2099, 1, 1)
ENTITLEMENT_EXPIRES_AT = Time.utc(2080, 1, 1)

signing_key = Ed25519::SigningKey.new(SEED)
public_key = Base64.strict_encode64(signing_key.verify_key.to_bytes)

token_payload = {
  schema_version: 1,
  license_key: LICENSE_KEY,
  product_slug: PRODUCT_SLUG,
  plan_key: "pro",
  mode: "hardware_locked",
  seat_limit: 1,
  fingerprint: FINGERPRINT,
  iat: ISSUED_AT.to_i,
  exp: EXPIRES_AT.to_i,
  nbf: ISSUED_AT.to_i,
  license_expires_at: EXPIRES_AT.to_i,
  kid: KEY_ID,
  entitlements: [
    {key: "pro-feature", expires_at: ENTITLEMENT_EXPIRES_AT.to_i},
    {key: "perpetual-feature", expires_at: nil}
  ],
  metadata: {
    "nested" => {"z" => 1, "a" => 2},
    "issuer" => "license_seat-ruby",
    "fractional" => 0.125,
    "large_float" => 1.0e20,
    "unicode" => "Licença ✓"
  }
}
canonical = LicenseSeat::Utils::JsonUtils.canonical_json_generate(token_payload)
offline_token = {
  "object" => "offline_token",
  "token" => JSON.parse(canonical),
  "signature" => {
    "algorithm" => "Ed25519",
    "key_id" => KEY_ID,
    "value" => Base64.strict_encode64(signing_key.sign(canonical))
  },
  "canonical" => canonical
}

ttl = EXPIRES_AT.to_i - ISSUED_AT.to_i
machine_payload = {
  meta: {
    schema_version: 2,
    issued: ISSUED_AT.iso8601,
    iat: ISSUED_AT.to_i,
    expiry: EXPIRES_AT.iso8601,
    exp: EXPIRES_AT.to_i,
    nbf: ISSUED_AT.to_i,
    ttl: ttl,
    grace_period: 86_400,
    lic: LICENSE_KEY,
    license_exp: EXPIRES_AT.to_i,
    kid: KEY_ID,
    sdk_version: "ruby-core-fixture"
  },
  data: {
    type: "machines",
    id: ACTIVATION_ID,
    attributes: {
      fingerprint: FINGERPRINT,
      fingerprint_components: {
        schema_version: "1",
        platform: "macos",
        architecture: "arm64"
      },
      name: "Ruby Fixture Device",
      platform: "macos",
      created: ISSUED_AT.iso8601,
      metadata: {"issuer" => "license_seat-ruby"}
    },
    relationships: {
      license: {data: {type: "licenses", id: LICENSE_KEY}},
      product: {data: {type: "products", id: PRODUCT_SLUG}}
    }
  },
  included: [
    {
      type: "licenses",
      id: LICENSE_KEY,
      attributes: {
        key: LICENSE_KEY,
        status: "active",
        mode: "hardware_locked",
        seat_limit: 1,
        plan_key: "pro",
        product_slug: PRODUCT_SLUG,
        starts_at: ISSUED_AT.iso8601,
        ends_at: EXPIRES_AT.iso8601,
        entitlements: [
          {key: "pro-feature", expires_at: ENTITLEMENT_EXPIRES_AT.iso8601},
          {key: "perpetual-feature", expires_at: nil}
        ],
        metadata: {"issuer" => "license_seat-ruby"}
      }
    }
  ]
}

digest = OpenSSL::Digest::SHA256.digest(LICENSE_KEY + FINGERPRINT)
cipher = OpenSSL::Cipher.new("aes-256-gcm")
cipher.encrypt
cipher.key = digest
nonce = (1..12).to_a.pack("C*")
cipher.iv = nonce
cipher.auth_data = ""
ciphertext = cipher.update(machine_payload.to_json) + cipher.final
tag = cipher.auth_tag
encoded_payload = [
  Base64.urlsafe_encode64(ciphertext, padding: false),
  Base64.urlsafe_encode64(nonce, padding: false),
  Base64.urlsafe_encode64(tag, padding: false)
].join(".")
envelope = {
  enc: encoded_payload,
  sig: Base64.urlsafe_encode64(signing_key.sign("machine/#{encoded_payload}"), padding: false),
  alg: "aes-256-gcm+ed25519",
  kid: KEY_ID
}
certificate_body = Base64.strict_encode64(envelope.to_json).scan(/.{1,64}/).join("\n")
certificate = [
  "-----BEGIN MACHINE FILE-----",
  certificate_body,
  "-----END MACHINE FILE-----"
].join("\n")

fixture = {
  "provenance" => {
    "issuer" => "LicenseSeat Ruby core-compatible generator",
    "canonical_json_source" => "license_seat/lib/license_seat/utils/json_utils.rb",
    "machine_file_contract_source" => "license_seat/lib/license_seat/services/offline_machine_file.rb",
    "seed_source" => "RFC 8032 test vector 1",
    "generated_by" => File.basename(__FILE__)
  },
  "public_key" => public_key,
  "key_id" => KEY_ID,
  "license_key" => LICENSE_KEY,
  "product_slug" => PRODUCT_SLUG,
  "fingerprint" => FINGERPRINT,
  "activation_id" => ACTIVATION_ID,
  "offline_token" => offline_token,
  "machine_file" => {
    "certificate" => certificate,
    "algorithm" => "aes-256-gcm+ed25519",
    "ttl" => ttl,
    "issued_at" => ISSUED_AT.iso8601,
    "expires_at" => EXPIRES_AT.iso8601,
    "license_key" => LICENSE_KEY,
    "fingerprint" => FINGERPRINT
  }
}

puts JSON.pretty_generate(fixture)
