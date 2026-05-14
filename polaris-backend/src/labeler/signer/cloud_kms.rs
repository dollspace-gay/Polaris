//! `cloud-kms-oracle` custody mode — per-signature KMS RPC.
//!
//! The only mode that defends T4 (code execution as the Polaris user):
//! the private key never enters Polaris's address space. Every
//! `sign()` is a network call to a cloud KMS service that holds the
//! key under HSM-backed protection and returns the ECDSA-SHA256
//! signature inline.
//!
//! # Provider matrix
//!
//! Today only `Aws` is wired. The `Gcp` and `Azure` variants exist on
//! [`crate::config::KmsProvider`] so the operator-facing config can
//! name them, but constructing a signer for them returns
//! [`SigningError::Sign`] with a "not yet implemented for provider"
//! message. The shape is established here so a future issue can fill
//! in the per-provider RPC without an enum migration.
//!
//! # Feature gate
//!
//! The AWS implementation is gated behind the `kms-integration` Cargo
//! feature. Without the feature, the factory returns
//! [`SigningError::Sign`] naming the missing feature flag — the
//! polaris-backend default build does not pull the AWS SDK + tokio
//! runtime extensions.
//!
//! # Cached state
//!
//! On construction, [`AwsKmsSigner::new`] performs a single
//! `get_public_key` RPC and computes the `did:key:z…` form of the
//! returned ECC point. The signer caches *only* that public DID. The
//! private key is never read or cached.

use std::sync::Arc;

use super::{SigningError, SigningKey};
use crate::config::KmsProvider;

/// Build the configured cloud-KMS signer.
///
/// Routes by `provider`; the AWS implementation is feature-gated. The
/// factory returns an `Arc<dyn SigningKey>` directly (rather than a
/// concrete type) because the per-provider concrete types do not need
/// to escape this module — the polaris-backend startup path only
/// consumes the dyn-wrapped form.
///
/// # Errors
///
/// - [`SigningError::Sign`] if the `kms-integration` feature is off
///   and the operator selected an AWS provider, or if the provider is
///   a not-yet-implemented variant (GCP / Azure).
/// - [`SigningError::Kms`] on transport / authentication failure when
///   the AWS path is active.
pub fn build_cloud_kms_signer(
    provider: KmsProvider,
    key_id: &str,
    region: &str,
) -> Result<Arc<dyn SigningKey>, SigningError> {
    match provider {
        KmsProvider::Aws => build_aws(key_id, region),
        KmsProvider::Gcp => Err(SigningError::Sign {
            reason: "cloud-kms-oracle: GCP provider not yet implemented",
        }),
        KmsProvider::Azure => Err(SigningError::Sign {
            reason: "cloud-kms-oracle: Azure provider not yet implemented",
        }),
    }
}

#[cfg(feature = "kms-integration")]
fn build_aws(key_id: &str, region: &str) -> Result<Arc<dyn SigningKey>, SigningError> {
    Ok(Arc::new(aws::AwsKmsSigner::new(key_id, region)?))
}

#[cfg(not(feature = "kms-integration"))]
fn build_aws(_key_id: &str, _region: &str) -> Result<Arc<dyn SigningKey>, SigningError> {
    Err(SigningError::Sign {
        reason: "cloud-kms-oracle: AWS provider requires the `kms-integration` cargo feature",
    })
}

#[cfg(feature = "kms-integration")]
mod aws {
    //! AWS KMS impl. Each `sign()` is an RPC to KMS; the private key
    //! never enters this process.

    use aws_config::BehaviorVersion;
    use aws_sdk_kms::Client;
    use aws_sdk_kms::primitives::Blob;
    use aws_sdk_kms::types::{MessageType, SigningAlgorithmSpec};
    use proto_blue::crypto::{format_did_key, k256_compress_pubkey};
    use sha2::{Digest as _, Sha256};

    use super::super::{Signature, SigningError, SigningKey};

    pub(super) struct AwsKmsSigner {
        client: Client,
        key_id: String,
        region: String,
        /// did:key:z… form of the KMS-resident public key, computed
        /// once at construction time and cached. The private key
        /// itself is never cached.
        public_key_did: String,
    }

    impl AwsKmsSigner {
        pub(super) fn new(key_id: &str, region: &str) -> Result<Self, SigningError> {
            // Build the SDK client synchronously by blocking on a one-
            // shot tokio runtime — the startup path is not yet inside
            // a runtime when build_signing_key runs, so we cannot
            // `.await`. The runtime is dropped immediately after the
            // client is constructed.
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| SigningError::Kms {
                    reason: "failed to spin a tokio runtime for KMS bootstrap",
                })?;

            let (client, public_key_did) = rt.block_on(async {
                let cfg = aws_config::defaults(BehaviorVersion::latest())
                    .region(aws_config::Region::new(region.to_owned()))
                    .load()
                    .await;
                let client = Client::new(&cfg);
                let pk_resp = client
                    .get_public_key()
                    .key_id(key_id)
                    .send()
                    .await
                    .map_err(|_| SigningError::Kms {
                        reason: "AWS KMS GetPublicKey RPC failed",
                    })?;
                let der = pk_resp.public_key().ok_or(SigningError::Kms {
                    reason: "AWS KMS GetPublicKey returned no public key",
                })?;
                // KMS returns SubjectPublicKeyInfo (DER). Extract the
                // raw uncompressed (0x04 ‖ X ‖ Y) point; the last 65
                // bytes of a P-256 / K-256 SPKI are exactly that. For
                // K-256 (ECC_SECG_P256K1) we then compress to 33 bytes
                // and format as did:key:z…(K-256 multikey).
                let raw = der.as_ref();
                if raw.len() < 65 {
                    return Err(SigningError::Kms {
                        reason: "AWS KMS GetPublicKey returned a too-short SPKI",
                    });
                }
                let uncompressed = &raw[raw.len() - 65..];
                let compressed =
                    k256_compress_pubkey(uncompressed).map_err(|_| SigningError::Kms {
                        reason: "AWS KMS public key is not a valid K-256 point",
                    })?;
                let did = format_did_key("ES256K", &compressed);
                Ok::<_, SigningError>((client, did))
            })?;

            Ok(Self {
                client,
                key_id: key_id.to_owned(),
                region: region.to_owned(),
                public_key_did,
            })
        }
    }

    impl SigningKey for AwsKmsSigner {
        fn sign(&self, payload: &[u8]) -> Result<Signature, SigningError> {
            // Pre-hash to SHA-256: KMS accepts MessageType::Digest, and
            // the atproto label-signing contract is ECDSA over the
            // SHA-256 of the payload. Sending Digest matches what
            // proto_blue_crypto::K256Keypair::sign does locally (it
            // calls sign_prehash(&sha256(msg))) so the produced
            // signatures are interoperable.
            let digest = Sha256::digest(payload).to_vec();

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| SigningError::Kms {
                    reason: "failed to spin a tokio runtime for KMS sign",
                })?;
            let sig_der = rt.block_on(async {
                self.client
                    .sign()
                    .key_id(&self.key_id)
                    .message(Blob::new(digest))
                    .message_type(MessageType::Digest)
                    .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
                    .send()
                    .await
                    .map_err(|_| SigningError::Kms {
                        reason: "AWS KMS Sign RPC failed",
                    })
                    .and_then(|resp| {
                        resp.signature()
                            .map(|b| b.as_ref().to_vec())
                            .ok_or(SigningError::Kms {
                                reason: "AWS KMS Sign returned no signature",
                            })
                    })
            })?;

            // KMS returns a DER-encoded ECDSA signature. The atproto
            // wire format requires the 64-byte compact (r || s) form
            // with low-S normalisation. Convert via the k256 crate
            // re-exported by proto_blue_crypto's keypair plumbing.
            let sig =
                k256::ecdsa::Signature::from_der(&sig_der).map_err(|_| SigningError::Sign {
                    reason: "AWS KMS Sign returned a malformed DER signature",
                })?;
            let normalized = sig.normalize_s().unwrap_or(sig);
            let compact = normalized.to_bytes();
            Signature::from_bytes(&compact)
        }

        fn public_key_did(&self) -> &str {
            &self.public_key_did
        }
    }

    impl std::fmt::Debug for AwsKmsSigner {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("AwsKmsSigner")
                .field("key_id", &self.key_id)
                .field("region", &self.region)
                .field("public_key_did", &self.public_key_did)
                .field("private_key", &"[NEVER IN PROCESS]")
                .finish()
        }
    }

    // ── AC-13 round-trip for cloud-kms-oracle (feature-gated) ────────
    //
    // Exercised against localstack: the CI workflow that turns on the
    // `kms-integration` feature also stands up a localstack container
    // with a pre-provisioned K-256 key.

    #[cfg(test)]
    #[allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test code is allowed to panic — rust-quality §7 convention"
    )]
    mod tests {
        use super::*;
        use proto_blue::crypto::{K256Keypair, Verifier as _};

        /// Round-trip against localstack. Skipped (not failed) unless
        /// `POLARIS_KMS_TEST_KEY_ARN` and `POLARIS_KMS_TEST_REGION` are
        /// set — that is the contract with the test infra.
        #[test]
        fn aws_kms_roundtrip_against_localstack() {
            let Ok(key_id) = std::env::var("POLARIS_KMS_TEST_KEY_ARN") else {
                eprintln!("skipping: POLARIS_KMS_TEST_KEY_ARN unset");
                return;
            };
            let region =
                std::env::var("POLARIS_KMS_TEST_REGION").unwrap_or_else(|_| "us-east-1".to_owned());

            let signer = AwsKmsSigner::new(&key_id, &region).unwrap();
            let payload = b"polaris label payload";
            let sig = signer.sign(payload).unwrap();
            // Verify by handing the cached did:key + payload + sig
            // back to proto-blue-crypto's high-level helper; no
            // local key reconstruction required.
            assert!(
                proto_blue::crypto::verify_signature(
                    signer.public_key_did(),
                    payload,
                    sig.as_bytes(),
                    false,
                )
                .unwrap()
            );
            let _ = K256Keypair::generate(); // suppress unused-import on a fully-feature build
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;

    #[test]
    fn gcp_provider_returns_not_implemented() {
        let err = build_cloud_kms_signer(
            KmsProvider::Gcp,
            "projects/p/keyRings/r/.../v/1",
            "us-east-1",
        )
        .unwrap_err();
        match err {
            SigningError::Sign { reason } => {
                assert!(reason.contains("GCP"), "got {reason}");
                assert!(reason.contains("not yet implemented"), "got {reason}");
            }
            other => panic!("expected Sign{{not implemented}}, got {other:?}"),
        }
    }

    #[test]
    fn azure_provider_returns_not_implemented() {
        let err = build_cloud_kms_signer(KmsProvider::Azure, "https://kv.../keys/k/v", "eastus")
            .unwrap_err();
        match err {
            SigningError::Sign { reason } => {
                assert!(reason.contains("Azure"), "got {reason}");
                assert!(reason.contains("not yet implemented"), "got {reason}");
            }
            other => panic!("expected Sign{{not implemented}}, got {other:?}"),
        }
    }

    #[cfg(not(feature = "kms-integration"))]
    #[test]
    fn aws_provider_without_feature_returns_feature_flag_message() {
        let err =
            build_cloud_kms_signer(KmsProvider::Aws, "arn:aws:kms:...", "us-east-1").unwrap_err();
        match err {
            SigningError::Sign { reason } => {
                assert!(reason.contains("kms-integration"), "got {reason}");
            }
            other => panic!("expected Sign{{feature flag}}, got {other:?}"),
        }
    }
}
