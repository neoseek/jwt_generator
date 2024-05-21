extern crate jsonwebtoken as jwt;
extern crate openssl;
#[macro_use]
extern crate serde_derive;
use crate::jwt_utils::jwt_claims::Claims;

use jwt::{encode, Header, EncodingKey};
use openssl::pkcs12::Pkcs12;
use openssl::pkey::PKey;
use openssl::x509::X509;
use serde::Serialize;
use std::fs::File;
use std::io::Read;
use uuid::Uuid;
use openssl::x509::X509;

fn get_cert_thumbprint(cert_subject: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Build the X509Store
    let mut builder = X509Builder::new()?;
    // Here you would typically add lookups or certificates to the builder
    let store = builder.build();

    // Create a context for the store
    let mut store_ctx = X509StoreContext::new()?;
    store_ctx.init(&store, None, &[], |ctx| {
        // In a real application, initialize the context as needed
        Ok(())
    })?;

    // Retrieve all certificates from the store context
    let all_certs = get_all_certificates(&store_ctx)?;

    // Find the certificate with the given subject name
    let found_cert = all_certs.iter().find(|c| {
        c.subject_name()
            .entries()
            .any(|e| e.data().as_utf8().unwrap() == cert_subject)
    });

    // If the certificate is found, calculate its thumbprint
    if let Some(cert) = found_cert {
        // Calculate the SHA-1 thumbprint of the certificate
        let thumbprint = cert.digest(MessageDigest::sha1())?;

        // Convert the thumbprint to a hexadecimal string
        let thumbprint_hex = hex::encode(thumbprint);

        Ok(thumbprint_hex)
    } else {
        Err(format!("Certificate with subject '{}' not found", cert_subject).into())
    }
}

fn create_jwt(
    tenant_id: &str,
    client_id: &str,
    pfx_path: &str,
    pfx_password: &str,
    thumbprint: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Read the PFX file
    let mut pfx_file = File::open(pfx_path)?;
    let mut pfx_data = Vec::new();
    pfx_file.read_to_end(&mut pfx_data)?;

    // Parse the PFX file
    let pkcs12 = Pkcs12::from_der(&pfx_data)?;
    let parsed = pkcs12.parse(pfx_password)?;

    // Extract the private key
    let private_key = parsed.pkey;

    // Create the JWT claims
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() as usize;
    let exp = now + 3600; // Token expiration time (1 hour)
    let claims = Claims {
        aud: format!("https://login.microsoftonline.com/{}/oauth2/v2.0/token", tenant_id),
        iss: client_id.to_string(),
        sub: client_id.to_string(),
        jti: Uuid::new_v4().to_string(),
        exp,
        iat: now,
    };

    // Create the JWT header with thumbprint
    let mut header = Header::new(jwt::Algorithm::RS256);
    header.kid = Some(thumbprint.to_string());

    // Encode and sign the JWT
    let token = encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(&private_key.private_key_to_pem_pkcs8()?)?,
    )?;

    Ok(token)
}



