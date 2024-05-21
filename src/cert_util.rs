use openssl::x509::{X509, X509StoreContextRef, X509S, X509StoreContext};
use std::error::Error;
use openssl::hash::MessageDigest;

// Finding a Certificate via Subject Name
// Finding a Certificate via Thumbprint
// Get all the certificates

// Creating the Certificate Store
pub fn create_cert_store() -> Result<X509StoreContext, Box<dyn Error>> {
    // Create an empty X509StoreBuilder
    let mut builder = X509StoreBuilder::new()?;

    // You can add certificates to the builder here if needed
    let store = builder.build();

    // Create a context for the store
    let mut store_ctx = X509StoreContext::new()?;
    store_ctx.init(&store, None, &[], |ctx| Ok(()))?;

    Ok(store_ctx)
}

pub fn find_cert_by_subject(store_ctx: &X509StoreContextRef, subject_name: &str) -> Result<Option<X509>, Box<dyn std::error::Error>> {
    let all_certs = get_all_certificates(store_ctx)?;
    for cert in all_certs {
        if cert.subject_name().entries().any(|e| e.data().as_utf8().unwrap() == subject_name) {
            return Ok(Some(cert));
        }
    }
    Ok(None)
}

pub fn find_cert_by_thumbprint(store_ctx: &X509StoreContextRef, thumbprint: &str) -> Result<Option<X509>, Box<dyn std::error::Error>> {
    let thumbprint_bytes = hex::decode(thumbprint)?;
    let all_certs = get_all_certificates(store_ctx)?;
    for cert in all_certs {
        let digest = cert.digest(MessageDigest::sha1())?;
        if digest == thumbprint_bytes {
            return Ok(Some(cert));
        }
    }
    Ok(None)
}

fn get_all_certificates(_store_ctx: &X509StoreContextRef) -> Result<Vec<X509>, Box<dyn std::error::Error>> {
    // In a real application, you would retrieve actual certificates here
    // For the example, return an empty vector or mock certificates
    Ok(vec![])
}