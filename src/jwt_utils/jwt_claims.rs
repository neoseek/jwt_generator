use serde::{Serialize, Deserialize};

#[derive(Debug,Serialize,Deserialize)]
/// Represents the claims of a JSON Web Token (JWT).
///
/// # Fields
///
/// * `iss`: The issuer of the token.
/// * `sub`: The subject of the token.
/// * `aud`: The audience of the token.
/// * `exp`: The expiration time of the token.
/// * `nbf`: The "not before" time of the token.
/// * `iat`: The issued at time of the token.
/// * `jti`: The unique identifier of the token.
pub struct Claims {
    pub aud: String,
    pub iss: String,
    pub sub: String,
    pub jti: String,
    pub exp: usize,
    pub iat: usize,
}