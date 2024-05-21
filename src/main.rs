mod jwt_utils;
mod cert_util;

use std::io;
use colored::*;
use std::path::Path;
use crate::jwt_utils::jwt_generator::generate_jwt;

fn main() -> Result<(), io::Error> {
    println!("{}", "Welcome to the JWT Generator! \n".green());

    let mut tenant_id = String::new();
    let mut client_id = String::new();
    let mut cert_path = String::new();

    println!("Please enter the Tenant ID");
    io::stdin().read_line(&mut tenant_id).expect("Unable to parse value");

    println!("Please enter the Client ID");
    io::stdin().read_line(&mut client_id).expect("Unable to parse value");

    println!("Please enter the Cert Path");
    io::stdin().read_line(&mut cert_path).expect("Unable to parse value");

    // Validate the Cert_Path
    let path = Path::new(&cert_path);

    if !path.exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "Path Could not be found"));
    }

    println!("{}", format!("You entered the tenant_id: {tenant_id} \nclient_id: {client_id} \ncert_path: {cert_path}"));

    println!("Generating JWT Token now");
    generate_jwt(tenant_id, client_id);
    Ok(())
}
