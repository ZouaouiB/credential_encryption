use ldap3::LdapConnAsync;
use ldap3::Scope;
use ldap3::LdapConnSettings;
use native_tls::TlsConnector;
use serde::Deserialize;
use serde::Serialize;
use std::io::{self, Write};

#[derive(Serialize, Deserialize)]
struct AuthResponse {
    success: bool,
    message: String,
}

// Function to read user input from the terminal
fn read_input(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

// Create a custom TLS connector that accepts your server's certificate
fn create_tls_connector() -> Result<TlsConnector, String> {
    TlsConnector::builder()
        .danger_accept_invalid_certs(true) // Accepts invalid certificates (use only for testing!)
        .danger_accept_invalid_hostnames(true) // Accepts invalid hostnames (use only for testing!)
        .build()
        .map_err(|e| format!("Failed to create TLS connector: {}", e))
}

// Function to check LDAP connectivity with custom TLS settings
async fn test_ldap_connectivity(ldap_url: &str) -> Result<(), String> {
    let tls_connector = create_tls_connector()?;
    
    let ldap_settings = LdapConnSettings::new()
        .set_connector(tls_connector);
    
    let (conn, mut ldap) = LdapConnAsync::with_settings(ldap_settings, ldap_url)
        .await
        .map_err(|e| format!("Failed to connect to LDAP server: {}", e))?;

    ldap3::drive!(conn);

    // Perform a simple search to test connectivity
    let search_result = ldap
        .search(
            "", // Root DSE search
            Scope::Base,
            "(objectClass=*)",
            vec!["namingContexts"],
        )
        .await;

    match search_result {
        Ok(_) => {
            ldap.unbind().await.map_err(|e| format!("Failed to unbind: {}", e))?;
            Ok(())
        }
        Err(e) => Err(format!("Failed to perform LDAP search: {}", e)),
    }
}

// AD authentication function with custom TLS settings
async fn ad_authenticate(username: String, password: String) -> Result<AuthResponse, String> {
    // Use the provided LDAP URL
    let ldap_url = "LDAP://10.210.153.1/"; // prod "LDAP://10.210.153.1/"; test_dev LDAP://10.240.70.5:389/";
    let ldap_user_dn = format!("WIFAKBANK\\{}", username);

    // Create custom TLS connector
    let tls_connector = create_tls_connector()?;
    
    // Configure LDAP connection with custom TLS settings
    let ldap_settings = LdapConnSettings::new()
        .set_connector(tls_connector);

    // Test LDAP connectivity first
    test_ldap_connectivity(ldap_url).await?;

    // Connect to the LDAP server with custom settings
    let (conn, mut ldap) = LdapConnAsync::with_settings(ldap_settings, ldap_url)
        .await
        .map_err(|e| format!("Failed to connect to LDAP server: {}", e))?;

    ldap3::drive!(conn);

    // Attempt to bind with the provided username and password
    match ldap.simple_bind(&ldap_user_dn, &password).await {
        Ok(response) => {
            if response.rc == 0 {
                ldap.unbind().await.map_err(|e| format!("Failed to unbind: {}", e))?;
                Ok(AuthResponse {
                    success: true,
                    message: "Authentication successful!".to_string(),
                })
            } else {
                Err(format!("Authentication failed: {} (Result Code: {})", 
                    response.text, response.rc))
            }
        }
        Err(e) => Err(format!("LDAP error: {}", e)),
    }
}

#[tokio::main]
async fn main() {
    println!("LDAP Authentication System");
    println!("-------------------------");
    
    // Get username and password from terminal
    let username = read_input("Enter your username: ");
    let password = read_input("Enter your password: ");

    println!("\nAttempting to authenticate...");
    
    // Attempt to authenticate the user
    match ad_authenticate(username, password).await {
        Ok(response) => println!("Success: {}", response.message),
        Err(err) => {
            eprintln!("Authentication Error:");
            eprintln!("--------------------");
            eprintln!("{}", err);
            eprintln!("\nPlease check:");
            eprintln!("1. Your username and password are correct");
            eprintln!("2. The LDAP server is accessible");
            eprintln!("3. The server's SSL/TLS certificate is valid");
        }
    }
}
