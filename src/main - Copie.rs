use aes_gcm::{Aes256Gcm, Nonce, KeyInit};
use aes_gcm::aead::Aead; // Aead trait for encryption
use generic_array::GenericArray;
use oracle::{Connection, Error}; // Import necessary modules for Oracle connection

// Function to encrypt credentials
fn encrypt_credentials(plaintext: &str, key: &[u8], nonce: &[u8]) -> Vec<u8> {
    let key = GenericArray::from_slice(key); // Define the key type explicitly
    let cipher = Aes256Gcm::new(key);

    cipher.encrypt(Nonce::from_slice(nonce), plaintext.as_bytes())
        .expect("Encryption failed")
}

// Function to test connection to Oracle database
fn test_connection(username: &str, password: &str, connection_string: &str) -> Result<(), Error> {
    let conn = Connection::connect(username, password, connection_string)?;
    println!("Successfully connected to the database: {}", connection_string);
    conn.close()?;
    Ok(())
}

fn main() {
    // Define your encryption key (32 bytes) and nonce (12 bytes)
    let key = b"0123456789abcdef0123456789abcdef"; // 32 bytes
    let nonce = b"unique nonce"; // 12 bytes

    // Define plaintext credentials for each environment
    let environments = vec![
        ("HOME", "DESKTOP-JV7OH8A/XE=IMAL=IMAL", "username1", "password1"),
        ("WIB_LOCAL", "= = ", "username2", "password2"),
        ("PROD_WIB", "10.210.150.3/imal=MOA1=Hamza", "username3", "password3"),
        ("UAT_WIB", "10.210.140.55/IMAL=IMAL=Azerty123", "username4", "password4"),
        ("CAC_WIB", "10.210.140.35/IMAL=IMAL=Azerty123", "username5", "password5"),
        ("J_1_WIB", "10.210.140.11/IMALJ=IMAL=IMAL3258", "username6", "password6"), // Use underscores
    ];

    // Create a vector to hold encrypted credentials
    let mut encrypted_credentials = Vec::new();

    // Encrypt credentials for each environment and store them in the vector
    for (_env_name, plaintext, _, _) in &environments {  // Prefixing env_name with an underscore
        let encrypted = encrypt_credentials(plaintext, key, nonce);
        encrypted_credentials.push(encrypted);
    }

    // Print the encrypted credentials in the specified format
    println!("// Encrypted credentials for each environment");
    println!("pub const ENCRYPTED_CREDENTIALS: [&[u8]; {}] = [", encrypted_credentials.len());
    for encrypted in encrypted_credentials {
        let encrypted_str = format!("{:?}", encrypted);
        let clean_str = encrypted_str.trim_start_matches("b").replace(&['[', ']', ' '], "").replace(", ", ",");
        println!("    &[{}],", clean_str);
    }
    println!("];");

    // Test connections for each environment
    for (env_name, _, username, password) in environments {
        match test_connection(username, password, env_name) {
            Ok(_) => println!("Connection test for {} passed.", env_name),
            Err(e) => eprintln!("Connection test for {} failed: {}", env_name, e),
        }
    }
}
