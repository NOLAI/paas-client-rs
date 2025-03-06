use log::info;
use openid::{DiscoveredClient, Options};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::string::ToString;
use url::Url;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OIDCConfig {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub issuer_url: String,
    pub redirect_url: String,
    pub scopes: Vec<String>,
}

pub async fn authenticate_oidc(
    oidc_config: &OIDCConfig,
) -> Result<(String, u64), Box<dyn std::error::Error>> {
    let issuer = Url::parse(&oidc_config.issuer_url)?;

    info!("Initiating OIDC discovery for issuer: {}", issuer);

    let client = match DiscoveredClient::discover(
        oidc_config.client_id.clone(),
        oidc_config.client_secret.clone().unwrap_or_default(),
        Some(oidc_config.redirect_url.clone()),
        issuer,
    )
    .await
    {
        Ok(client) => client,
        Err(e) => {
            return Err(format!("OIDC discovery failed: {}", e).into());
        }
    };

    info!("Discovery successful");

    let redirect_url = Url::parse(&oidc_config.redirect_url)?;
    let host = redirect_url
        .host_str()
        .ok_or("Missing host in redirect URL")?;
    let port = redirect_url.port().ok_or("Missing port in redirect URL")?;
    let server_addr = format!("{}:{}", host, port);

    // Start local server to receive the callback before we open the browser
    info!("Starting local server at {}", server_addr);
    let listener = TcpListener::bind(server_addr)?;

    // Generate a secure random state parameter for CSRF protection
    let csrf_token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // Create authorization options with our custom state
    let options = Options {
        scope: Some(oidc_config.scopes.join(" ")),
        state: Some(csrf_token.clone()),
        ..Default::default()
    };

    // Generate the authorization URL
    let mut auth_url = client.auth_url(&options);

    // Confirm our state param is in the URL
    if !auth_url
        .query_pairs()
        .any(|(key, value)| key == "state" && value == csrf_token)
    {
        // If not, we need to add it manually
        auth_url.query_pairs_mut().append_pair("state", &csrf_token);
    }

    let opened = try_open_browser(auth_url.as_ref());
    if !opened {
        println!("Please open the following URL in your browser to authenticate:");
        println!("\n    {}\n", auth_url);
    }
    println!("Waiting for authentication callback...");

    let mut auth_code = None;
    let mut state_param = None;

    // Listen for the callback
    for stream in listener.incoming() {
        let mut stream = stream?;
        let reader = BufReader::new(&stream);
        let request_line = reader.lines().next().ok_or("Empty request")??;

        if !request_line.starts_with("GET") {
            continue;
        }

        // Extract code and state from the request
        if let Some(query_start) = request_line.find('?') {
            let query_end = request_line.find(" HTTP").unwrap_or(request_line.len());
            let query = &request_line[(query_start + 1)..query_end];

            for pair in query.split('&') {
                if let Some(eq_pos) = pair.find('=') {
                    let (key, value) = pair.split_at(eq_pos);
                    let value = &value[1..]; // Remove the '='

                    // URL decode the value
                    let decoded_value = urlencoding::decode(value)
                        .map_err(|e| format!("Failed to decode URL parameter: {}", e))?
                        .into_owned();

                    if key == "code" {
                        auth_code = Some(decoded_value);
                    } else if key == "state" {
                        state_param = Some(decoded_value);
                    }
                }
            }
        }

        // Send success response back to the browser
        let response = auth_success_response();
        stream.write_all(response.as_bytes())?;

        if auth_code.is_some() {
            break;
        }
    }

    // Verify state and exchange code for token
    match (auth_code, state_param) {
        (Some(code), Some(state)) if state == csrf_token => {
            info!("Exchanging authorization code for tokens...");

            // Request the token using the authorization code
            let token_result = client.request_token(&code).await?;

            // Calculate expiration time
            let expires_in = token_result.expires_in.unwrap_or(3600); // Default to 1 hour if not specified
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let expiry_time = current_time + expires_in;

            info!("Authentication successful");
            Ok((token_result.access_token.to_string(), expiry_time))
        }
        (_, Some(state)) if state != csrf_token => Err(format!(
            "CSRF token mismatch - authentication failed. Expected: '{}', Got: '{}'",
            csrf_token, state
        )
        .into()),
        _ => Err("Failed to receive authorization code from provider".into()),
    }
}
fn auth_success_response() -> String {
    r#"HTTP/1.1 200 OK
Content-Type: text/html

<!DOCTYPE html>
<html>
<head>
    <title>PAASCLI authentication successful</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            text-align: center;
            margin-top: 50px;
            background-color: #f5f5f5;
        }
        .container {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            padding: 30px;
            max-width: 500px;
            margin: 0 auto;
        }
        h1 {
            color: #4CAF50;
        }
        .system-id {
            font-weight: bold;
            color: #2196F3;
        }
        .countdown {
            margin: 20px 0;
            font-size: 1.2em;
            font-weight: bold;
        }
    </style>
    <script>
        // Close the window automatically after a countdown
        let countdown = 5;
        function updateCountdown() {
            document.getElementById('seconds').textContent = countdown;
            if (countdown <= 0) {
                window.close();
                // Fallback message if the window doesn't close
                document.getElementById('countdown-message').innerHTML = 'You can now close this window manually.';
            } else {
                countdown--;
                setTimeout(updateCountdown, 1000);
            }
        }
        window.onload = updateCountdown;
    </script>
</head>
<body>
    <div class='container'>
        <h1>Authentication successful!</h1>
        <p>PAASCLI has successfully received authentication</p>
        <p class='countdown' id='countdown-message'>This window will close automatically in <span id='seconds'>5</span> seconds...</p>
    </div>
</body>
</html>"#.to_string()
}

#[cfg(feature = "browser")]
fn try_open_browser(url: &str) -> bool {
    match webbrowser::open(url) {
        Ok(_) => {
            println!("Browser opened for authentication. Waiting for callback...");
            true
        }
        Err(e) => {
            println!("Unable to open browser automatically: {}", e);
            false
        }
    }
}

#[cfg(not(feature = "browser"))]
fn try_open_browser(_url: &str) -> bool {
    false
}
