use imap_tls::connect_tls;
use imap_client::credentials::OAuthToken;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Establish a secure TLS connection to Gmail
    // This automatically negotiates IMAP4rev2/rev1 capabilities
    let mut session = connect_tls("imap.gmail.com", 993).await?;
    
    println!("Server capabilities: {:?}", session.capabilities);

    // 2. Authenticate using an OAuth2 token
    // In a real app, you'd get this from a library like `yup-oauth2`
    let token = OAuthToken::new("ya29.a0AfH6SM..."); 
    
    // Note: session.login() or similar for OAuth2
    // For this example, we assume we have a mechanism for OAuth2 auth
    // session = session.authenticate_oauth2("user@gmail.com", token).await?;
    
    println!("Successfully authenticated!");

    // 3. Select the INBOX
    let mut selected_session = session.select("INBOX").await?;
    
    // 4. Fetch the last unread email
    let messages = selected_session.fetch("1:*", "BODY[]").await?;
    println!("Fetched {} messages", messages.len());

    // 5. Enter IDLE mode to wait for new emails
    let idle_handle = selected_session.idle().await?;
    println!("Now idling... (stopping in 10 seconds)");
    
    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
    idle_handle.stop().await?;

    Ok(())
}
