use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    println!("TUI has been removed for now.");
    println!("Use the web UI in web-ui/ and run backend services via docker-compose.");
    println!("A dedicated CLI can be added later without reintroducing terminal UI code.");
    Ok(())
}
