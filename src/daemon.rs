pub struct Daemon;

impl Daemon {
    pub fn new() -> Self {
        Self
    }
    
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Starting daemon...");
        Ok(())
    }
}
