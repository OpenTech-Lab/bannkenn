#[tokio::main]
async fn main() -> anyhow::Result<()> {
    bannkenn_server::app::main_entry().await
}
