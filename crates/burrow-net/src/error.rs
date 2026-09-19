#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("no free /30 blocks left in the sandbox address pool")]
    AddressPoolExhausted,

    #[error("node index {index} is outside the pool: only {max} nodes are addressable")]
    NodeIndexOutOfRange { index: u32, max: u32 },

    #[error("lease block {block} is outside this node's range {first}..{end}")]
    LeaseBlockOutOfRange { block: u32, first: u32, end: u32 },

    #[error("lease block {block} is already reserved by sandbox {sandbox_id}")]
    LeaseBlockInUse { block: u32, sandbox_id: String },

    #[error("{command} failed ({status}): {stderr}")]
    Command {
        command: String,
        status: String,
        stderr: String,
    },
}

pub type Result<T> = std::result::Result<T, NetError>;
