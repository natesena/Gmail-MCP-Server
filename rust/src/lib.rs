//! Gmail MCP server: one process serving one or more Gmail accounts.

pub mod accounts;
pub mod auth;
pub mod config;
pub mod gmail;
pub mod handlers;
pub mod mcp;
pub mod message;
pub mod mime;
pub mod scopes;
pub mod tools;
