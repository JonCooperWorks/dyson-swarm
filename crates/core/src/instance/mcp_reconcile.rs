use crate::mcp_servers::McpAuthSpec;

/// True when the OAuth-token-bearing fields of the auth shape
/// (kind + endpoints + scopes) haven't moved.  When they have, the
/// OAuth tokens we stored under the previous shape are stale —
/// clearing them forces the user to reconnect with the new metadata.
pub(super) fn auth_shape_matches(prev: &McpAuthSpec, next: &McpAuthSpec) -> bool {
    use McpAuthSpec::*;
    match (prev, next) {
        (None, None) => true,
        (Bearer { .. }, Bearer { .. }) => true,
        (
            Oauth {
                scopes: a_s,
                authorization_url: a_a,
                token_url: a_t,
                ..
            },
            Oauth {
                scopes: b_s,
                authorization_url: b_a,
                token_url: b_t,
                ..
            },
        ) => a_s == b_s && a_a == b_a && a_t == b_t,
        _ => false,
    }
}

/// Static placeholder the SPA's MCP edit form pre-fills into
/// secret-bearing inputs — bullets, fixed length.  When the
/// inbound auth spec carries this verbatim, swarm interprets it
/// as "keep the existing sealed value" and the field on the row
/// is left untouched.  Picked to be a string a real API token
/// can't realistically contain, so a user typing this exact
/// pattern by accident is a non-concern.
pub(crate) const MCP_KEEP_TOKEN: &str = "••••••••";

/// Replace any [`MCP_KEEP_TOKEN`] sentinels in `next` with the
/// corresponding plaintext from `prev` so the SPA's "leave it
/// alone" UX round-trips without making the swarm re-decrypt.
/// Caller must have already verified `auth_shape_matches` —
/// otherwise the fields don't line up.
pub(super) fn keep_existing_secrets(prev: &McpAuthSpec, next: &mut McpAuthSpec) {
    use McpAuthSpec::*;
    match (prev, next) {
        (Bearer { token: prev_token }, Bearer { token: next_token }) => {
            if next_token == MCP_KEEP_TOKEN {
                *next_token = prev_token.clone();
            }
        }
        (
            Oauth {
                client_secret: Some(prev_cs),
                ..
            },
            Oauth {
                client_secret: Some(next_cs),
                ..
            },
        ) => {
            if next_cs == MCP_KEEP_TOKEN {
                *next_cs = prev_cs.clone();
            }
        }
        _ => {}
    }
}
