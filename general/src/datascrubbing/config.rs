use serde::{Deserialize, Serialize};

use lazycell::AtomicLazyCell;

use crate::datascrubbing::convert::to_pii_config;
use crate::pii::PiiConfig;

/// Helper method to check whether a flag is false.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_flag_default(flag: &bool) -> bool {
    !*flag
}

/// Configuration for Sentry's datascrubbing
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct DataScrubbingConfig {
    /// List with the fields to be excluded.
    pub exclude_fields: Vec<String>,
    /// Toggles all data scrubbing on or off.
    #[serde(skip_serializing_if = "is_flag_default")]
    pub scrub_data: bool,
    /// Should ip addresses be scrubbed from messages?
    #[serde(skip_serializing_if = "is_flag_default")]
    pub scrub_ip_addresses: bool,
    /// List of sensitive fields to be scrubbed from the messages.
    pub sensitive_fields: Vec<String>,
    /// Controls whether default fields will be scrubbed.
    #[serde(skip_serializing_if = "is_flag_default")]
    pub scrub_defaults: bool,

    /// PII config derived from datascrubbing settings.
    ///
    /// Cached because the conversion process is expensive.
    #[serde(skip, default = "AtomicLazyCell::new")]
    pub(super) pii_config: AtomicLazyCell<Option<PiiConfig>>,
}

impl DataScrubbingConfig {
    /// Returns true if datascrubbing is disabled.
    pub fn is_disabled(&self) -> bool {
        !self.scrub_data && !self.scrub_ip_addresses
    }

    /// Get the PII config derived from datascrubbing settings.
    pub fn pii_config(&self) -> Option<&PiiConfig> {
        if let Some(ref pii_config) = self.pii_config.borrow() {
            pii_config.as_ref()
        } else {
            let pii_config = to_pii_config(&self);
            let _ = self.pii_config.fill(pii_config);
            self.pii_config
                .borrow()
                .expect("filled lazycell for datascrubbing settings, but cell is still empty")
                .as_ref()
        }
    }
}

impl Default for DataScrubbingConfig {
    fn default() -> DataScrubbingConfig {
        DataScrubbingConfig {
            exclude_fields: Default::default(),
            scrub_data: true,
            scrub_ip_addresses: true,
            sensitive_fields: Default::default(),
            scrub_defaults: true,
            pii_config: AtomicLazyCell::new(),
        }
    }
}