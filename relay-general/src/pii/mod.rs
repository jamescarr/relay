//! PII stripping processor.

mod builtin;
mod compiledconfig;
mod config;
mod convert;
mod generate_selectors;
mod legacy;
mod processor;
mod redactions;
mod utils;

pub use self::builtin::BUILTIN_RULES;
pub use self::compiledconfig::CompiledPiiConfig;
pub use self::config::{
    AliasRule, MultipleRule, Pattern, PatternRule, PiiConfig, RedactPairRule, RuleSpec, RuleType,
    Vars,
};
pub use self::generate_selectors::selector_suggestions_from_value;
pub use self::legacy::DataScrubbingConfig;
pub use self::processor::PiiProcessor;
pub use self::redactions::{
    HashAlgorithm, HashRedaction, MaskRedaction, Redaction, ReplaceRedaction,
};
