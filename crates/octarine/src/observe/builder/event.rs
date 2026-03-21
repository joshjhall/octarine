//! Event extensions for ObserveBuilder
//!
//! Provides logging methods that delegate to EventBuilder internally.

use super::ObserveBuilder;
use crate::observe::event::EventBuilder;

/// Extensions for ObserveBuilder related to event logging
impl ObserveBuilder {
    /// Log as debug
    pub fn debug(self) {
        EventBuilder::new(&self.message)
            .with_context(self.build_context())
            .with_metadata_map(self.metadata)
            .debug();
    }

    /// Log as info
    pub fn info(self) {
        EventBuilder::new(&self.message)
            .with_context(self.build_context())
            .with_metadata_map(self.metadata)
            .info();
    }

    /// Log as warning
    pub fn warn(self) {
        EventBuilder::new(&self.message)
            .with_context(self.build_context())
            .with_metadata_map(self.metadata)
            .warn();
    }

    /// Log as error
    pub fn error(self) {
        EventBuilder::new(&self.message)
            .with_context(self.build_context())
            .with_metadata_map(self.metadata)
            .error();
    }

    /// Log as success
    pub fn success(self) {
        EventBuilder::new(&self.message)
            .with_context(self.build_context())
            .with_metadata_map(self.metadata)
            .success();
    }

    /// Log as trace
    pub fn trace(self) {
        EventBuilder::new(&self.message)
            .with_context(self.build_context())
            .with_metadata_map(self.metadata)
            .trace();
    }

    /// Log as critical
    pub fn critical(self) {
        EventBuilder::new(&self.message)
            .with_context(self.build_context())
            .with_metadata_map(self.metadata)
            .critical();
    }
}
