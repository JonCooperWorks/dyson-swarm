//! Backup sinks. [`local::LocalDiskBackupSink`] (step 8) and
//! [`s3::S3BackupSink`] (step 9) both implement
//! [`crate::traits::BackupSink`] so the snapshot module can switch sinks
//! without per-call branching.

pub mod local;
pub mod s3;
