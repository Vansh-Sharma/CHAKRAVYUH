// Red Team OS — Reports Module Root (D1)

pub mod redteam_report;

pub use redteam_report::{
    detection_rate_per_ring, generate_report, missed_attacks, RedTeamReportSummary, RingCell,
    RingDetectionMatrix,
};
