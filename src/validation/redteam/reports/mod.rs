// Red Team OS — Reports Module Root (D1)

pub mod redteam_report;

pub use redteam_report::{
    RedTeamReportSummary, RingDetectionMatrix, RingCell,
    generate_report, detection_rate_per_ring, missed_attacks,
};
