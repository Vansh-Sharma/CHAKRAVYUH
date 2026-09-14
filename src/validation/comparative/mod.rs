// Comparative Research Lab — D7
//
// NOT marketing. Research.
//
// Stores benchmark definitions so future releases can be compared
// against previous ones and, where appropriate, against other approaches.
// This is a research tool for understanding how CHAKRAVYUH evolves
// over time and how it compares to alternative security approaches.

pub mod benchmarks;
pub mod comparison;
pub mod store;

pub use benchmarks::{BenchmarkCategory, BenchmarkDef, BenchmarkResult, BenchmarkSuite};
pub use comparison::{ComparisonReport, ComparisonSnapshot, Delta};
pub use store::{BenchmarkStore, Query};
