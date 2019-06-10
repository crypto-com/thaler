//! Input selection operations
use crate::unspent_transactions::{Operation, Sorter};

/// Different strategies for input selection
#[derive(Debug)]
pub enum InputSelectionStrategy {
    /// Selects unspent transactions with highest value first
    HighestValueFirst,
    /// Selects unspent transactions with lowest value first
    LowestValueFirst,
    /// Selects unspent transactions randomly
    Random,
}

impl Default for InputSelectionStrategy {
    #[inline]
    fn default() -> Self {
        InputSelectionStrategy::HighestValueFirst
    }
}

impl AsRef<[Operation]> for InputSelectionStrategy {
    fn as_ref(&self) -> &[Operation] {
        match self {
            InputSelectionStrategy::HighestValueFirst => {
                &[Operation::Sort(Sorter::HighestValueFirst)]
            }
            InputSelectionStrategy::LowestValueFirst => {
                &[Operation::Sort(Sorter::LowestValueFirst)]
            }
            InputSelectionStrategy::Random => &[],
        }
    }
}
