//! Definition of linear combinations.

use crate::curve::bs257::Fr;
use ark_std::{
    iter::FromIterator,
    ops::{Add, Mul, Neg, Sub},
    One,
};

/// Represents a variable in a constraint system.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Variable {
    /// Represents an external input specified by a commitment.
    Committed(usize),
    /// Represents the left input of a multiplication gate.
    MultiplierLeft(usize),
    /// Represents the right input of a multiplication gate.
    MultiplierRight(usize),
    /// Represents the output of a multiplication gate.
    MultiplierOutput(usize),
    /// Represents the constant 1.
    One(),
}

impl From<Variable> for LinearCombination {
    fn from(v: Variable) -> LinearCombination {
        LinearCombination {
            terms: vec![(v, Fr::one())],
        }
    }
}

impl<S: Into<Fr>> From<S> for LinearCombination {
    fn from(s: S) -> LinearCombination {
        LinearCombination {
            terms: vec![(Variable::One(), s.into())],
        }
    }
}

// Arithmetic on variables produces linear combinations

impl Neg for Variable {
    type Output = LinearCombination;

    fn neg(self) -> Self::Output {
        -LinearCombination::from(self)
    }
}

impl<L: Into<LinearCombination>> Add<L> for Variable {
    type Output = LinearCombination;

    fn add(self, other: L) -> Self::Output {
        LinearCombination::from(self) + other.into()
    }
}

impl<L: Into<LinearCombination>> Sub<L> for Variable {
    type Output = LinearCombination;

    fn sub(self, other: L) -> Self::Output {
        LinearCombination::from(self) - other.into()
    }
}

impl<S: Into<Fr>> Mul<S> for Variable {
    type Output = LinearCombination;

    fn mul(self, other: S) -> Self::Output {
        LinearCombination {
            terms: vec![(self, other.into())],
        }
    }
}

// Arithmetic on scalars with variables produces linear combinations

impl Add<Variable> for Fr {
    type Output = LinearCombination;

    fn add(self, other: Variable) -> Self::Output {
        LinearCombination {
            terms: vec![(Variable::One(), self), (other, Fr::one())],
        }
    }
}

impl Sub<Variable> for Fr {
    type Output = LinearCombination;

    fn sub(self, other: Variable) -> Self::Output {
        LinearCombination {
            terms: vec![(Variable::One(), self), (other, -Fr::one())],
        }
    }
}

impl Mul<Variable> for Fr {
    type Output = LinearCombination;

    fn mul(self, other: Variable) -> Self::Output {
        LinearCombination {
            terms: vec![(other, self)],
        }
    }
}

/// Represents a linear combination of
/// [`Variables`](::r1cs::Variable).  Each term is represented by a
/// `(Variable, Fr)` pair.
#[derive(Clone, Debug, PartialEq)]
pub struct LinearCombination {
    pub(super) terms: Vec<(Variable, Fr)>,
}

impl Default for LinearCombination {
    fn default() -> Self {
        LinearCombination { terms: Vec::new() }
    }
}

impl FromIterator<(Variable, Fr)> for LinearCombination {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = (Variable, Fr)>,
    {
        LinearCombination {
            terms: iter.into_iter().collect(),
        }
    }
}

impl<'a> FromIterator<&'a (Variable, Fr)> for LinearCombination {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = &'a (Variable, Fr)>,
    {
        LinearCombination {
            terms: iter.into_iter().cloned().collect(),
        }
    }
}

// Arithmetic on linear combinations

impl<L: Into<LinearCombination>> Add<L> for LinearCombination {
    type Output = Self;

    fn add(mut self, rhs: L) -> Self::Output {
        self.terms.extend(rhs.into().terms.iter().cloned());
        LinearCombination { terms: self.terms }
    }
}

impl<L: Into<LinearCombination>> Sub<L> for LinearCombination {
    type Output = Self;

    fn sub(mut self, rhs: L) -> Self::Output {
        self.terms.extend(
            rhs.into()
                .terms
                .iter()
                .map(|(var, coeff)| (*var, coeff.neg())),
        );
        LinearCombination { terms: self.terms }
    }
}

impl Mul<LinearCombination> for Fr {
    type Output = LinearCombination;

    fn mul(self, other: LinearCombination) -> Self::Output {
        let out_terms = other
            .terms
            .into_iter()
            .map(|(var, scalar)| (var, scalar * self))
            .collect();
        LinearCombination { terms: out_terms }
    }
}

impl Neg for LinearCombination {
    type Output = Self;

    fn neg(mut self) -> Self::Output {
        for (_, s) in self.terms.iter_mut() {
            *s = -*s
        }
        self
    }
}

impl<S: Into<Fr>> Mul<S> for LinearCombination {
    type Output = Self;

    fn mul(mut self, other: S) -> Self::Output {
        let other = other.into();
        for (_, s) in self.terms.iter_mut() {
            *s *= other
        }
        self
    }
}
