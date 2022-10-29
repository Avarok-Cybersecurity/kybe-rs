//! Algebraics
//!
//! Definiton of basic algebraic structures (Ring, Field, Polynomial, Vector, Matrix)

mod matrix;
mod polynomial;
mod polyvec;

use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Sub, SubAssign};
pub use matrix::Matrix;
pub use polynomial::Polynomial;
pub use polyvec::PolyVec;

/// Finite Group element
pub trait FiniteGroup: Sized + Eq {
    /// Check if the element is the additive identity
    fn is_zero(&self) -> bool;

    /// Returns the additive identity
    fn zero() -> Self;

    /// Returns the additive inverse of the element
    fn neg(&self) -> Self;

    /// Defines the addition of two elements
    fn add(&self, other: &Self) -> Self;

    /// Defines the substraction of two elements
    fn sub(&self, other: &Self) -> Self;
}

/// Finite Ring element
pub trait FiniteRing: Sized + Eq {
    /// Check if the element is the additive identity
    fn is_zero(&self) -> bool;

    /// Returns the additive identity
    fn zero() -> Self;

    /// Returns the additive inverse of the element
    fn neg(&self) -> Self;

    /// Defines the addition of two elements
    fn add(&self, other: &Self) -> Self;

    /// Defines the substraction of two elements
    fn sub(&self, other: &Self) -> Self;

    /// Returns the multiplicative identity
    fn one() -> Self;

    /// Defines the multiplication of two elements
    fn mul(&self, other: &Self) -> Self;
}

/// Finite field element
pub trait FiniteField: Sized + Eq + Add<Output=Self> + Sub<Output=Self> + Div<Output=Self> + Mul<Output=Self> + AddAssign + SubAssign + MulAssign + DivAssign {
    /// Check if the element is the additive identity
    fn is_zero(&self) -> bool;

    /// Returns the additive identity
    fn zero() -> Self;

    /// Returns the additive inverse of the element
    fn neg(&self) -> Self;

    /// Returns the multiplicative identity
    fn one() -> Self;

    /// Returns the dimension of the finite field
    fn dimension() -> usize;

    /// Returns the multiplicative inverse of the element
    fn inv(&self) -> Result<Self, String>;
}

/// The `Vector` trait describes the general properties of an element in a vector space.
pub trait VectorSpace<T: FiniteField> {
    /// Check if the element is the additive identity
    fn is_zero(&self) -> bool;

    /// Returns the additive identity
    fn zero() -> Self;

    /// Returns the additive inverse of the element
    fn neg(&self) -> Self;

    /// Defines the addition of two elements
    fn add(&self, other: &Self) -> Self;

    /// Defines the substraction of two elements
    fn sub(&self, other: &Self) -> Self;

    /// Returns the vector's dimension
    fn dimension() -> usize;

    /// Initialise vector type
    fn init() -> Self;

    /// Scalar multiplication
    fn mulf(&self, other: &T) -> Self;

    /// Basis vector
    fn basis_vector(position: usize) -> Self;

    /// Set coefficient
    fn set(&mut self, position: usize, value: T);

    /// Get coefficient
    fn get(&self, position: usize) -> T;

    /// Dot product
    fn dot(&self, other: &Self) -> T;
}

/// The `Vector` trait describes the general properties of an element in a module.
pub trait RingModule<T: FiniteRing> {
    /// Check if the element is the additive identity
    fn is_zero(&self) -> bool;

    /// Returns the additive identity
    fn zero() -> Self;

    /// Returns the additive inverse of the element
    fn neg(&self) -> Self;

    /// Defines the addition of two elements
    fn add(&self, other: &Self) -> Self;

    /// Defines the substraction of two elements
    fn sub(&self, other: &Self) -> Self;

    /// Returns the vector's dimension
    fn dimension() -> usize;

    /// Initialise vector type
    fn init() -> Self;

    /// Scalar multiplication
    fn mulf(&self, other: &T) -> Self;

    /// Basis vector
    fn basis_vector(position: usize) -> Self;

    /// Set coefficient
    fn set(&mut self, position: usize, value: T);

    /// Get coefficient
    fn get(&self, position: usize) -> T;

    /// Dot product
    fn dot(&self, other: &Self) -> T;
}
