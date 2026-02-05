//! Fast Fourier Sampling for Falcon.

use crate::fft::{add_fft, adj_fft, div_fft, merge_fft, mul_fft, split_fft, sub_fft, Complex};
use crate::samplerz::samplerz;

/// LDL decomposition tree node.
#[derive(Clone)]
pub enum LdlTree {
    /// Leaf node with sigma value.
    Leaf(f64),
    /// Internal node with l10 polynomial and two children.
    Node {
        l10: Vec<Complex>,
        left: Box<LdlTree>,
        right: Box<LdlTree>,
    },
}

/// Compute Gram matrix of B (2x2 matrix of polynomials in FFT representation).
/// G[i][j] = sum_k B[i][k] * adj(B[j][k])
pub fn gram(b: &[[Vec<Complex>; 2]; 2]) -> [[Vec<Complex>; 2]; 2] {
    let n = b[0][0].len();
    let mut g = [
        [vec![Complex::ZERO; n], vec![Complex::ZERO; n]],
        [vec![Complex::ZERO; n], vec![Complex::ZERO; n]],
    ];

    for i in 0..2 {
        for j in 0..2 {
            for k in 0..2 {
                let prod = mul_fft(&b[i][k], &adj_fft(&b[j][k]));
                g[i][j] = add_fft(&g[i][j], &prod);
            }
        }
    }
    g
}

/// LDL decomposition of 2x2 Gram matrix in FFT representation.
/// Returns (L, D) where G = L * D * L^*
pub fn ldl_fft(g: &[[Vec<Complex>; 2]; 2]) -> ([[Vec<Complex>; 2]; 2], [[Vec<Complex>; 2]; 2]) {
    let n = g[0][0].len();
    let zero = vec![Complex::ZERO; n];
    let one = vec![Complex::ONE; n];

    let d00 = g[0][0].clone();
    let l10 = div_fft(&g[1][0], &g[0][0]);
    let l10_adj = adj_fft(&l10);
    let l10_l10_adj = mul_fft(&l10, &l10_adj);
    let d11 = sub_fft(&g[1][1], &mul_fft(&l10_l10_adj, &g[0][0]));

    let l = [[one.clone(), zero.clone()], [l10, one]];
    let d = [[d00, zero.clone()], [zero, d11]];

    (l, d)
}

/// Compute ffLDL decomposition tree.
/// The tree structure mirrors the recursive FFT splitting.
pub fn ffldl_fft(g: &[[Vec<Complex>; 2]; 2]) -> LdlTree {
    let n = g[0][0].len();
    let (l, d) = ldl_fft(g);

    if n > 1 {
        let (d00_0, d00_1) = split_fft(&d[0][0]);
        let (d11_0, d11_1) = split_fft(&d[1][1]);

        // Build Gram matrices for recursion
        // g0 corresponds to d00, g1 corresponds to d11
        let g0 = [
            [d00_0.clone(), d00_1.clone()],
            [adj_fft(&d00_1), d00_0],
        ];
        let g1 = [
            [d11_0.clone(), d11_1.clone()],
            [adj_fft(&d11_1), d11_0],
        ];

        LdlTree::Node {
            l10: l[1][0].clone(),
            left: Box::new(ffldl_fft(&g0)),
            right: Box::new(ffldl_fft(&g1)),
        }
    } else {
        // Leaf: store sigma = sqrt(d[0][0].re)
        LdlTree::Leaf(d[0][0][0].re.sqrt())
    }
}

/// Normalize LDL tree leaves (from ||b_i||^2 to sigma/||b_i||).
/// After this, leaves contain the scaled sigma values for sampling.
pub fn normalize_tree(tree: &mut LdlTree, sigma: f64) {
    match tree {
        LdlTree::Leaf(ref mut val) => {
            *val = sigma / *val;
        }
        LdlTree::Node { left, right, .. } => {
            normalize_tree(left, sigma);
            normalize_tree(right, sigma);
        }
    }
}

/// Fast Fourier Sampling.
///
/// Given target t (in FFT representation) and LDL tree,
/// sample z such that (z - t) follows discrete Gaussian distribution.
pub fn ffsampling_fft<F: FnMut(usize) -> Vec<u8>>(
    t: &[Vec<Complex>; 2],
    tree: &LdlTree,
    sigmin: f64,
    random_bytes: &mut F,
) -> [Vec<Complex>; 2] {
    match tree {
        LdlTree::Leaf(sigma) => {
            // Base case: sample two integers from discrete Gaussian
            let z0 = samplerz(t[0][0].re, *sigma, sigmin, random_bytes);
            let z1 = samplerz(t[1][0].re, *sigma, sigmin, random_bytes);
            [
                vec![Complex::new(z0 as f64, 0.0)],
                vec![Complex::new(z1 as f64, 0.0)],
            ]
        }
        LdlTree::Node { l10, left, right } => {
            // Recursive case: sample z1 first, then z0 conditioned on z1
            let (t1_0, t1_1) = split_fft(&t[1]);
            let z1_split = ffsampling_fft(&[t1_0, t1_1], right, sigmin, random_bytes);
            let z1 = merge_fft(&z1_split[0], &z1_split[1]);

            // Compute t0' = t0 + (t1 - z1) * l10
            let diff = sub_fft(&t[1], &z1);
            let t0b = add_fft(&t[0], &mul_fft(&diff, l10));

            let (t0b_0, t0b_1) = split_fft(&t0b);
            let z0_split = ffsampling_fft(&[t0b_0, t0b_1], left, sigmin, random_bytes);
            let z0 = merge_fft(&z0_split[0], &z0_split[1]);

            [z0, z1]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ldl_fft_basic() {
        // Create a simple 2x2 Gram matrix in FFT form
        // Use identity-like structure for basic sanity check
        let n = 4;
        let one = vec![Complex::ONE; n];
        let half = vec![Complex::new(0.5, 0.0); n];

        // G = [[1, 0.5], [0.5, 1]] (diagonal dominant, positive definite)
        let g = [[one.clone(), half.clone()], [half.clone(), one.clone()]];

        let (l, d) = ldl_fft(&g);

        // L should be lower triangular with ones on diagonal
        assert_eq!(l[0][0][0], Complex::ONE);
        assert_eq!(l[1][1][0], Complex::ONE);
        assert_eq!(l[0][1][0], Complex::ZERO);

        // D should be diagonal
        assert_eq!(d[0][1][0], Complex::ZERO);
        assert_eq!(d[1][0][0], Complex::ZERO);

        // D[0][0] = G[0][0] = 1
        assert!((d[0][0][0].re - 1.0).abs() < 1e-10);

        // D[1][1] = G[1][1] - L[1][0]^2 * G[0][0] = 1 - 0.25 = 0.75
        assert!((d[1][1][0].re - 0.75).abs() < 1e-10);
    }

    #[test]
    fn test_ffldl_tree_structure() {
        // Create a simple Gram matrix for n=4
        let n = 4;
        let one = vec![Complex::ONE; n];
        let zero = vec![Complex::ZERO; n];

        // Identity Gram matrix
        let g = [[one.clone(), zero.clone()], [zero.clone(), one.clone()]];

        let tree = ffldl_fft(&g);

        // Root should be a Node (n=4 > 1)
        match &tree {
            LdlTree::Node { left, .. } => {
                // At n=2, children should also be nodes
                match left.as_ref() {
                    LdlTree::Node { left: ll, .. } => {
                        // At n=1, we should have a Leaf
                        assert!(matches!(ll.as_ref(), LdlTree::Leaf(_)));
                    }
                    _ => panic!("Expected Node at depth 1"),
                }
            }
            LdlTree::Leaf(_) => panic!("Expected Node at root"),
        }
    }

    #[test]
    fn test_normalize_tree() {
        let mut tree = LdlTree::Node {
            l10: vec![Complex::ZERO; 2],
            left: Box::new(LdlTree::Leaf(2.0)),
            right: Box::new(LdlTree::Leaf(4.0)),
        };

        normalize_tree(&mut tree, 8.0);

        match tree {
            LdlTree::Node { left, right, .. } => {
                match (*left, *right) {
                    (LdlTree::Leaf(l), LdlTree::Leaf(r)) => {
                        assert!((l - 4.0).abs() < 1e-10); // 8.0 / 2.0 = 4.0
                        assert!((r - 2.0).abs() < 1e-10); // 8.0 / 4.0 = 2.0
                    }
                    _ => panic!("Expected leaves"),
                }
            }
            _ => panic!("Expected node"),
        }
    }
}
