#![warn(rust_2018_idioms, missing_docs)]

use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::{Field, UniformRand, Zero, One};

use rand::{CryptoRng, Rng};

/// Structure of the recipients
pub struct Recipient<E: PairingEngine> {
    /// identifier
    identifier: usize,
    /// key pair
    key_pair: KeyPair<E>,
}

/// Key pair of recipients.
pub struct KeyPair<E: PairingEngine> {
    /// public key
    public_key: PublicKey<E>,
    /// private key
    private_key: PrivateKey<E>,
}

/// Public key
pub struct PublicKey<E:PairingEngine> {
    point_q: E::G2Projective,
}

/// Private key
pub struct PrivateKey<E: PairingEngine> {
    key: E::G1Projective,
}

/// Broadcast channel. This is initiated by the trusted party, and includes all recipients
pub struct BroadcastChannel<E: PairingEngine> {
    participants: Vec<Recipient<E>>,
    broadcaster_pk_g1: Vec<E::G1Projective>,
    broadcaster_pk_g2: Vec<E::G2Projective>,
}

impl<E: PairingEngine> BroadcastChannel<E> {
    pub fn init_participants<R>(n: usize, rng: &mut R,) -> Vec<Recipient<E>>
    where
        R: Rng + CryptoRng,
    {
        let generator_p = E::G1Projective::prime_subgroup_generator();
        let generator_q = E::G2Projective::prime_subgroup_generator();

        let mut alpha = E::Fr::rand(rng);

        // vectors containing the generated points
        let mut p_points_vec: Vec<E::G1Projective> = Vec::new();
        let mut q_points_vec: Vec<E::G2Projective> = Vec::new();

        // counter to keep the state of each multiplication by \alpha
        let mut counter_p = generator_p.clone();
        let mut counter_q = generator_q.clone();

        for _ in 0..2*n {
            counter_p *= alpha;
            p_points_vec.push(counter_p);
        }

        // now we remove values at position n + 1
        p_points_vec.remove(n+1);

        for _ in 0..n {
            counter_q *= alpha;
            q_points_vec.push(counter_q);
        }

        // Now we proceed with the generation of the keys
        let gamma = E::Fr::rand(rng);
        let mut point_v =  E::G1Projective::prime_subgroup_generator();
        point_v *= gamma;

        let mut participants: Vec<Recipient<E>> = Vec::new();

        for i in 0..n {
            let mut secret_key = p_points_vec[i];
            secret_key *= gamma;

            let key_pair = KeyPair{
                public_key: PublicKey{point_q: q_points_vec[i]},
                private_key: PrivateKey{key: secret_key},
            };

            participants.push(
                Recipient{
                identifier: i + 1,
                key_pair
            });
        }

        participants
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{
        Bls12_381, Fr, G1Affine, G1Projective as G1, G1Projective, G2Projective as G2,
    };
    use rand::thread_rng;

    #[test]
    fn it_works() {
        let number_participants = 10usize;
        let mut rng = thread_rng();

        let participants = BroadcastChannel::<Bls12_381>::init_participants(number_participants, &mut rng);

        assert_eq!(participants.len(), number_participants)
    }
}
