#![warn(rust_2018_idioms, missing_docs)]
#![allow(non_snake_case)]
//! Implementation of Broadcast encryption scheme present in paper by Dubois, Guillevic, Sengelin
//! Le Breton, "Improved Broadcast Encryption Scheme with Constant-Size Ciphertext", available
//! here https://eprint.iacr.org/2012/370.pdf

use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::UniformRand;

use rand::{CryptoRng, Rng};

/// Structure of the recipients
#[derive(Clone)]
pub struct Recipient<E: PairingEngine> {
    /// identifier
    identifier: usize,
    /// key pair
    key_pair: KeyPair<E>,
}

impl<E: PairingEngine> Recipient<E> {
    /// Decrypt a ciphertext encrypted for set `set_recipients`
    pub fn decrypt(
        &self,
        set_recipients: &[usize],
        channel: &BroadcastChannel<E>,
        ctx_0: &E::G1Projective,
        ctx_1: &E::G2Projective,
    ) -> E::Fqk {
        let mut K = E::pairing(ctx_0.clone(), self.key_pair.public_key);

        let mut g_1point_second_pairing = self.key_pair.private_key;

        for index in set_recipients.iter() {
            if *index == self.identifier {
                continue;
            }

            g_1point_second_pairing += channel.broadcaster_pk_g1
                [channel.number_participants + 1 - index + self.identifier];
        }

        let denominator_pairing = E::pairing(g_1point_second_pairing, ctx_1.clone());
        K /= denominator_pairing;

        K
    }
}

/// Key pair of recipients.
#[derive(Clone)]
pub struct KeyPair<E: PairingEngine> {
    /// public key
    public_key: E::G2Projective,
    /// private key
    private_key: E::G1Projective,
}

/// Broadcast channel. This is initiated by the trusted party, and includes all recipients
#[derive(Clone)]
pub struct BroadcastChannel<E: PairingEngine> {
    number_participants: usize,
    broadcaster_pk_g1: Vec<E::G1Projective>,
    broadcaster_pk_g2: Vec<E::G2Projective>,
}

impl<E: PairingEngine> BroadcastChannel<E> {
    /// Init broadcast channel. This needs to be performed by a trusted entity
    pub fn init_participants<R>(n: usize, rng: &mut R) -> (Self, Vec<Recipient<E>>)
    where
        R: Rng + CryptoRng,
    {
        let generator_p = E::G1Projective::prime_subgroup_generator();
        let generator_q = E::G2Projective::prime_subgroup_generator();

        let alpha = E::Fr::rand(rng);

        // vectors containing the generated points
        let mut p_points_vec: Vec<E::G1Projective> = Vec::new();
        p_points_vec.push(generator_p);
        let mut q_points_vec: Vec<E::G2Projective> = Vec::new();
        q_points_vec.push(generator_q);

        // counter to keep the state of each multiplication by \alpha
        let mut counter_p = generator_p;
        let mut counter_q = generator_q;

        for _ in 0..2 * n {
            counter_p *= alpha;
            p_points_vec.push(counter_p);
        }

        // now we remove values at position n + 1
        // p_points_vec.remove(n+1);

        for _ in 0..n {
            counter_q *= alpha;
            q_points_vec.push(counter_q);
        }

        // Now we proceed with the generation of the keys
        let gamma = E::Fr::rand(rng);
        let mut point_v = E::G1Projective::prime_subgroup_generator();
        point_v *= gamma;

        let mut participants: Vec<Recipient<E>> = Vec::new();

        for i in 1..(n + 1) {
            let mut secret_key = p_points_vec[i];
            secret_key *= gamma;

            let key_pair = KeyPair {
                public_key: q_points_vec[i],
                private_key: secret_key,
            };

            participants.push(Recipient {
                identifier: i,
                key_pair,
            });
        }

        // we append the V vector to the G1 points. This is not super elegant, but functional
        p_points_vec.push(point_v);

        let parameters = BroadcastChannel {
            number_participants: n,
            broadcaster_pk_g1: p_points_vec,
            broadcaster_pk_g2: q_points_vec[..2].to_vec(),
        };

        (parameters, participants)
    }

    /// Encrypt for set of recipients. To be precise, what we do here is generate the symmetric
    /// key.
    pub fn encrypt<R>(
        &self,
        set_recipients: &[usize],
        rng: &mut R,
    ) -> (E::G1Projective, E::G2Projective, E::Fqk)
    where
        R: Rng + CryptoRng,
    {
        let k = E::Fr::rand(rng);
        let mut g_2_point = self.broadcaster_pk_g2[1];
        g_2_point *= k;
        let K = E::pairing(self.broadcaster_pk_g1[self.number_participants], g_2_point);

        let mut header_point_in_g2 = self.broadcaster_pk_g2[0];
        header_point_in_g2 *= k;

        let mut header_point_in_g1 = *self.broadcaster_pk_g1.last().unwrap();

        for index in set_recipients.iter() {
            header_point_in_g1 += self.broadcaster_pk_g1[self.number_participants + 1 - index];
        }

        header_point_in_g1 *= k;

        (header_point_in_g1, header_point_in_g2, K)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use rand::thread_rng;

    #[test]
    fn it_works() {
        let number_participants = 10usize;
        let mut rng = thread_rng();

        let (channel, participants) =
            BroadcastChannel::<Bls12_381>::init_participants(number_participants, &mut rng);

        assert_eq!(participants.clone().len(), number_participants);

        let recipients = vec![1, 3, 5];

        let (ctx_0, ctx_1, ctx_2) = channel.encrypt(&recipients, &mut rng);

        let participant_1: Recipient<Bls12_381> = participants[0].clone();
        let participant_2: Recipient<Bls12_381> = participants[1].clone();
        let participant_3: Recipient<Bls12_381> = participants[2].clone();

        let dec_key_1 = participant_1.decrypt(&recipients, &channel, &ctx_0, &ctx_1);
        assert_eq!(ctx_2, dec_key_1);

        let dec_key_2 = participant_2.decrypt(&recipients, &channel, &ctx_0, &ctx_1);
        assert_ne!(ctx_2, dec_key_2);

        let dec_key_3 = participant_3.decrypt(&recipients, &channel, &ctx_0, &ctx_1);
        assert_eq!(ctx_2, dec_key_3);
    }
}
