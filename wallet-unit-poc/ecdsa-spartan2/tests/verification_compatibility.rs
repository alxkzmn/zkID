#![cfg(not(target_arch = "wasm32"))]

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ecdsa_spartan2::{prover::verify_linked, Scalar, E};
use ff::Field;
use spartan2::{
    traits::{circuit::SpartanCircuit, snark::R1CSSNARKTrait},
    zk_spartan::R1CSSNARK,
};

type Proof = R1CSSNARK<E>;

#[derive(Clone, Debug)]
struct TinyCircuit {
    shared: bool,
    value: u64,
    offset: u64,
}

impl TinyCircuit {
    fn public_value(&self) -> Scalar {
        let value = Scalar::from(self.value);
        value.square() + Scalar::from(self.offset)
    }
}

impl SpartanCircuit<E> for TinyCircuit {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![self.public_value()])
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        if self.shared {
            Ok(vec![AllocatedNum::alloc(
                cs.namespace(|| "shared x"),
                || Ok(Scalar::from(self.value)),
            )?])
        } else {
            Ok(vec![])
        }
    }

    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        _: &mut CS,
        _: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }

    fn num_challenges(&self) -> usize {
        0
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let local_x;
        let x = if self.shared {
            assert_eq!(shared.len(), 1, "fixture must allocate one shared variable");
            &shared[0]
        } else {
            local_x =
                AllocatedNum::alloc(cs.namespace(|| "local x"), || Ok(Scalar::from(self.value)))?;
            &local_x
        };
        let square = x.square(cs.namespace(|| "x squared"))?;
        let y = AllocatedNum::alloc(cs.namespace(|| "public y"), || Ok(self.public_value()))?;
        cs.enforce(
            || "y = x squared + offset",
            |lc| lc + square.get_variable() + (Scalar::from(self.offset), CS::one()),
            |lc| lc + CS::one(),
            |lc| lc + y.get_variable(),
        );
        y.inputize(cs.namespace(|| "y output"))?;
        Ok(())
    }
}

fn prove(circuit: TinyCircuit) -> (Proof, spartan2::zk_spartan::SpartanVerifierKey<E>) {
    let (pk, vk) = Proof::setup(circuit.clone()).unwrap();
    let prepared = Proof::prep_prove(&pk, circuit.clone(), false).unwrap();
    (Proof::prove(&pk, circuit, &prepared, false).unwrap(), vk)
}

fn roundtrip<T: serde::Serialize + serde::de::DeserializeOwned>(value: &T) -> T {
    let bytes = bincode::serialize(value).unwrap();
    let decoded = bincode::deserialize(&bytes).unwrap();
    assert_eq!(bincode::serialize(&decoded).unwrap(), bytes);
    decoded
}

#[test]
fn linked_verifier_accepts_matching_witnesses_and_rejects_mismatches() {
    let shared = TinyCircuit {
        shared: true,
        value: 2,
        offset: 5,
    };
    let (pk, vk) = Proof::setup(shared.clone()).unwrap();
    let prepared = Proof::prep_prove(&pk, shared.clone(), false).unwrap();
    let prepare = Proof::prove(&pk, shared.clone(), &prepared, false).unwrap();
    let show = Proof::prove(&pk, shared.clone(), &prepared, false).unwrap();
    let changed = TinyCircuit {
        value: 3,
        ..shared.clone()
    };
    let changed_prepared = Proof::prep_prove(&pk, changed.clone(), false).unwrap();
    let different = Proof::prove(&pk, changed, &changed_prepared, false).unwrap();
    let (missing, missing_vk) = prove(TinyCircuit {
        shared: false,
        ..shared.clone()
    });
    let (_, wrong_vk) = Proof::setup(TinyCircuit {
        offset: 6,
        ..shared
    })
    .unwrap();

    let expected = Some((vec![Scalar::from(9)], vec![Scalar::from(9)]));
    assert_eq!(verify_linked(&prepare, &vk, &show, &vk), expected);
    assert!(verify_linked(&prepare, &vk, &different, &vk).is_none());
    assert!(verify_linked(&missing, &missing_vk, &missing, &missing_vk).is_none());
    assert!(verify_linked(&prepare, &wrong_vk, &show, &vk).is_none());
    assert!(verify_linked(&prepare, &vk, &show, &wrong_vk).is_none());

    // Deserializing the key clears its digest cache. Both its first use and
    // subsequent uses must preserve the linked verifier's result.
    let cold_key = roundtrip(&vk);
    for _ in 0..2 {
        assert_eq!(
            verify_linked(&prepare, &cold_key, &show, &cold_key),
            expected
        );
    }
    let decoded_prepare = roundtrip(&prepare);
    let decoded_show = roundtrip(&show);
    assert_eq!(
        verify_linked(&decoded_prepare, &cold_key, &decoded_show, &cold_key),
        expected
    );
    roundtrip(&different);
    roundtrip(&missing);
    roundtrip(&missing_vk);
    roundtrip(&wrong_vk);
}
