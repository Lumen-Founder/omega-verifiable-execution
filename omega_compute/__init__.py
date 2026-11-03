"""OMEGA verifiable compute: deterministic VM, trace commitments, bisection fraud proofs."""
from omega_compute.vm import ProgramError, program_hash, run, state_hash, transition
from omega_compute.merkle import Tree, verify
from omega_compute.dispute import Referee
