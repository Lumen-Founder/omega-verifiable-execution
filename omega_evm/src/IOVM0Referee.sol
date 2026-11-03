// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title What OVM0Dispute needs from a one-step referee, whatever its state encoding.
/// @notice A referee fixes how an OVM-0 state is committed (full state in OVM0Step, constant-size in OVM0StepM). The
///  dispute game only ever compares keccak hashes of those encodings, so it can run over either one.
interface IOVM0Referee {
    /// @dev the agreed pre-state is halted, so no successor exists
    error NoSuccessor();

    /// @return pre keccak of the supplied pre-state, post keccak of its unique successor
    function stepHash(bytes calldata preEnc, bytes calldata auxEnc, uint256 maxSteps)
        external view returns (bytes32 pre, bytes32 post);

    /// @return keccak of the encoding of vm.initial for these commitments (pc 0, empty stack and memory)
    function initialHash(bytes32 prog, bytes32 inputs) external view returns (bytes32);

    /// @notice Read what a claim reveals from its final state. `outWitness` proves the top of stack for encodings
    ///  that only commit to the stack (empty when the encoding carries the stack or the stack is empty).
    ///  `output` is the top of stack (0 if empty).
    function finalInfo(bytes calldata finalEnc, bytes calldata outWitness)
        external view returns (bool halted, bytes32 prog, bytes32 inputs, uint64 output, uint8 trap);
}
