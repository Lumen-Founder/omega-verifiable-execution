// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title Data availability for OVM-0 claims: a program and its inputs must be published before anyone can claim
///  a result for them.
/// @notice publish() takes the program and inputs as calldata, checks them exactly as vm.check_program / vm.initial
///  do, and computes on chain the same commitments as omega_compute/evm_step.py (keccak Merkle roots over
///  keccak(abi.encode(i, op, imm)) and keccak(abi.encode(i, x)), padded with zero leaves to a power of two, then
///  keccak(abi.encode(root, n))). The program and inputs are also logged, so watchers rebuild them from the event
///  whoever the caller was (an EOA or a smart account forwarding the call), and a claim can never be about a
///  computation they cannot re-execute. Logs are only as available as the chain's history (EIP-4444 expiry), so the
///  inbox records when data was last published and OVM0Dispute only takes claims within daMaxAge of that; publishing
///  again re-emits the data and refreshes the time.
contract OVM0Inbox {
    uint256 internal constant N_OPS = 17;
    uint256 internal constant MOD = 2 ** 64;
    uint256 internal constant MAX_PROGRAM = 4096;
    uint256 internal constant MAX_INPUTS = 1024;
    // opcodes that carry an immediate (PUSH DUP SWAP JMP JZ LOAD, in vm.OPS order)
    uint256 internal constant WITH_IMM = (1 << 0) | (1 << 2) | (1 << 3) | (1 << 11) | (1 << 12) | (1 << 13);

    mapping(bytes32 => uint64) public publishedAt; // keccak(abi.encode(programCommitment, inputsCommitment)) -> time

    event Published(bytes32 indexed prog, bytes32 indexed inputs, address indexed publisher, uint256[] ops,
                    uint256[] imms, uint256[] values);

    error BadProgram();
    error BadInputs();

    function key(bytes32 prog, bytes32 inputs) public pure returns (bytes32) {
        return keccak256(abi.encode(prog, inputs));
    }

    function isPublished(bytes32 prog, bytes32 inputs) external view returns (bool) {
        return publishedAt[key(prog, inputs)] != 0;
    }

    /// @return when (prog, inputs) was last published, 0 if never
    function lastPublished(bytes32 prog, bytes32 inputs) external view returns (uint64) {
        return publishedAt[key(prog, inputs)];
    }

    function publish(uint256[] calldata ops, uint256[] calldata imms, uint256[] calldata inputs)
        external returns (bytes32 prog, bytes32 inp)
    {
        uint256 n = ops.length;
        if (n == 0 || n > MAX_PROGRAM || imms.length != n) revert BadProgram();
        bytes32[] memory leaves = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            uint256 op = ops[i];
            if (op >= N_OPS || imms[i] >= MOD || ((WITH_IMM >> op) & 1 == 0 && imms[i] != 0)) revert BadProgram();
            leaves[i] = keccak256(abi.encode(i, op, imms[i]));
        }
        prog = keccak256(abi.encode(_root(leaves), n));
        uint256 m = inputs.length;
        if (m > MAX_INPUTS) revert BadInputs();
        leaves = new bytes32[](m);
        for (uint256 i; i < m; ++i) {
            if (inputs[i] >= MOD) revert BadInputs();
            leaves[i] = keccak256(abi.encode(i, inputs[i]));
        }
        inp = keccak256(abi.encode(_root(leaves), m));
        publishedAt[key(prog, inp)] = uint64(block.timestamp);
        emit Published(prog, inp, msg.sender, ops, imms, inputs);
    }

    /// @dev evm_step._tree: pad to a power of two with zero leaves, hash pairs up; no leaves -> 0, one leaf -> itself
    function _root(bytes32[] memory leaves) internal pure returns (bytes32) {
        uint256 size = 1;
        while (size < leaves.length) size *= 2;
        bytes32[] memory level = new bytes32[](size);
        for (uint256 i; i < leaves.length; ++i) level[i] = leaves[i];
        while (size > 1) {
            size /= 2;
            for (uint256 i; i < size; ++i) level[i] = keccak256(abi.encodePacked(level[2 * i], level[2 * i + 1]));
        }
        return level[0];
    }
}
