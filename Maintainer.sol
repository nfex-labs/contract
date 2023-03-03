// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
pragma abicoder v2;

/*
MIT License
Copyright (c) 2023 nfex-labs

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

import {Address} from "./libraries/Address.sol";
import {MultisigUtils} from "./libraries/MultisigUtils.sol";
import {SafeMath} from "./libraries/SafeMath.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract Maintainer is Initializable, OwnableUpgradeable {
    using Address for address;

    // refer to https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md
    uint256 public SIGNATURE_SIZE;
    uint256 public VALIDATORS_SIZE_LIMIT;
    uint256 public MIN_VALIDATOR_SIZE;
    string public NAME_712;
    // if the number of verified signatures has reached `multisigThreshold_`, validators approve the tx
    uint8 public multisigThreshold_;
    address[] public validators_;

    // CHANGE_VALIDATORS_TYPEHASH = keccak256("changeValidators(address[] validators, uint8 multisigThreshold)");
    bytes32 public CHANGE_VALIDATORS_TYPEHASH;

    bytes32 private _CACHED_DOMAIN_SEPARATOR;
    uint256 private _CACHED_CHAIN_ID;
    bytes32 private _HASHED_NAME;
    bytes32 private _HASHED_VERSION;
    bytes32 private _TYPE_HASH;

    uint256 public latestChangeValidatorsNonce_;

    event validatorChanged(address[] _validators, uint8 _multisigThreshold);

    function initialize(address[] memory validators, uint8 multisigThreshold)
        public
        initializer
    {
        SIGNATURE_SIZE = 65;
        VALIDATORS_SIZE_LIMIT = 50;
        MIN_VALIDATOR_SIZE = 2;
        NAME_712 = "Validator Maintainer";

        CHANGE_VALIDATORS_TYPEHASH = 0x1d67c1fa3f9d6b80f0599d303ffad35c634615c72d95e2a13600b856f2a409e7;

        // set DOMAIN_SEPARATOR
        // refer: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/24a0bc23cfe3fbc76f8f2510b78af1e948ae6651/contracts/utils/cryptography/draft-EIP712.sol
        bytes32 hashedName = keccak256(bytes(NAME_712));
        bytes32 hashedVersion = keccak256(bytes("1"));
        bytes32 typeHash = keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
        _HASHED_NAME = hashedName;
        _HASHED_VERSION = hashedVersion;
        _CACHED_CHAIN_ID = _getChainId();
        _CACHED_DOMAIN_SEPARATOR = _buildDomainSeparator(
            typeHash,
            hashedName,
            hashedVersion
        );
        _TYPE_HASH = typeHash;

        // set validators
        require(validators.length > 0, "validators are none");
        require(multisigThreshold > 0, "invalid multisigThreshold");
        require(
            validators.length <= VALIDATORS_SIZE_LIMIT,
            "number of validators exceeds the limit"
        );

        require(
            validators.length >= MIN_VALIDATOR_SIZE,
            "number of validators is not enough"
        );

        require(
            multisigThreshold > SafeMath.div(validators.length, 2),
            "multisigThreshold is less than 50%"
        );

        validators_ = validators;
        require(
            multisigThreshold <= validators.length,
            "invalid multisigThreshold"
        );
        multisigThreshold_ = multisigThreshold;

        emit validatorChanged(validators, multisigThreshold);

        __Ownable_init();
    }

    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparator();
    }

    /**
     * @dev Returns the domain separator for the current chain.
     */
    function _domainSeparator() internal view virtual returns (bytes32) {
        if (_getChainId() == _CACHED_CHAIN_ID) {
            return _CACHED_DOMAIN_SEPARATOR;
        } else {
            return
                _buildDomainSeparator(
                    _TYPE_HASH,
                    _HASHED_NAME,
                    _HASHED_VERSION
                );
        }
    }

    function _buildDomainSeparator(
        bytes32 typeHash,
        bytes32 name,
        bytes32 version
    ) private view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    typeHash,
                    name,
                    version,
                    _getChainId(),
                    address(this)
                )
            );
    }

    function _getChainId() private view returns (uint256 chainId) {
        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
        // solhint-disable-next-line no-inline-assembly
        assembly {
            chainId := chainid()
        }
    }

    function changeValidators(
        address[] memory validators,
        uint8 multisigThreshold,
        uint256 nonce,
        bytes memory signatures
    ) public onlyOwner {
        require(
            nonce == latestChangeValidatorsNonce_,
            "changeValidators nonce invalid"
        );
        latestChangeValidatorsNonce_ = SafeMath.add(nonce, 1);

        require(validators.length > 0, "validators are none");
        require(multisigThreshold > 0, "invalid multisigThreshold");
        require(
            validators.length <= VALIDATORS_SIZE_LIMIT,
            "number of validators exceeds the limit"
        );

        require(
            validators.length >= MIN_VALIDATOR_SIZE,
            "number of validators is not enough"
        );

        require(
            multisigThreshold <= validators.length,
            "invalid multisigThreshold"
        );

        require(
            multisigThreshold > SafeMath.div(validators.length, 2),
            "multisigThreshold is less than 50%"
        );

        for (uint256 i = 0; i < validators.length; i++) {
            for (uint256 j = i + 1; j < validators.length; j++) {
                require(validators[i] != validators[j], "repeated validators");
            }
        }

        validators_ = validators;
        multisigThreshold_ = multisigThreshold;

        emit validatorChanged(validators_, multisigThreshold_);
    }

    /**
     * @notice  if addr is not one of validators_, return validators_.length
     * @return  index of addr in validators_
     */
    function _getIndexOfValidators(address user)
        internal
        view
        returns (uint256)
    {
        for (uint256 i = 0; i < validators_.length; i++) {
            if (validators_[i] == user) {
                return i;
            }
        }
        return validators_.length;
    }

    /**
     * @notice             @dev signatures are a multiple of 65 bytes and are densely packed.
     * @param signatures   The signatures bytes array
     */
    function validatorsApprove(bytes32 msgHash, bytes memory signatures)
        public
        view
    {
        require(signatures.length % SIGNATURE_SIZE == 0, "invalid signatures");

        uint256 threshold = multisigThreshold_;

        // 1. check length of signature
        uint256 length = signatures.length / SIGNATURE_SIZE;
        require(
            length >= threshold,
            "length of signatures must greater than threshold"
        );

        // 3. check number of verified signatures >= threshold
        uint256 verifiedNum = 0;
        uint256 i = 0;

        uint8 v;
        bytes32 r;
        bytes32 s;
        address recoveredAddress;
        // set indexVisited[ index of recoveredAddress in validators_ ] = true
        bool[] memory validatorIndexVisited = new bool[](validators_.length);
        uint256 validatorIndex;
        while (i < length) {
            (v, r, s) = MultisigUtils.parseSignature(signatures, i);
            i++;

            recoveredAddress = ecrecover(msgHash, v, r, s);
            require(recoveredAddress != address(0), "invalid signature");

            // get index of recoveredAddress in validators_
            validatorIndex = _getIndexOfValidators(recoveredAddress);
            // recoveredAddress is not validator or has been visited
            if (
                validatorIndex >= validators_.length ||
                validatorIndexVisited[validatorIndex]
            ) {
                continue;
            }
            // recoveredAddress verified
            validatorIndexVisited[validatorIndex] = true;
            verifiedNum++;
            if (verifiedNum >= threshold) {
                return;
            }
        }
        require(verifiedNum >= threshold, "signatures not verified");
    }

    /**
     * @notice  
     * @return Array of validators
     */
    function listValidators()
        public
        view
        returns (address[] memory)
    {
        return validators_;
    }
}
