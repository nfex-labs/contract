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

import {IERC20} from "./interfaces/IERC20.sol";
import {SafeERC20} from "./libraries/SafeERC20.sol";
import {Address} from "./libraries/Address.sol";
import {SafeMath} from "./libraries/SafeMath.sol";
import {IMaintainer} from "./interfaces/IMaintainer.sol";
import {IERC20Permit} from "./interfaces/IERC20Permit.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

contract Lock is
Initializable,
ReentrancyGuardUpgradeable,
PausableUpgradeable,
OwnableUpgradeable
{
    using Address for address;
    using SafeERC20 for IERC20;
    IMaintainer public Maintainer;
    // UNLOCK_TYPEHASH = keccak256("Unlock(UnlockRecord calldata record)");
    bytes32 public UNLOCK_TYPEHASH;
    mapping(uint256 => bool) public unlockStatus;
    struct UnlockRecord {
        address token;
        address recipient;
        uint256 amount;
        uint256 expirationTime;
        uint256 id;
    }
    event Locked(address tokenAddress, address sender, uint256 amount);
    event Unlocked(
        address tokenAddress,
        address recipient,
        uint256 amount,
        uint256 id
    );
    function initialize(IMaintainer _IMaintainer) public initializer {
        Maintainer = _IMaintainer;
        UNLOCK_TYPEHASH = 0x4589254478acd0495cc1e069821fdd206d2b12b20007016dba97269eecfd8827;
        __ReentrancyGuard_init();
        __Pausable_init();
        __Ownable_init();
    }
    function lockETH() public payable nonReentrant whenNotPaused {
        require(msg.value > 0, "LOCK: Amount should be greater than 0");
        emit Locked(address(0), msg.sender, msg.value);
    }
    receive() external payable {
        lockETH();
    }
    // before lockToken, user should approve -> TokenLocker Contract with 0xffffff token
    function LockToken(address token, uint256 amount)
    public
    nonReentrant
    whenNotPaused
    {
        require(amount > 0, "LOCK: Amount should be greater than 0");
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        emit Locked(token, msg.sender, amount);
    }
    function LockTokenWithPermit(
        address token,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s,
        bool approveMax
    ) public nonReentrant whenNotPaused {
        require(amount > 0, "LOCK: Amount should be greater than 0");
        uint256 approveAmount = approveMax ? type(uint256).max : amount;
        IERC20Permit(token).permit(
            msg.sender,
            address(this),
            approveAmount,
            deadline,
            v,
            r,
            s
        );
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        emit Locked(token, msg.sender, amount);
    }
    function Unlock(UnlockRecord calldata record, bytes calldata signatures)
    external
    nonReentrant
    whenNotPaused
    {
        // 1. calc msgHash
        bytes32 msgHash = getUnlockMsgHash(record);
        Maintainer.validatorsApprove(msgHash, signatures);
        require(!unlockStatus[record.id], "LOCK: Unlock id has been used.");
        require(record.amount != 0, "LOCK: Unlock amount should't be 0.");
        require(
            record.recipient != address(this),
            "LOCK: Unlock recipient should't be this contract."
        );
        require(
            record.expirationTime >= block.timestamp,
            "LOCK: Record expired."
        );
        setUnlockStatus(record.id, true);
        if (record.token == address(0)) {
            payable(record.recipient).transfer(record.amount);
        } else {
            IERC20(record.token).safeTransfer(record.recipient, record.amount);
        }
        emit Unlocked(record.token, record.recipient, record.amount, record.id);
    }
    function setUnlockStatus(uint256 id, bool status) internal {
        unlockStatus[id] = status;
    }
    function pause() public onlyOwner {
        _pause();
    }
    function unpause() public onlyOwner {
        _unpause();
    }
    function getUnlockMsgHash(UnlockRecord calldata records)
    public
    view
    returns (bytes32 msgHash)
    {
        msgHash = keccak256(
            abi.encodePacked(
                "\x19\x01", // solium-disable-line
                Maintainer.DOMAIN_SEPARATOR(),
                keccak256(abi.encode(UNLOCK_TYPEHASH, records))
            )
        );
    }
}