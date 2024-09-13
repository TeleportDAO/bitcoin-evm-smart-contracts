// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <=0.8.4;

import "@teleportdao/btc-evm-bridge/contracts/types/ScriptTypesEnum.sol";

interface IRuneRouter {
    // Structures

    /// @notice Structure for recording wrap and wrap&swap requests
    struct runeWrapRequest {
        bool isUsed;
        uint chainId;
        uint appId;
        uint tokenId;
        uint inputAmount;
        address inputToken;
        address recipientAddress;
        uint thirdPartyId;
        uint fee;
        uint outputAmount;
        address outputToken;
    }

    /// @notice Structure for recording unwrap and swap&unwrap requests
    struct runeUnwrapRequest {
        bool isProcessed;
        uint amount;
        uint burntAmount;
        uint appId;
        address sender;
        bytes userScript;
        ScriptTypes scriptType;
    }

    struct thirdParty {
        address thirdPartyAddress;
        uint thirdPartyFee;
    }

    struct fees {
        uint protocolFee;
        uint lockerFee;
        uint thirdPartyFee;
    }

    // Events

    /// @notice Emits when appId for an exchange connector is set
    /// @param appId Assigned application id to exchange
    /// @param exchangeConnector Address of exchange connector contract
    event SetExchangeConnector(uint appId, address exchangeConnector);

    /// @notice Emit when relay address updated
    event NewRelay(address oldRelay, address newRelay);

    /// @notice Emit when locker address updated
    event NewLocker(address oldLocker, address newLocker);

    /// @notice Emit when teleporter address updated
    event NewTeleporter(address oldTeleporter, address newTeleporter);

    /// @notice Emit when protocol fee updated
    event NewProtocolPercentageFee(
        uint oldProtocolPercentageFee,
        uint newProtocolPercentageFee
    );

    /// @notice Emit when treasury address updated
    event NewTreasury(address oldTreasury, address newTreasury);

    /// @notice Emit when new Rune added
    event NewRune(
        string name,
        string symbol,
        string runeId,
        uint decimal,
        uint internalId,
        address wRuneProxy,
        address wRuneLogic
    );

    /// @notice Emit when Rune removed
    event RuneRemoved(uint tokenId, address wRuneProxy);

    /// @notice Emit when unwrap fee updated
    event UnwrapFeeUpdated(uint oldFee, uint newFee);

    /// @notice Emit when third party fee updated
    event ThirdPartyInfoUpdated(
        uint thirdPartyId,
        address oldAddress,
        uint oldFee,
        address newAddress,
        uint newFee
    );

    /// @notice Emit when a rune wrap request is processed
    event NewRuneWrap(
        address user,
        uint remainingAmount,
        address inputToken,
        fees fee,
        address thirdPartyAddress,
        bytes32 txId
    );

    /// @notice Emit when a wrap&swap request is processed
    event NewRuneWrapAndSwap(
        address user,
        uint remainingAmount,
        address inputToken,
        uint outputAmount,
        address outputToken,
        fees fee,
        address thirdPartyAddress,
        bytes32 txId
    );

    /// @notice Emit when a wrap&swap request is processed but swap failed
    event FailedRuneWrapAndSwap(
        address user,
        uint remainingAmount,
        address inputToken,
        uint outputAmount,
        address outputToken,
        fees fee,
        address thirdPartyAddress,
        bytes32 txId
    );

    /// @notice Emit when a unwrap request is processed
    event UnwrapRuneProcessed(
        address user,
        uint remainingAmount,
        bytes userScript,
        ScriptTypes scriptType,
        uint reqIdx
    );

    /// @notice Emit when a new rune unwrap request is created
    event NewRuneUnwrap(
        address user,
        bytes userScript,
        ScriptTypes scriptType,
        address inputToken,
        uint inputAmount,
        uint remainingAmount,
        fees fee,
        uint unwrapFee,
        address thirdPartyAddress,
        uint reqIdx
    );

    /// @notice Emit when a new rune swap&unwrap request is created
    event NewRuneSwapAndUnwrap(
        address user,
        bytes userScript,
        ScriptTypes scriptType,
        uint inputAmount,
        address inputToken,
        uint outputAmount,
        uint remainingAmount,
        address outputToken,
        fees fee,
        uint unwrapFee,
        address thirdPartyAddress,
        uint reqIdx
    );

    // Read-only functions

    function isWrapRequestProcessed(bytes32 _txId) external view returns (bool);

    function isUnwrapRequestProcessed(
        uint _reqIdx
    ) external view returns (bool);

    function startingBlockNumber() external view returns (uint);

    function protocolPercentageFee() external view returns (uint);

    function chainId() external view returns (uint);

    function relay() external view returns (address);

    function locker() external view returns (address);

    function teleporter() external view returns (address);

    function exchangeConnector(uint appId) external view returns (address);

    function treasury() external view returns (address);

    function lockerLockingScript() external view returns (bytes memory);

    function lockerScriptType() external view returns (ScriptTypes);

    function unwrapFee() external view returns (uint);

    function totalRuneUnwrapRequests() external view returns (uint);

    // State-changing functions

    function setStartingBlockNumber(uint _startingBlockNumber) external;

    function setRelay(address _relay) external;

    function setLocker(address _locker) external;

    function setTeleporter(address _teleporter) external;

    function setExchangeConnector(
        uint _appId,
        address _exchangeConnector
    ) external;

    function setTreasury(address _treasury) external;

    function setWrappedNativeToken(address _wrappedNativeToken) external;

    function setProtocolPercentageFee(uint _protocolPercentageFee) external;

    function setChainId(uint _chainId) external;

    function setLockerLockingScript(
        bytes memory _lockerLockingScript,
        ScriptTypes _lockerScriptType
    ) external;

    function setUnwrapFee(uint _newFee) external;

    function setThirdParty(
        uint _thirdPartyId,
        address _thirdPartyAddress,
        uint _thirdPartyFee
    ) external;

    function addRune(
        string memory _name,
        string memory _symbol,
        string memory _runeId,
        uint8 _decimal,
        uint _tokenId
    ) external;

    function removeRune(uint _tokenId) external;

    function wrapRune(
        bytes4 _version,
        bytes memory _vin,
        bytes calldata _vout,
        bytes4 _locktime,
        uint256 _blockNumber,
        bytes calldata _intermediateNodes,
        uint _index,
        address[] memory _path
    ) external payable;

    function unwrapProofRune(
        bytes4 _version,
        bytes memory _vin,
        bytes memory _vout,
        bytes4 _locktime,
        uint256 _blockNumber,
        bytes memory _intermediateNodes,
        uint _index,
        uint[] memory _reqIndexes
    ) external payable;

    function unwrapRune(
        uint _thirdPartyId,
        uint _tokenId,
        uint _amount,
        bytes memory _userScript,
        ScriptTypes _scriptType,
        uint _appId,
        uint _inputAmount,
        address[] memory _path
    ) external payable;
}
