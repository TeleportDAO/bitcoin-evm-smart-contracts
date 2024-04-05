// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.8.4;

interface ICcExchangeRouter {

    // Structures

    struct chainIdStruct {
        uint middleChain;
        uint destinationChain;
    }

    /// @notice Structure for recording cross-chain exchange requests
    /// @param appId that user wants to use (which DEX)
    /// @param inputAmount Amount of locked BTC on source chain
    /// @param outputAmount Amount of output token
    /// @param isFixedToken True if amount of input token is fixed
    /// @param recipientAddress Address of exchange recipient
    /// @param fee Amount of fee that is paid to Teleporter (for tx, relayer and teleporter fees)
    /// @param isUsed True if tx has been submitted before
    /// @param path Exchange path from input token to output token
    /// @param deadline for exchanging tokens (not used anymore)
    /// @param speed of the request (normal or instant)
    struct ccExchangeRequest {
        uint appId;
        uint inputAmount;
        uint outputAmount;
        bool isFixedToken;
        address recipientAddress;
        uint fee;
        bool isUsed;
        address[] path;
        uint deadline;
        uint speed;
    }

    /// @notice Structure for recording cross-chain exchange requests
    /// @param isTransferredToOtherChain True if BTC to ETH exchange is processed successfully
    /// @param remainedInputAmount Amount of obtained TELEBTC on target chain
    /// @param bridgeFee percentage of fee we have to give to across relayers to fill our request
    struct extendedCcExchangeRequest {
        uint chainId;
        bool isTransferredToOtherChain;
        uint remainedInputAmount;
        uint bridgeFee;
        uint thirdParty;
        uint protocolFee;
        uint thirdPartyFee;
        uint lockerFee;
    }
    
    /// @notice Structure for passing tx and its inclusion proof
    /// @param version of the transaction containing the user request
    /// @param vin Inputs of the transaction containing the user request
    /// @param vout Outputs of the transaction containing the user request
    /// @param locktime of the transaction containing the user request
    /// @param blockNumber Height of the block containing the user request
    /// @param intermediateNodes Merkle inclusion proof for transaction containing the user request
    /// @param index of transaction containing the user request in the block
    struct TxAndProof {
        bytes4 version;
        bytes vin;
        bytes vout;
        bytes4 locktime;
        uint256 blockNumber;
        bytes intermediateNodes;
        uint index;
    }

    /// @notice Structure for storing filling requests
    /// @param startingTime First attemp to fill the request
    /// @param reqToken Requested exchange token
    /// @param lastUsedIdx Last used filler index
    /// @param remainingAmountOfLastFill Amount of unused tokens of last filler
    /// @param isWithdrawnLastFill True if last used filler has withdrawn unused tokens
    struct FillData {
        uint startingTime;
        address reqToken;
        uint lastUsedIdx;
        uint remainingAmountOfLastFill;
        bool isWithdrawnLastFill;
    }

    /// @notice Structure for storing fillers of a request
    /// @param index of filler between fillers
    /// @param token that filler used to fill
    /// @param amount that filler sent to fill
    struct FillerData {
        uint index;
        address token;
        uint amount;
    }

    /// @notice Structure for storing fillings
    /// @param prefixSum Cumulative sum of fillings
    /// @param currentIndex Next filler index
    struct PrefixFillSum {
        uint[] prefixSum;
        uint currentIndex;
    }
    // Events

    event TokenAdded(
        uint chainId,
        address newToken
    );

    event TokenRemoved(
        uint chainId,
        address oldToken
    );

    event ChainAdded(
        uint newChain
    );

    event ChainRemoved(
        uint oldChain
    );

    event AcrossUpdated(
        address oldAcross,
        address newAcross
    );

    event BurnRouterUpdated(
        address oldBurnRouter,
        address newBurnRouter
    );

	event NewFillerWithdrawInterval(
        uint oldFillerWithdrawInterval, 
        uint newFillerWithdrawInterval
    );

    /// @notice Emits when a new filler fills a request
    /// @param filler Address of filler
    /// @param txId Bitcoin request id
    /// @param token that used for filling
    /// @param amount that sent for filling
    event NewFill(
        address filler,
        bytes32 txId, 
        address token,
        uint amount
    );

    /// @notice Emits when a request is filled for the first time
    /// @param txId Bitcoin request id
    /// @param time Filling starting time 
    event FillStarted(
        bytes32 txId,
        uint time
    );

    /// @notice Emits when unused tokens withdrawn
    /// @param amount of unused tokens
    /// @param token that filler sent
    /// @param filler Address of filler
    /// @param fillIdx Index of filling
    /// @param txId that filler filled
    event FillTokensReturned(
        uint amount,
        address token,
        address filler,
        uint fillIdx,
        bytes32 txId
    );

    /// @notice Emits when filler withdraws teleBTC
    /// @param amount Total sent tokens
    /// @param remainingAmount Amount of unused token
    /// @param token that filler sent
    /// @param filler Address of filler
    /// @param fillIdx Index of filling
    /// @param txId that filler filled
    /// @param reqMintedTeleBtc Total teleBTC minted by txId
    /// @param sentTeleBtc Share of this filler from total minted teleBTC
    event FillTeleBtcSent(
        uint amount,
        uint remainingAmount,
        address token,
        address filler,
        uint fillIdx,
        bytes32 txId,
        uint reqMintedTeleBtc,
        uint sentTeleBtc
    );

    /// @notice Emits when a cc exchange request gets done
    /// @param lockerTargetAddress Address of Locker
    /// @param user Exchange recipient address
    /// @param inputAndOutputToken [inputToken, outputToken]
    /// @param inputAndOutputAmount [inputAmount, outputAmount]
    /// @param speed Speed of the request (normal or instant)
    /// @param teleporter Address of teleporter who submitted the request
    /// @param bitcoinTxId The transaction ID of request on Bitcoin 
    /// @param appId Assigned application id to exchange
    /// @param thirdPartyId Id of third party
    /// @param fees [network fee, locker fee, protocol fee, third party fee, bridge fee]
    event NewWrapAndSwap(
        address lockerTargetAddress,
        address indexed user,
        address[2] inputAndOutputToken,
        uint[2] inputAndOutputAmount,
        uint indexed speed,
        address indexed teleporter,
        bytes32 bitcoinTxId,
        uint appId,
        uint thirdPartyId,
        uint[5] fees
    );

    /// @notice Emits when a cc exchange request fails
    /// @dev We mint teleBTC and send it to the user
    /// @param lockerTargetAddress Address of Locker
    /// @param recipientAddress Exchange recipient address
    /// @param inputAndOutputToken [inputToken, outputToken]
    /// @param inputAndOutputAmount [inputAmount, outputAmount]
    /// @param speed Speed of the request (normal or instant)
    /// @param teleporter Address of teleporter who submitted the request
    /// @param bitcoinTxId The transaction ID of request on Bitcoin 
    /// @param appId Assigned application id to exchange
    /// @param thirdPartyId Id of third party
    /// @param fees [network fee, locker fee, protocol fee, third party fee, bridge fee]    
    event FailedWrapAndSwap(
        address lockerTargetAddress,
        address indexed recipientAddress,
        address[2] inputAndOutputToken,
        uint[2] inputAndOutputAmount,
        uint indexed speed,
        address indexed teleporter,
        bytes32 bitcoinTxId,
        uint appId,
        uint thirdPartyId,
        uint[5] fees
    );

    /// @notice Emits when appId for an exchange connector is set
    /// @param appId Assigned application id to exchange
    /// @param exchangeConnector Address of exchange connector contract
    event SetExchangeConnector(
        uint appId,
        address exchangeConnector
    );

    /// @notice Emits when relay contract updated
    event NewRelay(
        address oldRelay, 
        address newRelay
    );

    /// @notice Emits when instant router contract updated
    event NewInstantRouter(
        address oldInstantRouter, 
        address newInstantRouter
    );

    /// @notice Emits when lockers contract updated
    event NewLockers(
        address oldLockers, 
        address newLockers
    );

    /// @notice Emits when telebtc contract updated
    event NewTeleBTC(
        address oldTeleBTC, 
        address newTeleBTC
    );

    /// @notice Emits when protocol fee updated
    event NewProtocolPercentageFee(
        uint oldProtocolPercentageFee, 
        uint newProtocolPercentageFee
    );

    /// @notice Emits when treasury address updated
    event NewTreasury(
        address oldTreasury, 
        address newTreasury
    );

    /// @notice                     Emits when changes made to third party address
	event NewThirdPartyAddress(
		uint thirdPartyId,
		address oldThirdPartyAddress, 
		address newThirdPartyAddress
	);

	/// @notice                     Emits when changes made to third party fee
	event NewThirdPartyFee(
		uint thirdPartyId,
		uint oldThirdPartyFee, 
		uint newThirdPartyFee
	);

    /// @notice                     Emits when changes made to chain id mapping
    event NewChainIdMapping(
        uint mappedId,
        uint middleChain,
        uint destinationChain
    );

    /// @notice                     Emits when changes made to wrapped native token
    event NewWrappedNativeToken(
        address oldWrappedNativeToken,
        address newWrappedNativeToken
    );

    // Read-only functions
    
    function isRequestUsed(bytes32 _txId) external view returns (bool);

    // Read-only functions
    
    function startingBlockNumber() external view returns (uint);

    function protocolPercentageFee() external view returns (uint);
    
    function chainId() external view returns (uint);

    function relay() external view returns (address);

    function instantRouter() external view returns (address);

    function lockers() external view returns (address);

    function teleBTC() external view returns (address);

    function exchangeConnector(uint _appId) external view returns (address);

    function treasury() external view returns (address);

    function isTokenSupported(uint chainId, address _exchangeToken) external view returns (bool);

    function isChainSupported(uint _chainId) external view returns (bool);

    function across() external view returns (address);

    function burnRouter() external view returns (address);

    // State-changing functions

    function setStartingBlockNumber(uint _startingBlockNumber) external;

    function setRelay(address _relay) external;

    function setInstantRouter(address _instantRouter) external;

    function setLockers(address _lockers) external;

    function setTeleBTC(address _teleBTC) external;

    function setExchangeConnector(uint _appId, address _exchangeConnector) external;

	function setTreasury(address _treasury) external;

	function setProtocolPercentageFee(uint _protocolPercentageFee) external;

    // function setFillerWithdrawInterval(uint _fillerWithdrawInterval) external;

    function setAcross(address _across) external;

    function setBurnRouter(address _burnRouter) external;

    function setThirdPartyAddress(uint _thirdPartyId, address _thirdPartyAddress) external;

	function setThirdPartyFee(uint _thirdPartyId, uint _thirdPartyFee) external;

    function setWrappedNativeToken(address _wrappedNativeToken) external;

    function setChainIdMapping(uint _mappedId, uint _middleChain, uint _destinationChain) external;
    
    function wrapAndSwap(
        TxAndProof memory _txAndProof,
        bytes calldata _lockerLockingScript,
        address[] memory _path
    ) external payable returns(bool);

    // function fillTx(
    //     bytes32 _txId,
    //     address _recipient,
    //     address _token,
    //     uint _amount,
    //     uint _requestAmount
    // ) external payable;

    // function getTeleBtcForFill(
    //    bytes32 _txId
    // ) external returns (bool);

    function supportToken(uint chainId, address _token) external;

    function removeToken(uint chainId, address _token) external;

    function supportChain(uint _chainId) external;

    function removeChain(uint _chainId) external;

    function withdrawFailedWrapAndSwap(
        bytes32 _txId,
        uint8 _scriptType,
        bytes memory _userScript,
        uint _acrossRelayerFee,
        bytes32 _r,
        bytes32 _s,
        uint8 _v,
        bytes calldata _lockerLockingScript
    ) external returns (bool);

    function retryFailedWrapAndSwap(
        bytes32 _txId,
        uint256 _outputAmount,
        uint _acrossRelayerFee,
        address[] memory path,
        bytes32 _r,
        bytes32 _s,
        uint8 _v
    ) external returns (bool);
}