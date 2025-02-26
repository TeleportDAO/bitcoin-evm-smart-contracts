// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <=0.8.4;

import "./CcExchangeRouterStorage.sol";
import "./CcExchangeRouterStorageV2.sol";
import "./interfaces/IBurnRouter.sol";
import "../dex_connectors/interfaces/IDexConnector.sol";
import "../erc20/interfaces/ITeleBTC.sol";
import "../erc20/WETH.sol";
import "../lockersManager/interfaces/ILockersManager.sol";
import "./CcExchangeRouterLib.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "solidity-bytes-utils/contracts/BytesLib.sol";
import "@across-protocol/contracts-v2/contracts/interfaces/SpokePoolInterface.sol";

contract CcExchangeRouterLogic is
    CcExchangeRouterStorage,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable,
    CcExchangeRouterStorageV2
{
    using BytesLib for bytes;

    error ZeroAddress();

    modifier nonZeroAddress(address _address) {
        if (_address == address(0)) revert ZeroAddress();
        _;
    }

    // Contract is payable
    receive() external payable {}

    /// @notice Initialize CcExchangeRouter
    /// @param _startingBlockNumber Transactions that are included in blocks older
    ///                             than _startingBlockNumber cannot be processed
    /// @param _protocolPercentageFee Protocol percentage fee (min: %0.01).
    ///                               This fee goes to treasury from each wrapAndSwap request
    /// @param _chainId Chain Id of the current chain
    /// @param _relay Address of BitcoinRelay which checks Bitcoin transactions inclusion
    /// @param _lockers LockersManager contract address
    /// @param _teleBTC TeleBTC token
    /// @param _treasury Treasury collects protocol fees
    function initialize(
        uint256 _startingBlockNumber,
        uint256 _protocolPercentageFee,
        uint256 _chainId,
        address _lockers,
        address _relay,
        address _teleBTC,
        address _treasury,
        address _across,
        address _burnRouter
    ) public initializer {
        OwnableUpgradeable.__Ownable_init();
        ReentrancyGuardUpgradeable.__ReentrancyGuard_init();

        chainId = _chainId;
        _setStartingBlockNumber(_startingBlockNumber);
        _setProtocolPercentageFee(_protocolPercentageFee);
        _setRelay(_relay);
        _setLockers(_lockers);
        _setTeleBTC(_teleBTC);
        _setTreasury(_treasury);
        _setAcross(_across);
        _setBurnRouter(_burnRouter);
    }

    function renounceOwnership() public virtual override onlyOwner {}

    /// @notice Setter for starting block number
    function setStartingBlockNumber(
        uint256 _startingBlockNumber
    ) external override onlyOwner {
        _setStartingBlockNumber(_startingBlockNumber);
    }

    /// @notice Update Relay address
    function setRelay(address _relay) external override onlyOwner {
        _setRelay(_relay);
    }

    /// @notice Address of special Teleporter that can submit requests
    function setSpecialTeleporter(
        address _specialTeleporter
    ) external override onlyOwner {
        _setSpecialTeleporter(_specialTeleporter);
    }

    /// @notice Update LockersManager address
    function setLockers(address _lockers) external override onlyOwner {
        _setLockers(_lockers);
    }

    /// @notice Assign an exchange connector to an app id
    /// @dev Users determine which DEX to use by determining the app id.
    function setExchangeConnector(
        uint256 _appId,
        address _exchangeConnector
    ) external override onlyOwner {
        exchangeConnector[_appId] = _exchangeConnector;
        emit SetExchangeConnector(_appId, _exchangeConnector);
    }

    /// @notice Update TeleBTC address
    function setTeleBTC(address _teleBTC) external override onlyOwner {
        _setTeleBTC(_teleBTC);
    }

    /// @notice Setter for protocol percentage fee
    function setProtocolPercentageFee(
        uint256 _protocolPercentageFee
    ) external override onlyOwner {
        _setProtocolPercentageFee(_protocolPercentageFee);
    }

    /// @notice Setter for treasury
    function setTreasury(address _treasury) external override onlyOwner {
        _setTreasury(_treasury);
    }

    /// @notice Setter for across
    /// @dev Across is used to send exchanged tokens to other chains
    function setAcross(address _across) external override onlyOwner {
        _setAcross(_across);
    }

    /// @notice Setter for BurnRouter
    function setBurnRouter(address _burnRouter) external override onlyOwner {
        _setBurnRouter(_burnRouter);
    }

    /// @notice Setter for third party
    /// @dev Each third party has an id and an address.
    ///      Users determine the third party by determining the id in the request.
    ///      Third party fee is sent to the third party address.
    function setThirdPartyAddress(
        uint256 _thirdPartyId,
        address _thirdPartyAddress
    ) external override onlyOwner {
        _setThirdPartyAddress(_thirdPartyId, _thirdPartyAddress);
    }

    /// @notice Setter for third party fee
    /// @dev Third party fee is a percentage of the input amount.
    ///      Third parties can set their own fees.
    function setThirdPartyFee(
        uint256 _thirdPartyId,
        uint256 _thirdPartyFee
    ) external override onlyOwner {
        _setThirdPartyFee(_thirdPartyId, _thirdPartyFee);
    }

    /// @notice Setter for wrapped native token
    function setWrappedNativeToken(
        address _wrappedNativeToken
    ) external override onlyOwner {
        _setWrappedNativeToken(_wrappedNativeToken);
    }

    /// @notice Setter for chain id mapping
    /// @dev After processing a request, the exchanged token is sent to the destination chain.
    function setChainIdMapping(
        uint256 _destinationChain,
        uint256 _mappedId
    ) external override onlyOwner {
        _setChainIdMapping(_destinationChain, _mappedId);
    }

    /// @notice Support a new chain
    /// @dev Users can only submit exchange requests for supported chains.
    function supportChain(uint256 _chainId) external override onlyOwner {
        emit ChainAdded(_chainId);
        isChainSupported[_chainId] = true;
    }

    /// @notice Remove a chain from supported chains
    function removeChain(uint256 _chainId) external override onlyOwner {
        emit ChainRemoved(_chainId);
        isChainSupported[_chainId] = false;
    }

    /// @notice Setter for Retyer Admin
    function setRetyerAdmin(
        address _retryerAdmin
    ) external onlyOwner {
        retryerAdmin = _retryerAdmin;
    }

    /// @notice Check if a request has been processed
    /// @dev It prevents re-submitting a processed request
    /// @param _txId The transaction ID of request on Bitcoin
    /// @return True if the cc exchange request has been already executed
    function isRequestUsed(
        bytes32 _txId
    ) external view override returns (bool) {
        return ccExchangeRequests[_txId].isUsed ? true : false;
    }

    /// @notice Return the destination chain
    function getDestChainId(uint256 chainId) public view returns (uint256) {
        return chainIdMapping[chainId].destinationChain;
    }

    /// @notice Process a wrapAndSwap request after checking its inclusion on Bitcoin
    /// @dev Steps to process a request:
    ///      1. Check transaction inclusion on Bitcoin
    ///      2. Extract the request info
    ///      3. Mint TeleBTC and send fees to protocol, Locker, and third party
    ///      4. Exchange TeleBTC for the output token
    ///      5.1 Send the output token to the user
    ///      5.2 Send TeleBTC to user if exchange fails and the request belongs to the current chain
    ///      5.3 Keep TeleBTC if exchange fails and the request doesn't blong to the current chain
    /// @param _txAndProof Transaction and inclusion proof data
    /// @param _lockerLockingScript Script hash of Locker that user has sent BTC to it
    /// @param _path (Optional) Exchange path from teleBTC to the output token.
    function wrapAndSwap(
        TxAndProof memory _txAndProof,
        bytes calldata _lockerLockingScript,
        address[] memory _path
    ) external payable virtual override nonReentrant returns (bool) {
        // Basic checks
        require(
            _msgSender() == specialTeleporter,
            "ExchangeRouter: invalid sender"
        ); // Only Teleporter can submit requests
        require(
            _txAndProof.blockNumber >= startingBlockNumber,
            "ExchangeRouter: old request"
        );
        require(
            _txAndProof.locktime == bytes4(0),
            "ExchangeRouter: non-zero locktime"
        );

        // Check that the given script hash is Locker
        require(
            ILockersManager(lockers).isLocker(_lockerLockingScript),
            "ExchangeRouter: not locker"
        );

        // Extract request info and check if tx has been finalized on Bitcoin
        bytes32 txId = CcExchangeRouterLib.ccExchangeHelper(
            _txAndProof,
            ccExchangeRequests,
            extendedCcExchangeRequests,
            teleBTC,
            _lockerLockingScript,
            relay
        );

        // Find destination chain Id (the final chain that user gets its token on it)
        uint256 destinationChainId = getDestChainId(
            extendedCcExchangeRequests[txId].chainId
        );

        ccExchangeRequest memory request = ccExchangeRequests[txId];

        address _exchangeConnector = exchangeConnector[request.appId];
        require(
            _exchangeConnector != address(0),
            "ExchangeRouter: invalid appId"
        );

        // Find remained amount after reducing fees
        _mintAndReduceFees(_lockerLockingScript, txId);

        // Handle fast request
        if (request.speed == 1) {
            address filler = fillerAddress[txId][request.recipientAddress][
                request.path[request.path.length - 1]
            ][request.outputAmount][destinationChainId];

            if (filler != address(0)) {
                // If the request has been filled
                // Send TeleBTC to filler who filled the request
                _sendTeleBtcToFiller(
                    filler,
                    txId,
                    _lockerLockingScript,
                    destinationChainId
                );
                // TODO: emit event
                return true;
            } else {
                // If the request has not been filled
                // Set the request as a normal request
                ccExchangeRequests[txId].speed = 0;

                // Find new output amount
                ccExchangeRequests[txId].outputAmount =
                    (ccExchangeRequests[txId].outputAmount *
                        (MAX_PROTOCOL_FEE - REGULAR_SLIPPAGE)) /
                    MAX_PROTOCOL_FEE;
                // Then treat it as a normal request (speed = 0)
            }
        }

        if (destinationChainId == chainId) {
            // Requests that belongs to the current chain
            require(
                extendedCcExchangeRequests[txId].bridgeFee == 0,
                "ExchangeRouter: invalid bridge fee"
            );

            // Swap and send to the user
            _wrapAndSwap(_exchangeConnector, _lockerLockingScript, txId, _path);
        } else {
            // Requests that belongs to the other chain
            require(
                isChainSupported[destinationChainId],
                "ExchangeRouter: invalid chain id"
            );

            // Swap and then send to the destination chain
            _wrapAndSwapToOtherChain(
                _exchangeConnector,
                _lockerLockingScript,
                txId,
                _path,
                extendedCcExchangeRequests[txId].bridgeFee,
                destinationChainId
            );
        }

        return true;
    }

    /// @notice Filler fills an upcoming exchange request
    /// @param _txId Bitcoin request that filler wants to fill
    /// @param _token Address of exchange token in the request
    /// @param _amount Requested exchanging amount
    function fillTx(
        bytes32 _txId,
        address _recipient,
        address _token,
        uint _amount,
        uint _destinationChainId,
        uint _acrossRelayerFee
    ) external payable nonReentrant {
        require(
            fillerAddress[_txId][_recipient][_token][_amount][
                _destinationChainId
            ] == address(0),
            "ExchangeRouter: already filled"
        );

        if (_destinationChainId == chainId) {
            // Requests that belongs to the current chain
            if (_token == NATIVE_TOKEN) {
                require(msg.value == _amount, "ExchangeRouter: wrong amount");
                (bool sentToRecipient, ) = _recipient.call{value: _amount}("");
                require(sentToRecipient, "ExchangeRouter: transfer failed");
            } else {
                require(
                    IERC20(_token).transferFrom(
                        _msgSender(),
                        _recipient,
                        _amount
                    ),
                    "ExchangeRouter: no allowance"
                );
            }
        } else {
            // Requests that belongs to the other chain
            _sendTokenToOtherChain(
                _destinationChainId,
                _token,
                _amount,
                _recipient,
                _acrossRelayerFee
            );
        }

        emit RequestFilled(
            _msgSender(),
            _txId,
            _recipient,
            _token,
            _amount,
            _destinationChainId,
            _acrossRelayerFee
        );
    }

    function refundByOwnerOrAdmin(
        bytes32 _txId,
        uint8 _scriptType,
        bytes memory _userScript,
        bytes calldata _lockerLockingScript
    ) external override nonReentrant {
        require(
            msg.sender == retryerAdmin || msg.sender == owner(),
            "ExchangeRouter: not authorized"
        );

        // Check that the request has not been completed
        require(
            extendedCcExchangeRequests[_txId].isRequestCompleted == false,
            "ExchangeRouter: already processed"
        );
        extendedCcExchangeRequests[_txId].isRequestCompleted = true;

        uint256 refundAmount = extendedCcExchangeRequests[_txId].remainedInputAmount;

        // Burns teleBTC for user
        ITeleBTC(teleBTC).approve(
            burnRouter,
            refundAmount
        );

        IBurnRouter(burnRouter).unwrap(
            refundAmount,
            _userScript,
            ScriptTypes(_scriptType),
            _lockerLockingScript,
            0
        );

        emit RefundProcessed(
            _txId,
            msg.sender,
            refundAmount,
            _userScript,
            _scriptType
        );
    }

    /// @notice Emergency withdraw tokens from contract
    function emergencyWithdraw(
        address _token,
        uint256 _amount
    ) external onlyOwner nonReentrant {
        if (_token == NATIVE_TOKEN) {
            Address.sendValue(payable(owner()), _amount);
        } else {
            IERC20(_token).transfer(owner(), _amount);
        }
    }

    function _sendTeleBtcToFiller(
        address _filler,
        bytes32 _txId,
        bytes memory _lockerLockingScript,
        uint256 _destinationChainId
    ) private {
        ccExchangeRequest memory request = ccExchangeRequests[_txId];
        extendedCcExchangeRequest
            memory extendedRequest = extendedCcExchangeRequests[_txId];

        // Send TeleBTC to filler
        ITeleBTC(teleBTC).transfer(
            _filler,
            extendedRequest.remainedInputAmount
        );

        uint256[5] memory fees = [
            request.fee,
            extendedRequest.lockerFee,
            extendedRequest.protocolFee,
            extendedRequest.thirdPartyFee,
            extendedRequest.bridgeFee
        ];

        emit NewWrapAndSwap(
            ILockersManager(lockers).getLockerTargetAddress(
                _lockerLockingScript
            ),
            request.recipientAddress,
            [teleBTC, request.path[request.path.length - 1]],
            [extendedRequest.remainedInputAmount, request.outputAmount],
            1,
            _msgSender(),
            _txId,
            request.appId,
            extendedRequest.thirdParty,
            fees,
            _destinationChainId
        );

        emit FillerRefunded(
            _filler,
            _txId,
            extendedRequest.remainedInputAmount
        );
    }

    /// @notice Send tokens to the destination using Across
    function _sendTokenToOtherChain(
        uint256 _chainId,
        address _token,
        uint256 _amount,
        address _user,
        uint256 _acrossRelayerFee
    ) private {
        IERC20(_token).approve(across, _amount);
        SpokePoolInterface(across).deposit(
            _user,
            _token,
            _amount,
            getDestChainId(_chainId),
            int64(uint64(_acrossRelayerFee)),
            uint32(block.timestamp),
            "0x", // Null data
            115792089237316195423570985008687907853269984665640564039457584007913129639935
        );
    }

    /// @notice Internal function for request belonging to the current chain
    function _wrapAndSwap(
        address _exchangeConnector,
        bytes memory _lockerLockingScript,
        bytes32 _txId,
        address[] memory _path
    ) internal {
        // try swapping with path provided by teleporter
        (bool result, ) = _swap(
            ICcExchangeRouter.swapArguments(
                chainId,
                _lockerLockingScript,
                ccExchangeRequests[_txId],
                extendedCcExchangeRequests[_txId],
                _txId,
                _path,
                _exchangeConnector
            )
        );

        if (result) {
            extendedCcExchangeRequests[_txId].isRequestCompleted = true;
        }
        // If swap failed, keep TeleBTC in the contract for retry
    }

    /// @notice Internal function for request belonging chains other than the current chain
    function _wrapAndSwapToOtherChain(
        address _exchangeConnector,
        bytes memory _lockerLockingScript,
        bytes32 _txId,
        address[] memory _path,
        uint256 _acrossRelayerFee, // TODO: get the bridge fee from teleporter (use this as maximum amount of it)
        uint256 _chainId
    ) private {
        (bool result, uint256[] memory amounts) = _swap(
            ICcExchangeRouter.swapArguments(
                _chainId,
                _lockerLockingScript,
                ccExchangeRequests[_txId],
                extendedCcExchangeRequests[_txId],
                _txId,
                _path,
                _exchangeConnector
            )
        );

        if (result) {
            // If swap was successfull, user will get tokens on destination chain
            extendedCcExchangeRequests[_txId].isRequestCompleted = true;

            _sendTokenToOtherChain(
                extendedCcExchangeRequests[_txId].chainId,
                _path[_path.length - 1],
                amounts[amounts.length - 1],
                ccExchangeRequests[_txId].recipientAddress,
                _acrossRelayerFee
            );
        }
        // If swap failed, keep TeleBTC in the contract for retry
    }

    /// @notice Swap TeleBTC for the output token
    function _swap(
        ICcExchangeRouter.swapArguments memory swapArguments
    ) private returns (bool result, uint256[] memory amounts) {
        // Give allowance to exchange connector for swapping
        ITeleBTC(teleBTC).approve(
            swapArguments._exchangeConnector,
            swapArguments._extendedCcExchangeRequest.remainedInputAmount
        );

        // Check if the provided path is valid
        require(
            swapArguments._path[0] == teleBTC &&
                swapArguments._path[swapArguments._path.length - 1] ==
                swapArguments._ccExchangeRequest.path[
                    swapArguments._ccExchangeRequest.path.length - 1
                ],
            "CcExchangeRouter: invalid path"
        );

        // Swap teleBTC for the output token
        // Swapped token is sent to the contract
        (result, amounts) = IDexConnector(swapArguments._exchangeConnector)
            .swap(
                swapArguments._extendedCcExchangeRequest.remainedInputAmount,
                swapArguments._ccExchangeRequest.outputAmount,
                swapArguments._path,
                address(this),
                block.timestamp,
                true
            );

        if (result) { // Successfull swap
            if (swapArguments.destinationChainId == chainId) { // Send swapped token to the user for current chain requests
                address _outputToken = swapArguments._path[
                    swapArguments._path.length - 1
                ];
                uint256 _outputAmount = amounts[amounts.length - 1];
                if (_outputToken != wrappedNativeToken) {
                    // Send swapped token to the user
                    ITeleBTC(_outputToken).transfer(
                        swapArguments._ccExchangeRequest.recipientAddress,
                        _outputAmount
                    );
                } else { 
                    // Unwrap the wrapped native token
                    WETH(wrappedNativeToken).withdraw(_outputAmount);
                    // Send native token to the user
                    Address.sendValue(
                        payable(swapArguments._ccExchangeRequest.recipientAddress),
                        _outputAmount
                    );
                }
            }
            
            uint256 bridgeFee = (amounts[amounts.length - 1] *
                swapArguments._extendedCcExchangeRequest.bridgeFee) /
                MAX_BRIDGE_FEE;

            uint256[5] memory fees = [
                swapArguments._ccExchangeRequest.fee,
                swapArguments._extendedCcExchangeRequest.lockerFee,
                swapArguments._extendedCcExchangeRequest.protocolFee,
                swapArguments._extendedCcExchangeRequest.thirdPartyFee,
                bridgeFee
            ];

            emit NewWrapAndSwap(
                ILockersManager(lockers).getLockerTargetAddress(
                    swapArguments._lockerLockingScript
                ),
                swapArguments._ccExchangeRequest.recipientAddress,
                [teleBTC, swapArguments._path[swapArguments._path.length - 1]], // [input token, output token]
                [amounts[0], amounts[amounts.length - 1] - bridgeFee], // [input amount, output amount]
                swapArguments._ccExchangeRequest.speed,
                _msgSender(), // Teleporter address
                swapArguments._txId,
                swapArguments._ccExchangeRequest.appId,
                swapArguments._extendedCcExchangeRequest.thirdParty,
                fees,
                swapArguments.destinationChainId
            );
        } else { // Failed swap
            uint256[5] memory fees = [
                swapArguments._ccExchangeRequest.fee,
                swapArguments._extendedCcExchangeRequest.lockerFee,
                swapArguments._extendedCcExchangeRequest.protocolFee,
                swapArguments._extendedCcExchangeRequest.thirdPartyFee,
                0
            ];
            emit FailedWrapAndSwap(
                ILockersManager(lockers).getLockerTargetAddress(
                    swapArguments._lockerLockingScript
                ),
                swapArguments._ccExchangeRequest.recipientAddress,
                [teleBTC, swapArguments._path[swapArguments._path.length - 1]], // [input token, output token]
                [
                    swapArguments
                        ._extendedCcExchangeRequest
                        .remainedInputAmount,
                    0
                ], // [input amount, output amount]
                swapArguments._ccExchangeRequest.speed,
                _msgSender(), // Teleporter address
                swapArguments._txId,
                swapArguments._ccExchangeRequest.appId,
                swapArguments._extendedCcExchangeRequest.thirdParty,
                fees,
                swapArguments.destinationChainId
            );
        }
    }

    /// @notice Mints teleBTC by calling lockers contract
    /// @param _lockerLockingScript Locker's locking script
    /// @param _txId The transaction ID of the request
    function _mintAndReduceFees(
        bytes memory _lockerLockingScript,
        bytes32 _txId
    ) private {
        // Mints teleBTC for cc exchange router
        uint256 mintedAmount = ILockersManager(lockers).mint(
            _lockerLockingScript,
            address(this),
            ccExchangeRequests[_txId].inputAmount
        );

        // Calculates fees
        extendedCcExchangeRequests[_txId].protocolFee =
            (ccExchangeRequests[_txId].inputAmount * protocolPercentageFee) /
            MAX_PROTOCOL_FEE;
        uint256 networkFee = ccExchangeRequests[_txId].fee;
        extendedCcExchangeRequests[_txId].thirdPartyFee =
            (ccExchangeRequests[_txId].inputAmount *
                thirdPartyFee[extendedCcExchangeRequests[_txId].thirdParty]) /
            MAX_PROTOCOL_FEE;
        extendedCcExchangeRequests[_txId].lockerFee =
            ccExchangeRequests[_txId].inputAmount -
            mintedAmount;

        // Pays Teleporter fee
        if (networkFee > 0) {
            ITeleBTC(teleBTC).transfer(_msgSender(), networkFee);
        }

        // Pays protocol fee
        if (extendedCcExchangeRequests[_txId].protocolFee > 0) {
            ITeleBTC(teleBTC).transfer(
                treasury,
                extendedCcExchangeRequests[_txId].protocolFee
            );
        }

        // Pays third party fee
        if (extendedCcExchangeRequests[_txId].thirdPartyFee > 0) {
            ITeleBTC(teleBTC).transfer(
                thirdPartyAddress[extendedCcExchangeRequests[_txId].thirdParty],
                extendedCcExchangeRequests[_txId].thirdPartyFee
            );
        }

        extendedCcExchangeRequests[_txId].remainedInputAmount =
            mintedAmount -
            extendedCcExchangeRequests[_txId].protocolFee -
            networkFee -
            extendedCcExchangeRequests[_txId].thirdPartyFee;
    }

    /// @notice Internal setter for relay contract address
    function _setRelay(address _relay) private nonZeroAddress(_relay) {
        emit NewRelay(relay, _relay);
        relay = _relay;
    }

    /// @notice Internal setter for specialTeleporter address
    function _setSpecialTeleporter(
        address _specialTeleporter
    ) private nonZeroAddress(_specialTeleporter) {
        emit NewSpecialTeleporter(specialTeleporter, _specialTeleporter);
        specialTeleporter = _specialTeleporter;
    }

    /// @notice Internal setter for lockers contract address
    function _setLockers(address _lockers) private nonZeroAddress(_lockers) {
        emit NewLockers(lockers, _lockers);
        lockers = _lockers;
    }

    /// @notice Internal setter for teleBTC contract address
    function _setTeleBTC(address _teleBTC) private nonZeroAddress(_teleBTC) {
        emit NewTeleBTC(teleBTC, _teleBTC);
        teleBTC = _teleBTC;
    }

    /// @notice Internal setter for protocol percentage fee
    function _setProtocolPercentageFee(uint256 _protocolPercentageFee) private {
        require(
            MAX_PROTOCOL_FEE >= _protocolPercentageFee,
            "CCExchangeRouter: fee is out of range"
        );
        emit NewProtocolPercentageFee(
            protocolPercentageFee,
            _protocolPercentageFee
        );
        protocolPercentageFee = _protocolPercentageFee;
    }

    /// @notice Internal setter for starting block number
    function _setStartingBlockNumber(uint256 _startingBlockNumber) private {
        require(
            _startingBlockNumber > startingBlockNumber,
            "CCExchangeRouter: low startingBlockNumber"
        );
        startingBlockNumber = _startingBlockNumber;
    }

    /// @notice Internal setter for treasury
    function _setTreasury(address _treasury) private nonZeroAddress(_treasury) {
        emit NewTreasury(treasury, _treasury);
        treasury = _treasury;
    }

    /// @notice Internal setter for across
    function _setAcross(address _across) private {
        emit AcrossUpdated(across, _across);
        across = _across;
    }

    /// @notice Internal setter for burnRouter
    function _setBurnRouter(
        address _burnRouter
    ) private nonZeroAddress(_burnRouter) {
        emit BurnRouterUpdated(burnRouter, _burnRouter);
        burnRouter = _burnRouter;
    }

    /// @notice Internal setter for third party address
    function _setThirdPartyAddress(
        uint256 _thirdPartyId,
        address _thirdPartyAddress
    ) private {
        emit NewThirdPartyAddress(
            _thirdPartyId,
            thirdPartyAddress[_thirdPartyId],
            _thirdPartyAddress
        );
        thirdPartyAddress[_thirdPartyId] = _thirdPartyAddress;
    }

    /// @notice Internal setter for third party fee
    function _setThirdPartyFee(
        uint256 _thirdPartyId,
        uint256 _thirdPartyFee
    ) private {
        emit NewThirdPartyFee(
            _thirdPartyId,
            thirdPartyFee[_thirdPartyId],
            _thirdPartyFee
        );
        thirdPartyFee[_thirdPartyId] = _thirdPartyFee;
    }

    /// @notice Internal setter for wrappedNativeToken
    function _setWrappedNativeToken(address _wrappedNativeToken) private {
        emit NewWrappedNativeToken(wrappedNativeToken, _wrappedNativeToken);
        wrappedNativeToken = _wrappedNativeToken;
    }

    /// @notice Internal setter for chain id mapping
    function _setChainIdMapping(
        uint256 _destinationChain,
        uint256 _mappedId
    ) private {
        emit NewChainIdMapping(_destinationChain, _mappedId);
        chainIdMapping[_mappedId] = chainIdStruct(chainId, _destinationChain);
    }
}
