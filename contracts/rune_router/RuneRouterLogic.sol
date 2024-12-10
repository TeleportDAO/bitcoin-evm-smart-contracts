// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <=0.8.4;

import "./RuneRouterStorage.sol";
import "./RuneRouterLib.sol";
import "../erc20/interfaces/IRune.sol";
import "../erc20/interfaces/IWETH.sol";
import "../dex_connectors/interfaces/IDexConnector.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@across-protocol/contracts-v2/contracts/interfaces/SpokePoolInterface.sol";

contract RuneRouterLogic is
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable,
    RuneRouterStorage
{
    /// @notice Initialize the contract
    /// @param _startingBlockNumber Requests included in a block older than _startingBlockNumber cannot be processed
    /// @param _protocolPercentageFee Percentage amount of protocol fee (min: %0.01)
    /// @param _chainId Id of the underlying chain
    /// @param _relay Bitcoin bridge address which validates Bitcoin tx
    /// @param _treasury Address of treasury that collects protocol fees
    function initialize(
        uint _startingBlockNumber,
        uint _protocolPercentageFee,
        uint _lockerPercentageFee,
        uint _chainId,
        address _relay,
        address _locker,
        bytes memory _lockerLockingScript,
        ScriptTypes _lockerScriptType,
        address _teleporter,
        address _treasury,
        address _wrappedNativeToken
    ) public initializer {
        OwnableUpgradeable.__Ownable_init();
        ReentrancyGuardUpgradeable.__ReentrancyGuard_init();

        chainId = _chainId;
        setStartingBlockNumber(_startingBlockNumber);
        setProtocolPercentageFee(_protocolPercentageFee);
        setLockerPercentageFee(_lockerPercentageFee);
        setRelay(_relay);
        setLocker(_locker);
        setLockerLockingScript(_lockerLockingScript, _lockerScriptType);
        setTeleporter(_teleporter);
        setTreasury(_treasury);
        setWrappedNativeToken(_wrappedNativeToken);
    }

    receive() external payable {}

    function renounceOwnership() public virtual override onlyOwner {}

    /// @notice Check if the wrap request has been processed before
    /// @param _txId of the request on Bitcoin
    function isWrapRequestProcessed(
        bytes32 _txId
    ) external view override returns (bool) {
        return runeWrapRequests[_txId].isUsed ? true : false;
    }

    /// @notice Check if the unwrap request has been processed before
    function isUnwrapRequestProcessed(
        uint _reqIdx
    ) external view override returns (bool) {
        return runeUnwrapRequests[_reqIdx].isProcessed ? true : false;
    }

    function totalRuneUnwrapRequests() external view override returns (uint) {
        return runeUnwrapRequests.length;
    }

    /// @notice Setter for reward distributor
    /// @dev This contract distributes locker fee between locker and stakers
    function setRewardDistributor(
        address _rewardDistributor
    ) external override onlyOwner {
        rewardDistributor = _rewardDistributor;
    }

    /// @notice Setter for locker locking script
    function setLockerLockingScript(
        bytes memory _lockerLockingScript,
        ScriptTypes _lockerScriptType
    ) public override onlyOwner {
        lockerLockingScript = _lockerLockingScript;
        lockerScriptType = _lockerScriptType;
    }

    /// @notice Setter for starting block number
    function setStartingBlockNumber(
        uint _startingBlockNumber
    ) public override onlyOwner {
        require(
            _startingBlockNumber > startingBlockNumber,
            "Router: low number"
        );
        startingBlockNumber = _startingBlockNumber;
    }

    /// @notice Setter for protocol percentage fee
    function setProtocolPercentageFee(
        uint _protocolPercentageFee
    ) public override onlyOwner {
        require(
            MAX_PROTOCOL_FEE >= _protocolPercentageFee,
            "Router: out of range"
        );
        emit NewProtocolPercentageFee(
            protocolPercentageFee,
            _protocolPercentageFee
        );
        protocolPercentageFee = _protocolPercentageFee;
    }

    /// @notice Setter for locker percentage fee
    function setLockerPercentageFee(
        uint _lockerPercentageFee
    ) public override onlyOwner {
        require(
            MAX_PROTOCOL_FEE >= _lockerPercentageFee,
            "Router: out of range"
        );
        emit NewLockerPercentageFee(lockerPercentageFee, _lockerPercentageFee);
        lockerPercentageFee = _lockerPercentageFee;
    }

    /// @notice Setter for Bitcoin relay
    function setRelay(
        address _relay
    ) public override onlyOwner {
        relay = _relay;
    }

    /// @notice Setter for locker
    function setLocker(
        address _locker
    ) public override onlyOwner {
        emit NewLocker(locker, _locker);
        locker = _locker;
    }

    /// @notice Setter for teleporter
    function setTeleporter(
        address _teleporter
    ) public override onlyOwner {
        emit NewTeleporter(teleporter, _teleporter);
        teleporter = _teleporter;
    }

    /// @notice Setter for treasury
    function setTreasury(
        address _treasury
    ) public override onlyOwner {
        treasury = _treasury;
    }

    /// @notice Set exchange connector for appId
    /// @dev If address(0) is set for an appId, that appId is inactive
    function setExchangeConnector(
        uint _appId,
        address _exchangeConnector
    ) external override onlyOwner {
        exchangeConnector[_appId] = _exchangeConnector;
    }

    /// @notice Setter for third party address and fee
    function setThirdParty(
        uint _thirdPartyId,
        address _thirdPartyAddress,
        uint _thirdPartyFee
    ) external override onlyOwner {
        emit ThirdPartyInfoUpdated(
            _thirdPartyId,
            thirdParties[_thirdPartyId].thirdPartyAddress,
            thirdParties[_thirdPartyId].thirdPartyFee,
            _thirdPartyAddress,
            _thirdPartyFee
        );

        thirdParty memory _thirdParty;
        _thirdParty.thirdPartyAddress = _thirdPartyAddress;
        _thirdParty.thirdPartyFee = _thirdPartyFee;
        thirdParties[_thirdPartyId] = _thirdParty;
    }

    /// @notice Setter for chainId
    function setChainId(uint _chainId) public override onlyOwner {
        chainId = _chainId;
    }

    /// @notice Setter for wrapped native token
    function setWrappedNativeToken(
        address _wrappedNativeToken
    ) public override onlyOwner {
        wrappedNativeToken = _wrappedNativeToken;
    }

    /// @notice Virtual locker is introduced bcz of reward distribution contract
    function setVirtualLocker(
        address _wrappedRune,
        address _virtualLocker
    ) external override onlyOwner {
        virtualLocker[_wrappedRune] = _virtualLocker;
    }

    /// @notice Setter for across contract
    function setAcross(address _across) external override onlyOwner {
        across = _across;
    }

    /// @notice Deploy wrapped Rune token contract
    /// @dev We assign tokenId to a supported Rune
    /// @param _runeId Real rune id
    /// @param _internalId Internal id
    function addRune(
        string memory _name,
        string memory _symbol,
        string memory _runeId,
        uint8 _decimal,
        uint _internalId
    ) external override onlyOwner {
        // Cannot assign to a used tokenId
        require(
            supportedRunes[_internalId] == address(0),
            "Router: used id"
        );

        // Deploy logic contract
        address wRuneLogic = RuneRouterLib.addRuneHelper();

        bytes memory nullData;
        WRuneProxy _wRuneProxy = new WRuneProxy(wRuneLogic, owner(), nullData);
        // ^^ We set current owner as the proxy admin

        address wRuneProxy = address(_wRuneProxy);

        // Initialize proxy (logic owner is this contract)
        WRuneLogic(wRuneProxy).initialize(_name, _symbol, _decimal);

        // Add this contract as minter and burner
        WRuneLogic(wRuneProxy).addMinter(address(this));
        WRuneLogic(wRuneProxy).addBurner(address(this));

        supportedRunes[_internalId] = wRuneProxy;
        internalIds[wRuneProxy] = _internalId;
        runeIds[wRuneProxy] = _runeId;

        emit NewRune(
            _name,
            _symbol,
            _runeId,
            _decimal,
            _internalId,
            wRuneProxy,
            wRuneLogic
        );
    }

    /// @notice Remove support of a wrapped RUNE token
    function removeRune(uint _internalId) external override onlyOwner {
        address wrappedRune = supportedRunes[_internalId];
        require(wrappedRune != address(0), "Router: no token");
        emit RuneRemoved(_internalId, wrappedRune);
        delete runeIds[wrappedRune];
        delete internalIds[wrappedRune];
        delete supportedRunes[_internalId];
    }

    /// @notice Setter for unwrap fee
    /// @dev This fee is taken for unwrap requests to cover the Bitcoin network fee
    function setUnwrapFee(uint _newFee) external override onlyOwner {
        emit UnwrapFeeUpdated(unwrapFee, _newFee);
        unwrapFee = _newFee;
    }

    /// @notice Process wrap Rune request
    /// @dev Locker submits wrap requests to this function for:
    ///      1) Checking tx inclusion
    ///      2) Extracting wrap request info from the OP_RETURN output
    ///      3) Exchanging wrapped Rune (if request is wrap & exchange) using the path
    ///         provided by the locker
    /// @param _version of Bitcoin tx
    /// @param _vin Tx inputs
    /// @param _vout Tx outputs
    /// @param _locktime Tx locktime
    /// @param _blockNumber that includes the tx
    /// @param _intermediateNodes Merkle proof for tx
    /// @param _index of tx in the block
    function wrapRune(
        bytes4 _version,
        bytes memory _vin,
        bytes calldata _vout,
        bytes4 _locktime,
        uint256 _blockNumber,
        bytes calldata _intermediateNodes,
        uint _index,
        address[] memory _path
    ) external payable override nonReentrant {
        require(_msgSender() == teleporter, "Router: not teleporter");

        // Find txId and check its inclusion
        bytes32 txId = RuneRouterLib.checkTx(
            startingBlockNumber,
            relay,
            _version,
            _vin,
            _vout,
            _locktime,
            _blockNumber,
            _intermediateNodes,
            _index
        );

        // Extract information from the request & find fees and remaining amount
        (
            uint remainingAmount,
            fees memory fee,
            address _thirdPartyAddress,
            address wrappedRune
        ) = RuneRouterLib.wrapHelper(
                _vout,
                txId,
                runeWrapRequests,
                supportedRunes,
                thirdParties,
                protocolPercentageFee,
                lockerPercentageFee
            );

        // Mint wrapped tokens
        IRune(wrappedRune).mint(
            address(this),
            fee.protocolFee +
                fee.lockerFee +
                fee.thirdPartyFee +
                remainingAmount
        );

        // Send protocol, locker and third party fee
        IRune(wrappedRune).transfer(treasury, fee.protocolFee);

        _sendLockerFee(fee.lockerFee, wrappedRune);

        if (_thirdPartyAddress != address(0)) {
            IRune(wrappedRune).transfer(_thirdPartyAddress, fee.thirdPartyFee);
        }

        runeWrapRequest memory request = runeWrapRequests[txId];

        if (request.appId == 0) {
            // This is a wrap request
            // Transfer wrapped tokens to user
            IRune(wrappedRune).transfer(
                request.recipientAddress,
                remainingAmount
            );

            emit NewRuneWrap(
                request.recipientAddress,
                remainingAmount,
                wrappedRune,
                fee,
                _thirdPartyAddress,
                txId
            );
        } else {
            // This is wrap & exchange request
            // Check exchange path provided by locker
            require(
                _path[0] == request.inputToken &&
                    _path[_path.length - 1] == request.outputToken,
                "Router: wrong path"
            );

            // Swapped tokens are sent to this contract
            (bool result, uint[] memory amounts) = _swap(
                request.appId,
                address(this),
                remainingAmount,
                request.outputAmount,
                _path
            );

            if (result) {
                // Swap successful
                emit NewRuneWrapAndSwap(
                    request.recipientAddress,
                    remainingAmount,
                    wrappedRune,
                    amounts[amounts.length - 1],
                    request.outputToken,
                    fee,
                    _thirdPartyAddress,
                    txId,
                    request.speed,
                    request.chainId
                );
                if (request.chainId == chainId) {
                    // Transfer exchanged tokens to user
                    IRune(request.outputToken).transfer(
                        request.recipientAddress,
                        amounts[amounts.length - 1]
                    );
                } else {
                    runeWrapRequests[txId].isTransferredToOtherChain = true;
                    // Transfer exchanged tokens to the destination chain
                    _sendTokenToOtherChain(
                        request.chainId,
                        request.outputToken,
                        amounts[amounts.length - 1],
                        request.recipientAddress,
                        request.bridgeFee
                    );
                }
            } else {
                // Swap failed
                emit FailedRuneWrapAndSwap(
                    request.recipientAddress,
                    remainingAmount,
                    wrappedRune,
                    request.outputAmount,
                    request.outputToken,
                    fee,
                    _thirdPartyAddress,
                    txId,
                    request.speed,
                    request.chainId
                );
                if (request.chainId == chainId) {
                    // Transfer wrapped tokens to user
                    IRune(wrappedRune).transfer(
                        request.recipientAddress,
                        remainingAmount
                    );
                } else {
                    // Update input amount to remaining amount
                    runeWrapRequests[txId].inputAmount = remainingAmount;
                }
            }
        }
    }

    /// @notice Process user rune unwrap request
    /// @dev For unwrap requests (not swap & unwrap), pass _appId,
    ///      _inputAmount and _path ZERO
    /// @param _amount of WRune that user wants to burn
    /// @param _userScript User script hash
    /// @param _scriptType User script type
    function unwrapRune(
        uint _thirdPartyId,
        uint _internalId,
        uint _amount,
        bytes memory _userScript,
        ScriptTypes _scriptType,
        uint _appId,
        uint _inputAmount,
        address[] memory _path
    ) public payable override nonReentrant {
        address token = supportedRunes[_internalId];
        require(token != address(0), "Router: not supported");

        if (msg.value > unwrapFee) {
            // Input token is native token
            require(
                msg.value == _inputAmount + unwrapFee,
                "Router: wrong value"
            );

            require(
                wrappedNativeToken == _path[0],
                "Router: invalid path"
            );

            // Mint wrapped native token
            IWETH(wrappedNativeToken).deposit{value: _inputAmount}();
        } else {
            // Input token != native token
            require(msg.value == unwrapFee, "Router: wrong fee");
        }

        if (_path.length != 0) {
            // This is a swap and unwrap request

            if (msg.value == unwrapFee) {
                // Transfer user's tokens to contract
                // Input token is not native token
                IRune(_path[0]).transferFrom(
                    _msgSender(),
                    address(this),
                    _inputAmount
                );
            }

            (bool result, uint[] memory amounts) = _swap(
                _appId,
                address(this),
                _inputAmount,
                _amount,
                _path
            );
            require(result, "Router: swap failed");
            _amount = amounts[amounts.length - 1]; // Rune amount that would be burnt
        } else {
            // This is a unwrap request
            // Transfer user's tokens to contract
            require(
                IRune(token).transferFrom(_msgSender(), address(this), _amount),
                "Router: transfer failed"
            );
        }

        (
            fees memory fee,
            address thirdPartyAddress,
            uint remainingAmount
        ) = _unwrapRune(
                _thirdPartyId,
                token,
                _amount,
                _userScript,
                _scriptType
            );

        if (_path.length == 0) {
            emit NewRuneUnwrap(
                _msgSender(),
                _userScript,
                _scriptType,
                token,
                _amount,
                remainingAmount,
                fee,
                unwrapFee,
                thirdPartyAddress,
                runeUnwrapRequests.length - 1
            );
        } else {
            emit NewRuneSwapAndUnwrap(
                _msgSender(),
                _userScript,
                _scriptType,
                _inputAmount,
                _path[0],
                _amount,
                remainingAmount,
                token,
                fee,
                unwrapFee,
                thirdPartyAddress,
                runeUnwrapRequests.length - 1
            );
        }
    }

    /// @notice Check proof of unwraping Runes
    function unwrapProofRune(
        bytes4 _version,
        bytes memory _vin,
        bytes memory _vout,
        bytes4 _locktime,
        uint256 _blockNumber,
        bytes memory _intermediateNodes,
        uint _index,
        uint[] memory _reqIndexes
    ) external payable override nonReentrant {
        require(_msgSender() == locker, "Router: not locker");

        bytes32 txId = RuneRouterLib.checkTx(
            startingBlockNumber,
            relay,
            _version,
            _vin,
            _vout,
            _locktime,
            _blockNumber,
            _intermediateNodes,
            _index
        );

        for (uint i = 0; i < _reqIndexes.length; i++) {
            require(
                !runeUnwrapRequests[_reqIndexes[i]].isProcessed,
                "Router: already processed"
            );
            runeUnwrapRequests[_reqIndexes[i]].isProcessed = true;
            emit UnwrapRuneProcessed(
                runeUnwrapRequests[_reqIndexes[i]].sender,
                runeUnwrapRequests[_reqIndexes[i]].burntAmount,
                runeUnwrapRequests[_reqIndexes[i]].userScript,
                runeUnwrapRequests[_reqIndexes[i]].scriptType,
                _reqIndexes[i],
                txId
            );
        }
    }

    /// @notice Retry for failed exchange request
    /// @dev Users can retry their failed exchange request if
    /// their request destination is different from the current chain
    /// @param _message ABI encode of (txId, outputAmount, acrossRelayerFee, exchangePath)
    /// @param _r Signature r
    /// @param _s Signature s
    /// @param _v Signature v
    function retryFailedWrapAndSwap(
        bytes memory _message,
        bytes32 _r,
        bytes32 _s,
        uint8 _v
    ) external override nonReentrant {
        (
            bytes32 _txId,
            uint256 _newOutputAmount,
            uint256 _newBridgeFee,
            address[] memory _path
        ) = abi.decode(_message, (bytes32, uint256, uint256, address[]));

        RuneRouterLib.processFailedRequest(
            runeWrapRequests,
            _txId,
            _message,
            _r,
            _s,
            _v,
            chainId
        );

        runeWrapRequest memory request = runeWrapRequests[_txId];

        // Exchange wrapped Rune for desired token
        (bool result, uint256[] memory amounts) = _swap(
            request.appId,
            address(this),
            request.inputAmount,
            _newOutputAmount,
            _path
        );

        require(result, "Router: swap failed");

        // Send exchanged tokens to the destination chain
        _sendTokenToOtherChain(
            request.chainId,
            _path[_path.length - 1],
            amounts[amounts.length - 1],
            request.recipientAddress,
            _newBridgeFee
        );
    }

    /// @notice Request withdraw for failed exchange request
    /// @dev Users can get their Rune back if the request execution failed and 
    ///      their request destination is different from the current chain
    /// @param _message ABI encode of (txId, scriptType, userScript)
    /// @param _r Signature r
    /// @param _s Signature s
    /// @param _v Signature v
    function withdrawFailedWrapAndSwap(
        bytes memory _message,
        bytes32 _r,
        bytes32 _s,
        uint8 _v
    ) external override nonReentrant {
        (bytes32 _txId, uint8 _scriptType, bytes memory _userScript) = abi
            .decode(_message, (bytes32, uint8, bytes));

        RuneRouterLib.processFailedRequest(
            runeWrapRequests,
            _txId,
            _message,
            _r,
            _s,
            _v,
            chainId
        );

        // Unwrap wrapped Rune
        unwrapRune(
            0,
            internalIds[runeWrapRequests[_txId].inputToken],
            runeWrapRequests[_txId].inputAmount,
            _userScript,
            ScriptTypes(_scriptType),
            0,
            0,
            new address[](0)
        );
    }

    /// @notice Send locker fee by calling reward distributor
    function _sendLockerFee(uint _lockerFee, address _wrappedRune) internal {
        if (_lockerFee > 0) {
            if (rewardDistributor == address(0)) {
                // Send reward directly to locker
                IRune(_wrappedRune).transfer(locker, _lockerFee);
            } else {
                // Call reward distributor to distribute reward
                IRune(_wrappedRune).approve(rewardDistributor, _lockerFee);
                Address.functionCall(
                    rewardDistributor,
                    abi.encodeWithSignature(
                        "depositReward(address,uint256)",
                        virtualLocker[_wrappedRune],
                        _lockerFee
                    )
                );
            }
        }
    }

    /// @notice Burns wrapped Rune and record the request
    function _unwrapRune(
        uint _thirdPartyId,
        address _token,
        uint _amount,
        bytes memory _userScript,
        ScriptTypes _scriptType
    )
        private
        returns (
            fees memory _fee,
            address _thirdPartyAddress,
            uint _remainingAmount
        )
    {
        // Save unwrap request and get fee and burnt amounts
        (_fee, _thirdPartyAddress, _remainingAmount) = RuneRouterLib
            .unwrapHelper(
                _msgSender(),
                protocolPercentageFee,
                lockerPercentageFee,
                runeUnwrapRequests,
                thirdParties,
                _thirdPartyId,
                _amount,
                _userScript,
                _scriptType
            );

        runeUnwrapCounter++;

        // Send protocol, locker and third party fee
        IRune(_token).transfer(treasury, _fee.protocolFee);

        _sendLockerFee(_fee.lockerFee, _token);

        if (_thirdPartyAddress != address(0)) {
            IRune(_token).transfer(_thirdPartyAddress, _fee.thirdPartyFee);
        }

        // Send unwrap fee (in native token) to locker
        Address.sendValue(payable(locker), unwrapFee);

        // Burn remained amount
        IRune(_token).burn(_remainingAmount);
    }

    // Swap tokens using an exchange connector
    function _swap(
        uint _appId,
        address _recipientAddress,
        uint _inputAmount,
        uint _outputAmount,
        address[] memory _path
    ) private returns (bool _result, uint[] memory _amounts) {
        address _exchangeConnector = exchangeConnector[_appId];
        require(
            _exchangeConnector != address(0),
            "Router: invalid appId"
        );

        IRune(_path[0]).approve(_exchangeConnector, _inputAmount);

        if (IDexConnector(_exchangeConnector).isPathValid(_path)) {
            (_result, _amounts) = IDexConnector(_exchangeConnector).swap(
                _inputAmount,
                _outputAmount,
                _path,
                _recipientAddress,
                block.timestamp,
                true // Input amount is fixed
            );
        } else {
            _result = false;
        }
    }

    /// @notice Send tokens to the destination using Across
    function _sendTokenToOtherChain(
        uint256 _chainId,
        address _token,
        uint256 _amount,
        address _user,
        uint256 _acrossRelayerFee
    ) private {
        IRune(_token).approve(across, _amount);

        SpokePoolInterface(across).deposit(
            _user,
            _token,
            _amount,
            _chainId,
            int64(uint64(_acrossRelayerFee)),
            uint32(block.timestamp),
            "0x", // Null data
            115792089237316195423570985008687907853269984665640564039457584007913129639935
        );
    }
}
