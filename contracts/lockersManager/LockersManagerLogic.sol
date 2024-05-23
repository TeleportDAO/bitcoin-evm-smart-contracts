// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <=0.8.4;

import "./LockersManagerStorage.sol";
import "./LockersManagerStorage2.sol";
import "../oracle/interfaces/IPriceOracle.sol";
import "../erc20/interfaces/ITeleBTC.sol";
import "../routers/interfaces/IBurnRouter.sol";
import "../libraries/LockersManagerLib.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

//TODO tartib
contract LockersManagerLogic is
    LockersManagerStorage,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    LockersManagerStorage2
{
    error ZeroAddress();
    error ZeroValue();
    error NotBurner();
    error NotMinter();
    error NotLocker();
    error TransferFailed();
    error LockerActive();
    error InvalidValue();
    error AlreadyHasRole();
    error NotRequested();

    using LockersManagerLib for *;
    using SafeERC20 for IERC20;

    function initialize(
        address _teleBTC,
        address _priceOracle,
        address _ccBurnRouter,
        uint256 _minRequiredTDTLockedAmount,
        uint256 _collateralRatio,
        uint256 _liquidationRatio,
        uint256 _lockerPercentageFee,
        uint256 _priceWithDiscountRatio
    ) public initializer {
        OwnableUpgradeable.__Ownable_init();
        ReentrancyGuardUpgradeable.__ReentrancyGuard_init();
        PausableUpgradeable.__Pausable_init();

        setTeleBTC(_teleBTC);
        setCCBurnRouter(_ccBurnRouter);
        setPriceOracle(_priceOracle);
        setMinRequiredTDTLockedAmount(_minRequiredTDTLockedAmount);
        setCollateralRatio(_collateralRatio);
        setLiquidationRatio(_liquidationRatio);
        setLockerPercentageFee(_lockerPercentageFee);
        setPriceWithDiscountRatio(_priceWithDiscountRatio);

        libConstants.OneHundredPercent = ONE_HUNDRED_PERCENT;
        libConstants.HealthFactor = HEALTH_FACTOR;
        libConstants.UpperHealthFactor = UPPER_HEALTH_FACTOR;
        libConstants.MaxLockerFee = MAX_LOCKER_FEE;
        libConstants.NativeTokenDecimal = NATIVE_TOKEN_DECIMAL;
        libConstants.NativeToken = NATIVE_TOKEN;
    }

    // *************** Modifiers ***************

    modifier nonZeroAddress(address _address) {
        if (_address == address(0)) revert ZeroAddress();
        _;
    }

    modifier nonZeroValue(uint256 _value) {
        if (_value == 0) revert ZeroValue();
        _;
    }

    modifier onlyMinter() {
        if (!isMinter(_msgSender())) revert NotMinter();
        _;
    }

    modifier onlyBurner() {
        if (!isBurner(_msgSender())) revert NotBurner();
        _;
    }

    // *************** External functions ***************

    // @notice Whitelist new collateral token with decimal
    // @notice Set _decimal to 0 to remove token from whitelist
    function addCollateralToken (address _token, uint _decimal) external
        override
        nonZeroAddress(_token)
        onlyOwner 
    {
        collateralDecimal[_token] = _decimal;
        emit NewCollateralToken(_token, _decimal);
    }

    /// @notice Give an account access to mint
    function addMinter(address _account)
        external
        override
        nonZeroAddress(_account)
        onlyOwner
    {
        if (isMinter(_account))
            revert AlreadyHasRole();
            
        minters[_account] = true;
        emit MinterAdded(_account);
    }

    /// @notice Remove an account's access to mint
    function removeMinter(address _account)
        external
        override
        onlyOwner
    {
        if (!isMinter(_account))
            revert NotMinter();
            
        minters[_account] = false;
        emit MinterRemoved(_account);
    }

    /// @notice Give an account access to burn
    function addBurner(address _account)
        public
        override
        nonZeroAddress(_account)
        onlyOwner
    {
        if (isBurner(_account))
            revert AlreadyHasRole();

        burners[_account] = true;
        emit BurnerAdded(_account);
    }

    /// @notice Remove an account's access to burn
    function removeBurner(address _account)
        public
        override
        onlyOwner
    {
        // if (!isBurner(_account)) 
        //     revert NotBurner();
        burners[_account] = false;
        emit BurnerRemoved(_account);
    }

    /// @notice Pause the contract
    /// @dev Only functions with whenPaused modifier can be called
    function pauseLocker() external override onlyOwner {
        _pause();
    }

    /// @notice Un-pause the contract
    /// @dev Only functions with whenNotPaused modifier can be called
    function unPauseLocker() external override onlyOwner {
        _unpause();
    }

    /// @notice Return EVM address of _lockerLockingScript Locker
    function getLockerTargetAddress(bytes calldata _lockerLockingScript)
        external
        view
        override
        returns (address)
    {
        return lockerTargetAddress[_lockerLockingScript];
    }

    /// @notice Return true if _lockerLockingScript is Locker
    function isLocker(bytes calldata _lockerLockingScript)
        external
        view
        override
        returns (bool)
    {
        return
            lockersMapping[lockerTargetAddress[_lockerLockingScript]].isLocker;
    }

    /// @notice Return total number of Lockers
    function getNumberOfLockers() external view override returns (uint256) {
        return totalNumberOfLockers;
    }

    /// @notice Return locking script of _lockerTargetAddress Locker
    function getLockerLockingScript(address _lockerTargetAddress)
        external
        view
        override
        returns (bytes memory)
    {
        return lockersMapping[_lockerTargetAddress].lockerLockingScript;
    }

    /// @notice Update TST contract address
    function setTST(address _TST)
        public
        override
        onlyOwner
    {
        emit NewTST(TeleportDAOToken, _TST);
        TeleportDAOToken = _TST;
        libParams.teleportDAOToken = TeleportDAOToken;
    }

    /// @notice Update locker percentage fee
    /// @dev This fee is taken by Locker for every minting or burning
    function setLockerPercentageFee(uint256 _lockerPercentageFee)
        public
        override
        onlyOwner
    {
        if (_lockerPercentageFee > MAX_LOCKER_FEE) revert InvalidValue();
        emit NewLockerPercentageFee(lockerPercentageFee, _lockerPercentageFee);
        lockerPercentageFee = _lockerPercentageFee;
        libParams.lockerPercentageFee = lockerPercentageFee;
    }

    /// @notice Update price with discount ratio
    /// @dev This ratio gives discount to users who participate in Locker liquidation
    function setPriceWithDiscountRatio(uint256 _priceWithDiscountRatio)
        public
        override
        onlyOwner
    {
        if (_priceWithDiscountRatio > ONE_HUNDRED_PERCENT) revert InvalidValue();
        emit NewPriceWithDiscountRatio(
            priceWithDiscountRatio,
            _priceWithDiscountRatio
        );

        priceWithDiscountRatio = _priceWithDiscountRatio;
        libParams.priceWithDiscountRatio = priceWithDiscountRatio;
    }

    /// @notice Update the required TST bond to become Locker
    function setMinRequiredTDTLockedAmount(uint256 _minRequiredTDTLockedAmount)
        public
        override
        onlyOwner
    {
        emit NewMinRequiredTDTLockedAmount(
            minRequiredTDTLockedAmount,
            _minRequiredTDTLockedAmount
        );
        minRequiredTDTLockedAmount = _minRequiredTDTLockedAmount;
        libParams.minRequiredTDTLockedAmount = minRequiredTDTLockedAmount;
    }

    /// @notice Update the price oracle
    /// @dev This oracle is used to get the price of native token in BTC
    function setPriceOracle(address _priceOracle)
        public
        override
        nonZeroAddress(_priceOracle)
        onlyOwner
    {
        emit NewPriceOracle(priceOracle, _priceOracle);
        priceOracle = _priceOracle;
        libParams.priceOracle = priceOracle;
    }

    /// @notice Update burn router address
    function setCCBurnRouter(address _ccBurnRouter)
        public
        override
        nonZeroAddress(_ccBurnRouter)
        onlyOwner
    {
        emit NewCCBurnRouter(ccBurnRouter, _ccBurnRouter);
        removeBurner(ccBurnRouter);
        ccBurnRouter = _ccBurnRouter;
        libParams.ccBurnRouter = ccBurnRouter;
        addBurner(ccBurnRouter);
    }

    /// @notice Update wrapped BTC address
    function setTeleBTC(address _teleBTC)
        public
        override
        nonZeroAddress(_teleBTC)
        onlyOwner
    {
        emit NewTeleBTC(teleBTC, _teleBTC);
        teleBTC = _teleBTC;
        libParams.teleBTC = teleBTC;
    }

    /// @notice Update locker reliability factor
    /// @dev This ratio is used as a helper to calculate the maximum mintable TeleBTC by a Locker
    function setLockerReliabilityFactor(address lockerTargetAddress, uint reliabilityFactor)
        public
        override
        nonZeroValue(reliabilityFactor)
        onlyOwner
    {
        emit NewReliabilityFactor(lockerTargetAddress, lockerReliabilityFactor[lockerTargetAddress], reliabilityFactor);
        lockerReliabilityFactor[lockerTargetAddress] = reliabilityFactor;
    }

    /// @notice Update collateral ratio
    /// @dev This ratio is used to calculate the maximum mintable TeleBTC by a Locker
    function setCollateralRatio(uint256 _collateralRatio)
        public
        override
        onlyOwner
    {
        if (_collateralRatio <= liquidationRatio) revert InvalidValue();
        emit NewCollateralRatio(collateralRatio, _collateralRatio);
        collateralRatio = _collateralRatio;
        libParams.collateralRatio = collateralRatio;
    }

    /// @notice Update liquidation ratio
    function setLiquidationRatio(uint256 _liquidationRatio)
        public
        override
        onlyOwner
    {
        if (collateralRatio <= _liquidationRatio) revert InvalidValue();
        emit NewLiquidationRatio(liquidationRatio, _liquidationRatio);
        liquidationRatio = _liquidationRatio;
        libParams.liquidationRatio = liquidationRatio;
    }

    /// @notice Submit request to become Locker
    /// @dev This request may be approved by the owner
    /// @param _candidateLockingScript Locking script of the Locker. Users can use this script to lock BTC.
    /// @param _lockedTSTAmount TST bond amount
    /// @param _lockedNativeTokenAmount TNT (target native token) bond amount
    /// @param _lockerRescueType Type of Locker's rescue script (e.g. P2SH)
    /// @param _lockerRescueScript Rescue script of Locker. In the case of liqudation, BTC is sent to this script.
    /// @return True if candidate added successfully
    function requestToBecomeLocker(
        bytes calldata _candidateLockingScript,
        address _collateralToken,
        uint256 _lockedTSTAmount,
        uint256 _lockedNativeTokenAmount,
        ScriptTypes _lockerRescueType,
        bytes calldata _lockerRescueScript
    ) external payable override nonReentrant returns (bool) {
        LockersManagerLib.requestToBecomeLocker(
            lockersMapping,
            becomeLockerArguments(  
                libConstants,
                libParams,
                lockerTargetAddress[_candidateLockingScript],
                _collateralToken,
                collateralDecimal[_collateralToken],
                _lockedTSTAmount,
                _lockedNativeTokenAmount,
                _candidateLockingScript,
                _lockerRescueType,
                _lockerRescueScript
            )
        );

        lockerCollateralToken[_msgSender()] = _collateralToken;
        
        if (_collateralToken != NATIVE_TOKEN) {
            IERC20(_collateralToken).safeTransferFrom(
                _msgSender(),
                address(this),
                _lockedNativeTokenAmount
            );
        }

        if (libParams.teleportDAOToken != address(0)) {
            IERC20(libParams.teleportDAOToken).safeTransferFrom(
                _msgSender(),
                address(this),
                _lockedTSTAmount
            );
        }

        totalNumberOfCandidates = totalNumberOfCandidates + 1;

        emit RequestAddLocker(
            _msgSender(),
            _candidateLockingScript,
            _lockedTSTAmount,
            _collateralToken,
            _lockedNativeTokenAmount
        );

        return true;
    }

    /// @notice Revoke request to become Locker
    /// @dev Send back TST and TNT collateral to the candidate
    /// @return True if the candidate is removed successfully
    function revokeRequest() external override nonReentrant returns (bool) {
        if (!lockersMapping[_msgSender()].isCandidate)
            revert NotRequested();

        // Loads locker's information
        locker memory lockerRequest = lockersMapping[_msgSender()];

        // Removes candidate from lockersMapping
        delete lockersMapping[_msgSender()];

        totalNumberOfCandidates = totalNumberOfCandidates - 1;

        // Sends back TDT and TNT collateral
        if (libParams.teleportDAOToken != address(0)) {
            IERC20(TeleportDAOToken).safeTransfer(
                _msgSender(),
                lockerRequest.TDTLockedAmount
            );
        }
        
        if (lockerCollateralToken[_msgSender()] == NATIVE_TOKEN) {
            Address.sendValue(
                payable(_msgSender()),
                lockerRequest.nativeTokenLockedAmount
            );
        } else {
            IERC20(lockerCollateralToken[_msgSender()]).transfer(
                _msgSender(),
                lockerRequest.nativeTokenLockedAmount
            );
        }

        emit RevokeAddLockerRequest(
            _msgSender(),
            lockerRequest.lockerLockingScript,
            lockerRequest.TDTLockedAmount,
            lockerCollateralToken[_msgSender()],
            lockerRequest.nativeTokenLockedAmount
        );

        delete lockerCollateralToken[_msgSender()];

        return true;
    }

    /// @notice Approve the candidate request to become Locker
    /// @dev Only owner can call this. The isCandidate is also set to false.
    /// @param _lockerTargetAddress Locker's target chain address
    /// @return True if the candidate is added successfully
    function addLocker(address _lockerTargetAddress, uint256 _lockerReliabilityFactor)
        external
        override
        nonZeroAddress(_lockerTargetAddress)
        nonZeroValue(_lockerReliabilityFactor)
        nonReentrant
        onlyOwner
        returns (bool)
    {
        if(!lockersMapping[_lockerTargetAddress].isCandidate)
            revert NotRequested();

        // Updates locker's status
        lockersMapping[_lockerTargetAddress].isCandidate = false;
        lockersMapping[_lockerTargetAddress].isLocker = true;

        // Updates number of candidates and lockers
        totalNumberOfCandidates = totalNumberOfCandidates - 1;
        totalNumberOfLockers = totalNumberOfLockers + 1;

        lockerTargetAddress[
            lockersMapping[_lockerTargetAddress].lockerLockingScript
        ] = _lockerTargetAddress;

        lockerReliabilityFactor[_lockerTargetAddress] = _lockerReliabilityFactor;

        emit LockerAdded(
            _lockerTargetAddress,
            lockersMapping[_lockerTargetAddress].lockerLockingScript,
            lockersMapping[_lockerTargetAddress].TDTLockedAmount,
            lockerCollateralToken[_lockerTargetAddress],
            lockersMapping[_lockerTargetAddress].nativeTokenLockedAmount,
            _lockerReliabilityFactor,
            block.timestamp
        );
        return true;
    }

    /// @notice Request to inactivate Locker
    /// @dev This would inactivate Locker after INACTIVATION_DELAY. The impact of inactivation is:
    ///      1. No one can mint TeleBTC by the Locker
    ///      2. Locker can be removed
    ///      3. Locker can withdraw unused collateral
    /// @return True if deactivated successfully
    function requestInactivation()
        external
        override
        nonReentrant
        returns (bool)
    {
        if (!lockersMapping[_msgSender()].isLocker)
            revert NotLocker();

        require(
            lockerInactivationTimestamp[_msgSender()] == 0,
            "Lockers: already requested"
        );

        lockerInactivationTimestamp[_msgSender()] =
            block.timestamp +
            INACTIVATION_DELAY;

        emit RequestInactivateLocker(
            _msgSender(),
            lockerInactivationTimestamp[_msgSender()],
            lockersMapping[_msgSender()].lockerLockingScript,
            lockersMapping[_msgSender()].TDTLockedAmount,
            lockerCollateralToken[_msgSender()],
            lockersMapping[_msgSender()].nativeTokenLockedAmount,
            lockersMapping[_msgSender()].netMinted
        );

        return true;
    }

    /// @notice Activate Locker
    /// @dev Users can only mint TeleBTC by active locker
    ///      Note: lockerInactivationTimestamp = 0 means that the Locker is active
    /// @return True if activated successfully
    function requestActivation() external override nonReentrant returns (bool) {
        if (!lockersMapping[_msgSender()].isLocker)
            revert NotLocker();

        lockerInactivationTimestamp[_msgSender()] = 0;

        emit ActivateLocker(
            _msgSender(),
            lockersMapping[_msgSender()].lockerLockingScript,
            lockersMapping[_msgSender()].TDTLockedAmount,
            lockerCollateralToken[_msgSender()],
            lockersMapping[_msgSender()].nativeTokenLockedAmount,
            lockersMapping[_msgSender()].netMinted
        );

        return true;
    }

    /// @notice Removes Locker from system and send back Locker TST and TNT collateral.
    /// @dev Only Locker can call this. The conditions for successful remove is:
    ///      1. Locker has been inactivated
    ///      2. Locker net minted TeleBTC is 0
    ///      3. Locker is not being slashed
    /// @return True if locker is removed successfully
    function selfRemoveLocker() external override nonReentrant returns (bool) {
        locker memory _removingLocker = lockersMapping[_msgSender()];

        if (!_removingLocker.isLocker)
            revert NotLocker();

        if (isLockerActive(_msgSender())) revert LockerActive();

        require(_removingLocker.netMinted == 0, "Lockers: 0 net minted");

        require(
            _removingLocker.slashingTeleBTCAmount == 0,
            "Lockers: 0 slashing TBTC"
        );

        // Removes locker from lockersMapping

        delete lockerTargetAddress[
            lockersMapping[_msgSender()].lockerLockingScript
        ];
        delete lockersMapping[_msgSender()];
        totalNumberOfLockers = totalNumberOfLockers - 1;

        // Sends back TDT and TNT collateral
        if (libParams.teleportDAOToken != address(0)) {
            IERC20(TeleportDAOToken).safeTransfer(
                _msgSender(),
                _removingLocker.TDTLockedAmount
            );
        }

        //TODO test adding reservedNativeTokenForSlash
        if (lockerCollateralToken[_msgSender()] == NATIVE_TOKEN) {
            Address.sendValue(
                payable(_msgSender()),
                _removingLocker.nativeTokenLockedAmount + _removingLocker.reservedNativeTokenForSlash
            );
        } else {
            IERC20(lockerCollateralToken[_msgSender()]).transfer(
                _msgSender(),
                _removingLocker.nativeTokenLockedAmount + _removingLocker.reservedNativeTokenForSlash
            );
        }

        emit LockerRemoved(
            _msgSender(),
            _removingLocker.lockerLockingScript,
            _removingLocker.TDTLockedAmount,
            lockerCollateralToken[_msgSender()],
            _removingLocker.nativeTokenLockedAmount
        );
        return true;
    }

    /// @notice Slash Locker for unprocessed unwrap request
    /// @dev Only burn router can call this. Locker is slashed since he doesn't provide burn proof
    ///      before the request deadline. User who made the burn request will receive the slashed bond.
    /// @param _lockerTargetAddress Locker's target chain address
    /// @param _rewardAmount Amount of TeleBTC that slasher receives
    /// @param _slasher Address of slasher who receives reward
    /// @param _amount Amount of TeleBTC that is slashed from Locker
    /// @param _recipient Address of user who receives the slashed collateral
    /// @return True if the locker is slashed successfully
    function slashIdleLocker(
        address _lockerTargetAddress,
        uint256 _rewardAmount,
        address _slasher,
        uint256 _amount,
        address _recipient
    ) external override nonReentrant whenNotPaused returns (bool) {
        //TODO check tests for this cause locker collateral token was wrong
        (uint256 equivalentNativeToken, uint256 rewardAmountInNativeToken) = LockersManagerLib.slashIdleLocker(
            lockersMapping[_lockerTargetAddress],
            lockerCollateralToken[_lockerTargetAddress],
            collateralDecimal[lockerCollateralToken[_lockerTargetAddress]],
            libParams,
            _rewardAmount,
            _amount
        );

        if (lockerCollateralToken[_lockerTargetAddress] == NATIVE_TOKEN) {
            Address.sendValue(
                payable(_recipient),
                equivalentNativeToken - rewardAmountInNativeToken
            );
            Address.sendValue(
                payable(_slasher),
                rewardAmountInNativeToken
            );
        } else {
            IERC20(lockerCollateralToken[_lockerTargetAddress]).transfer(
                _recipient,
                equivalentNativeToken - rewardAmountInNativeToken
            );
            IERC20(lockerCollateralToken[_lockerTargetAddress]).transfer(
                _slasher,
                rewardAmountInNativeToken
            );
        }

        emit LockerSlashed(
            _lockerTargetAddress,
            lockerCollateralToken[_lockerTargetAddress],
            rewardAmountInNativeToken,
            _slasher,
            _amount,
            _recipient,
            equivalentNativeToken,
            block.timestamp,
            true
        );

        return true;
    }

    /// @notice Slash Locker for stealing users BTC
    /// @dev Only burn router can call. Locker is slashed because he moved BTC from
    ///      Locker's Bitcoin address without any corresponding burn req.
    ///      The slashed bond will be sold with discount.
    /// @param _lockerTargetAddress Locker's target chain address
    /// @param _rewardAmount Value of slashed reward (in TeleBTC)
    /// @param _slasher Address of slasher who receives reward
    /// @param _amount Value of slashed collateral (in TeleBTC)
    /// @return True if the locker is slashed successfully
    function slashThiefLocker(
        address _lockerTargetAddress,
        uint256 _rewardAmount,
        address _slasher,
        uint256 _amount
    ) external override nonReentrant whenNotPaused returns (bool) {
        //TODO check tests for this cause locker collateral token was wrong
        address collateralToken = lockerCollateralToken[_lockerTargetAddress];
        (
            uint256 rewardInNativeToken,
            uint256 neededNativeTokenForSlash
        ) = LockersManagerLib.slashThiefLocker(
                lockersMapping[_lockerTargetAddress],
                lockerReliabilityFactor[_lockerTargetAddress],
                libConstants,
                libParams,
                collateralToken,
                collateralDecimal[collateralToken],
                _rewardAmount,
                _amount
            );

        if (lockerCollateralToken[_lockerTargetAddress] == NATIVE_TOKEN) {
            Address.sendValue(
                payable(_slasher),
                rewardInNativeToken
            );
        } else {
            IERC20(lockerCollateralToken[_lockerTargetAddress]).transfer(
                _slasher,
                rewardInNativeToken
            );
        }

        emit LockerSlashed(
            _lockerTargetAddress,
            lockerCollateralToken[_lockerTargetAddress],
            rewardInNativeToken,
            _slasher,
            _amount,
            address(this),
            neededNativeTokenForSlash + rewardInNativeToken,
            block.timestamp,
            false
        );

        return true;
    }

    /// @notice Liquidate Locker with unhealthy collateral
    /// @dev Anyone can liquidate Locker with health factor under
    ///      100% by providing a sufficient amount of TeleBTC.
    /// @param _lockerTargetAddress Locker's target chain address
    /// @param _collateralAmount Amount of TNT collateral that someone wants to buy with discount
    /// @return True if liquidation was successful
    function liquidateLocker(
        address _lockerTargetAddress,
        uint256 _collateralAmount
    )
        external
        override
        nonZeroValue(_collateralAmount)
        nonReentrant
        whenNotPaused
        returns (bool)
    {
        uint256 neededTeleBTC = LockersManagerLib.liquidateLocker(
            lockersMapping[_lockerTargetAddress],
            libConstants,
            libParams,
            lockerCollateralToken[_lockerTargetAddress],
            collateralDecimal[lockerCollateralToken[_lockerTargetAddress]],
            _collateralAmount,
            lockerReliabilityFactor[_lockerTargetAddress]
        );

        locker memory theLiquidatingLocker = lockersMapping[
            _lockerTargetAddress
        ];

        // Updates TNT bond of locker
        lockersMapping[_lockerTargetAddress].nativeTokenLockedAmount =
            lockersMapping[_lockerTargetAddress].nativeTokenLockedAmount -
            _collateralAmount;

        // transfer teleBTC from user
        IERC20(teleBTC).safeTransferFrom(
            msg.sender,
            address(this),
            neededTeleBTC
        );

        // Burns TeleBTC for locker rescue script
        IERC20(teleBTC).approve(ccBurnRouter, neededTeleBTC);
        IBurnRouter(ccBurnRouter).unwrap(
            neededTeleBTC,
            theLiquidatingLocker.lockerRescueScript,
            theLiquidatingLocker.lockerRescueType,
            theLiquidatingLocker.lockerLockingScript,
            0
        );

        if (lockerCollateralToken[_lockerTargetAddress] == NATIVE_TOKEN) {
            Address.sendValue(
                payable(_msgSender()),
                _collateralAmount
            );
        } else {
            IERC20(lockerCollateralToken[_lockerTargetAddress]).transfer(
                _msgSender(),
                _collateralAmount
            );
        }

        emit LockerLiquidated(
            _lockerTargetAddress,
            _msgSender(),
            lockerCollateralToken[_lockerTargetAddress],
            _collateralAmount,
            neededTeleBTC,
            block.timestamp
        );

        return true;
    }

    /// @notice                           Sells lockers slashed collateral
    /// @dev                              Users buy the slashed collateral using TeleBTC with discount
    ///                                   The paid TeleBTC will be burnt to keep the system safe
    ///                                   If all the needed TeleBTC is collected and burnt,
    ///                                   the rest of slashed collateral is sent back to locker
    /// @param _lockerTargetAddress       Locker's target chain address
    /// @param _collateralAmount          Amount of collateral (TNT) that someone intends to buy with discount
    /// @return                           True if buying was successful
    function buySlashedCollateralOfLocker(
        address _lockerTargetAddress,
        uint256 _collateralAmount
    )
        external
        override
        nonZeroValue(_collateralAmount)
        nonReentrant
        whenNotPaused
        returns (bool)
    {
        uint256 neededTeleBTC = LockersManagerLib.buySlashedCollateralOfLocker(
            lockersMapping[_lockerTargetAddress],
            _collateralAmount
        );

        // Burns user's TeleBTC
        if (!
            ITeleBTC(teleBTC).transferFrom(
                _msgSender(),
                address(this),
                neededTeleBTC
            )
        ) revert TransferFailed();

        ITeleBTC(teleBTC).burn(neededTeleBTC);
        
        // Sends bought collateral to user
         if (lockerCollateralToken[_lockerTargetAddress] == NATIVE_TOKEN) {
            Address.sendValue(payable(_msgSender()), _collateralAmount);
        } else {
            IERC20(lockerCollateralToken[_lockerTargetAddress]).transfer(
                _msgSender(),
                _collateralAmount
            );
        }

        emit LockerSlashedCollateralSold(
            _lockerTargetAddress,
            _msgSender(),
            lockerCollateralToken[_lockerTargetAddress],
            _collateralAmount,
            neededTeleBTC,
            block.timestamp
        );

        return true;
    }

    /// @notice                                 Increases TNT collateral of the locker
    /// @notice                                 Not neccessary to fill _addingNativeTokenAmount if collateral token is native token
    /// @param _lockerTargetAddress             Locker's target chain address
    /// @param _addingNativeTokenAmount         Amount of added collateral
    /// @return                                 True if collateral is added successfully
    function addCollateral(
        address _lockerTargetAddress,
        uint256 _addingNativeTokenAmount 
    ) external payable override nonReentrant returns (bool) {

        LockersManagerLib.addCollateralHelper(
            libConstants,
            lockersMapping[_lockerTargetAddress],
            _addingNativeTokenAmount,
            lockerCollateralToken[_lockerTargetAddress]
        );

        if (lockerCollateralToken[_lockerTargetAddress] != NATIVE_TOKEN) {
            IERC20(lockerCollateralToken[_lockerTargetAddress]).safeTransferFrom(
                _msgSender(),
                address(this),
                _addingNativeTokenAmount
            );
        }

        emit CollateralAdded(
            _lockerTargetAddress,
            lockerCollateralToken[_msgSender()],
            _addingNativeTokenAmount,
            lockersMapping[_lockerTargetAddress].nativeTokenLockedAmount,
            block.timestamp
        );

        return true;
    }

    /// @notice                                 Decreases TNT collateral of the locker
    /// @param _removingNativeTokenAmount       Amount of removed collateral
    /// @return                                 True if collateral is removed successfully
    function removeCollateral(uint256 _removingNativeTokenAmount)
        external
        payable
        override
        nonZeroValue(_removingNativeTokenAmount)
        nonReentrant
        returns (bool)
    {
        LockersManagerLib.removeFromCollateral(
            lockersMapping[_msgSender()],
            libConstants,
            libParams,
            lockerReliabilityFactor[_msgSender()],
            lockerCollateralToken[_msgSender()],
            collateralDecimal[lockerCollateralToken[_msgSender()]],
            _removingNativeTokenAmount
        );

        if (isLockerActive(_msgSender())) revert LockerActive();

        if (lockerCollateralToken[_msgSender()] == NATIVE_TOKEN) {
            Address.sendValue(payable(_msgSender()), _removingNativeTokenAmount);
        } else {
            IERC20(lockerCollateralToken[_msgSender()]).safeTransfer(
                _msgSender(),
                _removingNativeTokenAmount
            );
        }

        emit CollateralRemoved(
            _msgSender(),
            lockerCollateralToken[_msgSender()],
            _removingNativeTokenAmount,
            lockersMapping[_msgSender()].nativeTokenLockedAmount,
            block.timestamp
        );

        return true;
    }

    /// @notice                       Mint teleBTC for an account
    /// @dev                          Mint teleBTC for an account and the locker fee as well
    /// @param _lockerLockingScript   Locking script of a locker
    /// @param _receiver              Address of the receiver of the minted teleBTCs
    /// @param _amount                Amount of the teleBTC which is minted, including the locker's fee
    /// @return uint                  The amount of teleBTC minted for the receiver
    function mint(
        bytes calldata _lockerLockingScript,
        address _receiver,
        uint256 _amount
    )
        external
        override
        nonZeroAddress(_receiver)
        nonReentrant
        whenNotPaused
        onlyMinter
        returns (uint256)
    {
        address _lockerTargetAddress = lockerTargetAddress[
            _lockerLockingScript
        ];

        if (_lockerTargetAddress == address(0))
            revert ZeroAddress();
            
        require(isLockerActive(_lockerTargetAddress), "Lockers: not active");

        LockersManagerLib.getLockerCapacity(
            libConstants,
            libParams,
            lockerCollateralToken[_lockerTargetAddress],
            collateralDecimal[lockerCollateralToken[_lockerTargetAddress]],
            lockersMapping[_lockerTargetAddress].nativeTokenLockedAmount,
            lockerReliabilityFactor[_lockerTargetAddress],
            lockersMapping[_lockerTargetAddress].netMinted,
            _amount
        );

        lockersMapping[_lockerTargetAddress].netMinted =
            lockersMapping[_lockerTargetAddress].netMinted +
            _amount;

        // Mints locker fee
        uint256 lockerFee = (_amount * lockerPercentageFee) / MAX_LOCKER_FEE;
        if (lockerFee > 0) {
            ITeleBTC(teleBTC).mint(_lockerTargetAddress, lockerFee);
        }

        // Mints tokens for receiver
        ITeleBTC(teleBTC).mint(_receiver, _amount - lockerFee);

        emit MintByLocker(
            _lockerTargetAddress,
            _receiver,
            _amount,
            lockerFee,
            block.timestamp
        );

        return _amount - lockerFee;
    }

    function getLockerCapacity(
        bytes calldata _lockerLockingScript
    )
        external
        view
        override
        returns (uint256 theLockerCapacity)
    {
        address _lockerTargetAddress = lockerTargetAddress[
            _lockerLockingScript
        ];

        return LockersManagerLib.getLockerCapacity(
            libConstants,
            libParams,
            lockerCollateralToken[_lockerTargetAddress],
            collateralDecimal[lockerCollateralToken[_lockerTargetAddress]],
            lockersMapping[_lockerTargetAddress].nativeTokenLockedAmount,
            lockerReliabilityFactor[_lockerTargetAddress],
            lockersMapping[_lockerTargetAddress].netMinted,
            0
        );
    }

    /// @notice                       Burn teleBTC of an account
    /// @dev                          Burn teleBTC and also get the locker's fee
    /// @param _lockerLockingScript   Locking script of a locker
    /// @param _amount                Amount of the teleBTC which is minted, including the locker's fee
    /// @return uint                  The amount of teleBTC burnt
    function burn(bytes calldata _lockerLockingScript, uint256 _amount)
        external
        override
        nonReentrant
        whenNotPaused
        onlyBurner
        returns (uint256)
    {
        address _lockerTargetAddress = lockerTargetAddress[
            _lockerLockingScript
        ];

        // Transfers teleBTC from user

        if (!
            ITeleBTC(teleBTC).transferFrom(
                _msgSender(),
                address(this),
                _amount
            )
        ) revert TransferFailed();
        
        uint256 lockerFee = (_amount * lockerPercentageFee) / MAX_LOCKER_FEE;
        uint256 remainedAmount = _amount - lockerFee;
        uint256 netMinted = lockersMapping[_lockerTargetAddress].netMinted;

        require(netMinted >= remainedAmount, "Lockers: insufficient funds");

        lockersMapping[_lockerTargetAddress].netMinted =
            netMinted -
            remainedAmount;

        // Burns teleBTC and sends rest of it to locker
        require(ITeleBTC(teleBTC).burn(remainedAmount), "Lockers: burn failed");
        
        if (!ITeleBTC(teleBTC).transfer(_lockerTargetAddress, lockerFee))
            revert TransferFailed();


        emit BurnByLocker(
            _lockerTargetAddress,
            _amount,
            lockerFee,
            block.timestamp
        );

        return remainedAmount;
    }

    // *************** Public functions ***************

    function renounceOwnership() public virtual override onlyOwner {}

    /// @notice                             Returns the Locker status
    /// @dev                                We check a locker status in below cases:
    ///                                     1. Minting TeleBTC
    ///                                     2. Removing locker's collateral
    ///                                     3. Removing locker
    /// @param _lockerTargetAddress         Address of locker on the target chain
    /// @return                             True if the locker is active
    function isLockerActive(address _lockerTargetAddress)
        public
        view
        override
        returns (bool)
    {
        if (lockerInactivationTimestamp[_lockerTargetAddress] == 0) {
            return true;
        } else if (
            lockerInactivationTimestamp[_lockerTargetAddress] > block.timestamp
        ) {
            return true;
        } else {
            return false;
        }
    }

    function getLockersHealthFactor (
        address _lockerTargetAddress
    )   public
        view
        override
        returns (uint256) {
        return LockersManagerLib.calculateHealthFactor(
            lockersMapping[_lockerTargetAddress],
            libConstants,
            libParams,
            priceOfOneUnitOfCollateralInBTC(lockerCollateralToken[_lockerTargetAddress]),
            collateralDecimal[lockerCollateralToken[_lockerTargetAddress]],
            lockerReliabilityFactor[_lockerTargetAddress]
        );
    }
    /**
     * @dev         Returns the price of one native token (1*10^18) in teleBTC
     * @return uint The price of one unit of collateral token (native token in teleBTC)
     */
    function priceOfOneUnitOfCollateralInBTC(
        address collateralToken
    )
        public
        view
        override
        returns (uint256)
    {
        return
            LockersManagerLib.priceOfOneUnitOfCollateralInBTC(
                collateralToken,
                collateralDecimal[collateralToken],
                libParams
            );
    }

    /// @notice                Check if an account is minter
    /// @param  account        The account which intended to be checked
    /// @return bool
    function isMinter(address account)
        public
        view
        override
        returns (bool)
    {
        return minters[account];
    }

    /// @notice                Check if an account is burner
    /// @param  account        The account which intended to be checked
    /// @return bool
    function isBurner(address account)
        public
        view
        override
        returns (bool)
    {
        return burners[account];
    }
}
